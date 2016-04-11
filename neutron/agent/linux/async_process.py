# Copyright 2013 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import signal

import eventlet
import eventlet.event
import eventlet.queue
from oslo_log import log as logging

from neutron._i18n import _, _LE
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)


class AsyncProcessException(Exception):
    pass


class AsyncProcess(object):
    """Manages an asynchronous process.

    This class spawns a new process via subprocess and uses
    greenthreads to read stderr and stdout asynchronously into queues
    that can be read via repeatedly calling iter_stdout() and
    iter_stderr().

    If respawn_interval is non-zero, any error in communicating with
    the managed process will result in the process and greenthreads
    being cleaned up and the process restarted after the specified
    interval.

    Example usage:

    >>> import time
    >>> proc = AsyncProcess(['ping'])
    >>> proc.start()
    >>> time.sleep(5)
    >>> proc.stop()
    >>> for line in proc.iter_stdout():
    ...     print(line)
    """

    def __init__(self, cmd, run_as_root=False, respawn_interval=None,
                 namespace=None, log_output=False, die_on_error=False):
        """Constructor.

        :param cmd: The list of command arguments to invoke.
        :param run_as_root: The process should run with elevated privileges.
        :param respawn_interval: Optional, the interval in seconds to wait
               to respawn after unexpected process death. Respawn will
               only be attempted if a value of 0 or greater is provided.
        :param namespace: Optional, start the command in the specified
               namespace.
        :param log_output: Optional, also log received output.
        :param die_on_error: Optional, kills the process on stderr output.
        """
        self.cmd_without_namespace = cmd
        self._cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
        self.run_as_root = run_as_root
        if respawn_interval is not None and respawn_interval < 0:
            raise ValueError(_('respawn_interval must be >= 0 if provided.'))
        self.respawn_interval = respawn_interval
        self._process = None
        self._is_running = False
        self._kill_event = None
        self._reset_queues()
        self._watchers = []
        self.log_output = log_output
        self.die_on_error = die_on_error

    @property
    def cmd(self):
        return ' '.join(self._cmd)

    def _reset_queues(self):
        self._stdout_lines = eventlet.queue.LightQueue()
        self._stderr_lines = eventlet.queue.LightQueue()

    def is_active(self):
        # If using sudo rootwrap as a root_helper, we have to wait until sudo
        # spawns rootwrap and rootwrap spawns the process.

        return utils.pid_invoked_with_cmdline(
            self.pid, self.cmd_without_namespace)

    def start(self, block=False):
        """Launch a process and monitor it asynchronously.

        :param block: Block until the process has started.
        :raises eventlet.timeout.Timeout if blocking is True and the process
                did not start in time.
        """
        LOG.debug('Launching async process [%s].', self.cmd)
        if self._is_running:
            raise AsyncProcessException(_('Process is already started'))
        else:
            self._spawn()

        if block:
            utils.wait_until_true(self.is_active)

    def stop(self, block=False, kill_signal=signal.SIGKILL):
        """Halt the process and watcher threads.

        :param block: Block until the process has stopped.
        :param kill_signal: Number of signal that will be sent to the process
                            when terminating the process
        :raises eventlet.timeout.Timeout if blocking is True and the process
                did not stop in time.
        """
        if self._is_running:
            LOG.debug('Halting async process [%s].', self.cmd)
            self._kill(kill_signal)
        else:
            raise AsyncProcessException(_('Process is not running.'))

        if block:
            utils.wait_until_true(lambda: not self.is_active())

    def _spawn(self):
        """Spawn a process and its watchers."""
        self._is_running = True
        self._kill_event = eventlet.event.Event()
        self._process, cmd = utils.create_process(self._cmd,
                                                  run_as_root=self.run_as_root)
        self._watchers = []
        for reader in (self._read_stdout, self._read_stderr):
            # Pass the stop event directly to the greenthread to
            # ensure that assignment of a new event to the instance
            # attribute does not prevent the greenthread from using
            # the original event.
            watcher = eventlet.spawn(self._watch_process,
                                     reader,
                                     self._kill_event)
            self._watchers.append(watcher)

    @property
    def pid(self):
        if self._process:
            return utils.get_root_helper_child_pid(
                self._process.pid,
                self.cmd_without_namespace,
                run_as_root=self.run_as_root)

    def _kill(self, kill_signal):
        """Kill the process and the associated watcher greenthreads."""
        pid = self.pid
        if pid:
            self._is_running = False
            self._kill_process(pid, kill_signal)

        # Halt the greenthreads if they weren't already.
        if self._kill_event:
            self._kill_event.send()
            self._kill_event = None

    def _kill_process(self, pid, kill_signal):
        try:
            # A process started by a root helper will be running as
            # root and need to be killed via the same helper.
            utils.execute(['kill', '-%d' % kill_signal, pid],
                          run_as_root=self.run_as_root)
        except Exception as ex:
            stale_pid = (isinstance(ex, RuntimeError) and
                         'No such process' in str(ex))
            if not stale_pid:
                LOG.exception(_LE('An error occurred while killing [%s].'),
                              self.cmd)
                return False

        if self._process:
            self._process.wait()
        return True

    def _handle_process_error(self):
        """Kill the async process and respawn if necessary."""
        LOG.debug('Halting async process [%s] in response to an error.',
                  self.cmd)
        self._kill(signal.SIGKILL)
        if self.respawn_interval is not None and self.respawn_interval >= 0:
            eventlet.sleep(self.respawn_interval)
            LOG.debug('Respawning async process [%s].', self.cmd)
            try:
                self.start()
            except AsyncProcessException:
                # Process was already respawned by someone else...
                pass

    def _watch_process(self, callback, kill_event):
        while not kill_event.ready():
            try:
                output = callback()
                if not output and output != "":
                    break
            except Exception:
                LOG.exception(_LE('An error occurred while communicating '
                                  'with async process [%s].'), self.cmd)
                break
            # Ensure that watching a process with lots of output does
            # not block execution of other greenthreads.
            eventlet.sleep()
        # self._is_running being True indicates that the loop was
        # broken out of due to an error in the watched process rather
        # than the loop condition being satisfied.
        if self._is_running:
            self._is_running = False
            self._handle_process_error()

    def _read(self, stream, queue):
        data = stream.readline()
        if data:
            data = common_utils.safe_decode_utf8(data.strip())
            queue.put(data)
            return data

    def _read_stdout(self):
        data = self._read(self._process.stdout, self._stdout_lines)
        if self.log_output:
            LOG.debug('Output received from [%(cmd)s]: %(data)s',
                      {'cmd': self.cmd,
                       'data': data})
        return data

    def _read_stderr(self):
        data = self._read(self._process.stderr, self._stderr_lines)
        if self.log_output:
            LOG.error(_LE('Error received from [%(cmd)s]: %(err)s'),
                      {'cmd': self.cmd,
                       'err': data})
        if self.die_on_error:
            LOG.error(_LE("Process [%(cmd)s] dies due to the error: %(err)s"),
                      {'cmd': self.cmd,
                       'err': data})
            # the callback caller will use None to indicate the need to bail
            # out of the thread
            return None

        return data

    def _iter_queue(self, queue, block):
        while True:
            try:
                yield queue.get(block=block)
            except eventlet.queue.Empty:
                break

    def iter_stdout(self, block=False):
        return self._iter_queue(self._stdout_lines, block)

    def iter_stderr(self, block=False):
        return self._iter_queue(self._stderr_lines, block)
