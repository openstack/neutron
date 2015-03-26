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

import eventlet
import eventlet.event
import eventlet.queue
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.i18n import _LE


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
    ...     print line
    """

    def __init__(self, cmd, run_as_root=False, respawn_interval=None,
                 namespace=None):
        """Constructor.

        :param cmd: The list of command arguments to invoke.
        :param run_as_root: The process should run with elevated privileges.
        :param respawn_interval: Optional, the interval in seconds to wait
               to respawn after unexpected process death. Respawn will
               only be attempted if a value of 0 or greater is provided.
        :param namespace: Optional, start the command in the specified
               namespace.
        """
        self.cmd_without_namespace = cmd
        self.cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
        self.run_as_root = run_as_root
        if respawn_interval is not None and respawn_interval < 0:
            raise ValueError(_('respawn_interval must be >= 0 if provided.'))
        self.respawn_interval = respawn_interval
        self._process = None
        self._kill_event = None
        self._reset_queues()
        self._watchers = []

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
        if self._kill_event:
            raise AsyncProcessException(_('Process is already started'))
        else:
            LOG.debug('Launching async process [%s].', self.cmd)
            self._spawn()

        if block:
            utils.wait_until_true(self.is_active)

    def stop(self, block=False):
        """Halt the process and watcher threads.

        :param block: Block until the process has stopped.
        :raises eventlet.timeout.Timeout if blocking is True and the process
                did not stop in time.
        """
        if self._kill_event:
            LOG.debug('Halting async process [%s].', self.cmd)
            self._kill()
        else:
            raise AsyncProcessException(_('Process is not running.'))

        if block:
            utils.wait_until_true(lambda: not self.is_active())

    def _spawn(self):
        """Spawn a process and its watchers."""
        self._kill_event = eventlet.event.Event()
        self._process, cmd = utils.create_process(self.cmd,
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
                run_as_root=self.run_as_root)

    def _kill(self, respawning=False):
        """Kill the process and the associated watcher greenthreads.

        :param respawning: Optional, whether respawn will be subsequently
               attempted.
        """
        # Halt the greenthreads
        self._kill_event.send()

        pid = self.pid
        if pid:
            self._kill_process(pid)

        if not respawning:
            # Clear the kill event to ensure the process can be
            # explicitly started again.
            self._kill_event = None

    def _kill_process(self, pid):
        try:
            # A process started by a root helper will be running as
            # root and need to be killed via the same helper.
            utils.execute(['kill', '-9', pid], run_as_root=self.run_as_root)
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
        respawning = self.respawn_interval >= 0
        self._kill(respawning=respawning)
        if respawning:
            eventlet.sleep(self.respawn_interval)
            LOG.debug('Respawning async process [%s].', self.cmd)
            self._spawn()

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
        # The kill event not being ready indicates that the loop was
        # broken out of due to an error in the watched process rather
        # than the loop condition being satisfied.
        if not kill_event.ready():
            self._handle_process_error()

    def _read(self, stream, queue):
        data = stream.readline()
        if data:
            data = data.strip()
            queue.put(data)
            return data

    def _read_stdout(self):
        return self._read(self._process.stdout, self._stdout_lines)

    def _read_stderr(self):
        return self._read(self._process.stderr, self._stderr_lines)

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
