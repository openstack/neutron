# Copyright 2012 New Dream Network, LLC (DreamHost)
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

import atexit
import fcntl
import grp
import logging as std_logging
from logging import handlers
import os
import pwd
import signal
import sys

from neutron_lib import exceptions
from oslo_log import log as logging
import setproctitle

from neutron._i18n import _

LOG = logging.getLogger(__name__)

DEVNULL = object()

# Note: We can't use sys.std*.fileno() here.  sys.std* objects may be
# random file-like objects that may not match the true system std* fds
# - and indeed may not even have a file descriptor at all (eg: test
# fixtures that monkey patch fixtures.StringStream onto sys.stdout).
# Below we always want the _real_ well-known 0,1,2 Unix fds during
# os.dup2 manipulation.
STDIN_FILENO = 0
STDOUT_FILENO = 1
STDERR_FILENO = 2


def setuid(user_id_or_name):
    try:
        new_uid = int(user_id_or_name)
    except (TypeError, ValueError):
        new_uid = pwd.getpwnam(user_id_or_name).pw_uid
    if new_uid != 0:
        try:
            os.setuid(new_uid)
        except OSError:
            msg = _('Failed to set uid %s') % new_uid
            LOG.critical(msg)
            raise exceptions.FailToDropPrivilegesExit(msg)


def setgid(group_id_or_name):
    try:
        new_gid = int(group_id_or_name)
    except (TypeError, ValueError):
        new_gid = grp.getgrnam(group_id_or_name).gr_gid
    if new_gid != 0:
        try:
            os.setgid(new_gid)
        except OSError:
            msg = _('Failed to set gid %s') % new_gid
            LOG.critical(msg)
            raise exceptions.FailToDropPrivilegesExit(msg)


def unwatch_log():
    """Replace WatchedFileHandler handlers by FileHandler ones.

    Neutron logging uses WatchedFileHandler handlers but they do not
    support privileges drop, this method replaces them by FileHandler
    handlers supporting privileges drop.
    """
    log_root = logging.getLogger(None).logger
    to_replace = [h for h in log_root.handlers
                  if isinstance(h, handlers.WatchedFileHandler)]
    for handler in to_replace:
        # NOTE(cbrandily): we use default delay(=False) to ensure the log file
        # is opened before privileges drop.
        new_handler = std_logging.FileHandler(handler.baseFilename,
                                              mode=handler.mode,
                                              encoding=handler.encoding)
        log_root.removeHandler(handler)
        log_root.addHandler(new_handler)


def drop_privileges(user=None, group=None):
    """Drop privileges to user/group privileges."""
    if user is None and group is None:
        return

    if os.geteuid() != 0:
        msg = _('Root permissions are required to drop privileges.')
        LOG.critical(msg)
        raise exceptions.FailToDropPrivilegesExit(msg)

    if group is not None:
        try:
            os.setgroups([])
        except OSError:
            msg = _('Failed to remove supplemental groups')
            LOG.critical(msg)
            raise exceptions.FailToDropPrivilegesExit(msg)
        setgid(group)

    if user is not None:
        setuid(user)

    LOG.info("Process runs with uid/gid: %(uid)s/%(gid)s",
             {'uid': os.getuid(), 'gid': os.getgid()})


class Pidfile:
    def __init__(self, pidfile, procname, uuid=None):
        self.pidfile = pidfile
        self.procname = procname
        self.uuid = uuid
        try:
            self.fd = os.open(pidfile, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            LOG.exception("Error while handling pidfile: %s", pidfile)
            sys.exit(1)

    def __str__(self):
        return self.pidfile

    def unlock(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)

    def write(self, pid):
        os.ftruncate(self.fd, 0)
        os.write(self.fd, bytes("%s" % pid, 'utf-8'))
        os.fsync(self.fd)

    def read(self):
        try:
            pid = int(os.read(self.fd, 128))
            os.lseek(self.fd, 0, os.SEEK_SET)
            return pid
        except ValueError:
            return

    def is_running(self):
        pid = self.read()
        if not pid:
            return False

        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline) as f:
                exec_out = f.readline()
            return self.procname in exec_out and (not self.uuid or
                                                  self.uuid in exec_out)
        except OSError:
            return False


class Daemon:
    """A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, stdin=DEVNULL, stdout=DEVNULL,
                 stderr=DEVNULL, procname=sys.executable, uuid=None,
                 user=None, group=None):
        """Note: pidfile may be None."""
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.procname = procname
        self.pidfile = (Pidfile(pidfile, procname, uuid)
                        if pidfile is not None else None)
        self.user = user
        self.group = group

    def _fork(self):
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError:
            LOG.exception('Fork failed')
            sys.exit(1)

    def daemonize(self):
        """Daemonize process by doing Stevens double fork."""

        # flush any buffered data before fork/dup2.
        if self.stdout is not DEVNULL:
            self.stdout.flush()
        if self.stderr is not DEVNULL:
            self.stderr.flush()
        # sys.std* may not match STD{OUT,ERR}_FILENO.  Tough.
        for f in (sys.stdout, sys.stderr):
            f.flush()

        # fork first time
        self._fork()

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # fork second time
        self._fork()

        # redirect standard file descriptors
        with open(os.devnull, 'w+') as devnull:
            stdin = devnull if self.stdin is DEVNULL else self.stdin
            stdout = devnull if self.stdout is DEVNULL else self.stdout
            stderr = devnull if self.stderr is DEVNULL else self.stderr
            os.dup2(stdin.fileno(), STDIN_FILENO)
            os.dup2(stdout.fileno(), STDOUT_FILENO)
            os.dup2(stderr.fileno(), STDERR_FILENO)

        if self.pidfile is not None:
            # write pidfile
            atexit.register(self.delete_pid)
            signal.signal(signal.SIGTERM, self.handle_sigterm)
            self.pidfile.write(os.getpid())

    def delete_pid(self):
        if self.pidfile is not None:
            os.remove(str(self.pidfile))

    def handle_sigterm(self, signum, frame):
        sys.exit(0)

    def start(self):
        """Start the daemon."""

        self._parent_proctitle = setproctitle.getproctitle()
        if self.pidfile is not None and self.pidfile.is_running():
            self.pidfile.unlock()
            LOG.error('Pidfile %s already exist. Daemon already '
                      'running?', self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def _set_process_title(self):
        proctitle = f"{self.procname} ({self._parent_proctitle})"
        setproctitle.setproctitle(proctitle)

    def run(self):
        """Override this method and call super().run when subclassing Daemon.

        start() will call this method after the process has daemonized.
        """
        self._set_process_title()
        unwatch_log()
        drop_privileges(self.user, self.group)
