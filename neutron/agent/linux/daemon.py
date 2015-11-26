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

from oslo_log import log as logging

from neutron.common import exceptions
from neutron.i18n import _LE, _LI

LOG = logging.getLogger(__name__)


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

    LOG.info(_LI("Process runs with uid/gid: %(uid)s/%(gid)s"),
             {'uid': os.getuid(), 'gid': os.getgid()})


class Pidfile(object):
    def __init__(self, pidfile, procname, uuid=None):
        self.pidfile = pidfile
        self.procname = procname
        self.uuid = uuid
        try:
            self.fd = os.open(pidfile, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            LOG.exception(_LE("Error while handling pidfile: %s"), pidfile)
            sys.exit(1)

    def __str__(self):
        return self.pidfile

    def unlock(self):
        if not not fcntl.flock(self.fd, fcntl.LOCK_UN):
            raise IOError(_('Unable to unlock pid file'))

    def write(self, pid):
        os.ftruncate(self.fd, 0)
        os.write(self.fd, "%d" % pid)
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
            with open(cmdline, "r") as f:
                exec_out = f.readline()
            return self.procname in exec_out and (not self.uuid or
                                                  self.uuid in exec_out)
        except IOError:
            return False


class Daemon(object):
    """A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null',
                 stderr='/dev/null', procname='python', uuid=None,
                 user=None, group=None, watch_log=True):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.procname = procname
        self.pidfile = Pidfile(pidfile, procname, uuid)
        self.user = user
        self.group = group
        self.watch_log = watch_log

    def _fork(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            LOG.exception(_LE('Fork failed'))
            sys.exit(1)

    def daemonize(self):
        """Daemonize process by doing Stevens double fork."""
        # fork first time
        self._fork()

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # fork second time
        self._fork()

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        stdin = open(self.stdin, 'r')
        stdout = open(self.stdout, 'a+')
        stderr = open(self.stderr, 'a+', 0)
        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(stdout.fileno(), sys.stdout.fileno())
        os.dup2(stderr.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delete_pid)
        signal.signal(signal.SIGTERM, self.handle_sigterm)
        self.pidfile.write(os.getpid())

    def delete_pid(self):
        os.remove(str(self.pidfile))

    def handle_sigterm(self, signum, frame):
        sys.exit(0)

    def start(self):
        """Start the daemon."""

        if self.pidfile.is_running():
            self.pidfile.unlock()
            LOG.error(_LE('Pidfile %s already exist. Daemon already '
                          'running?'), self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def run(self):
        """Override this method and call super().run when subclassing Daemon.

        start() will call this method after the process has daemonized.
        """
        if not self.watch_log:
            unwatch_log()
        drop_privileges(self.user, self.group)
