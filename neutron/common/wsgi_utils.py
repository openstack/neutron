# Copyright (c) 2024 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import tempfile

from oslo_utils import timeutils

from neutron.common import utils


_first_worker_result = None


def _write_temp_file(file_name: str, content: str) -> tuple[bool, str]:
    """Atomically create a temp file keyed by the parent PID.

    The file path is ``<tempdir>/<file_name><ppid>``. ``O_CREAT | O_EXCL``
    guarantees that exactly one process creates the file; all others get
    ``FileExistsError`` and this function returns False. Because every
    WSGI worker in a process group shares the same parent (the daemon
    manager), the parent PID acts as a natural group key that resets
    automatically when the WSGI server restarts.

    :param file_name: prefix for the temp file (the parent PID is appended).
    :param content: string to write into the file.
    :returns: True if this call created the file, False if it already existed.
              The full path of the temporary file.
    """
    ppid = os.getppid()
    _path = os.path.join(tempfile.gettempdir(), file_name + str(ppid))
    try:
        fd = os.open(_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, content.encode())
        os.close(fd)
        return True, _path
    except FileExistsError:
        return False, _path


def get_start_time(default=None, current_time=False):
    """Return the 'start-time=%t' config varible in the WSGI config

    This variable contains the start time of the WSGI server. Check
    https://uwsgi-docs.readthedocs.io/en/latest/Configuration.html
    #magic-variables

    :param default: (int or float) in case the uwsgi option 'start-time' is not
                    available or the uwsgi module cannot be loaded, the method
                    will return this value.
    :param current_time: (bool) if ``default`` is None and this flag is set,
                         the method will return the current time.
    :return: (int) start time in seconds.
    """
    if not default and current_time:
        default = utils.datetime_to_ts(timeutils.utcnow())
    default = int(default) if default else None
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        start_time = uwsgi.opt.get('start-time')
        if not start_time:
            return default
        return int(start_time.decode(encoding='utf-8'))
    except ImportError:
        return default


def get_api_worker_count() -> int | None:
    """Return the configured worker number provided to uWSGI"""
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        return uwsgi.numproc
    except (ImportError, ModuleNotFoundError):
        return None


def _elect_first_wsgi_worker() -> bool:
    """Elect one WSGI daemon process as the 'first' worker.

    All WSGI daemon processes in a group must share the same parent. By
    including ``os.getppid()`` in the flag filename, the election
    automatically resets when WSGI service restarts (new parent PID).
    ``O_CREAT | O_EXCL`` is atomic: exactly one process
    succeeds in creating the file and becomes the "first" worker. The temp
    file lives in ``/tmp`` and is cleaned up on reboot.
    """
    global _first_worker_result
    if _first_worker_result is not None:
        return _first_worker_result

    _first_worker_result, __ = _write_temp_file(
        'neutron_first_worker', str(os.getpid()))
    return _first_worker_result


def is_first_api_worker() -> bool:
    """Return True if this is the 'first' API worker in the process group.

    Used to elect a single worker for one-time initialization tasks
    (e.g. network segment range support).
    """
    return _elect_first_wsgi_worker()
