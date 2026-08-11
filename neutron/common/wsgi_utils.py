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

from oslo_log import log as logging
from oslo_utils import timeutils

from neutron.common import utils


LOG = logging.getLogger(__name__)

_first_worker_result = None
_start_time = None


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


def get_start_time():
    """Return the start time of the WSGI server process group.

    The first API worker to run records the current time in a temp file
    keyed by the parent PID. Subsequent workers (and future calls from
    the same worker) read from that file. The file is automatically
    invalidated when the WSGI server restarts (new parent PID).

    :return: (int) start time in seconds.
    """
    global _start_time
    if _start_time is not None:
        return _start_time

    _time = utils.datetime_to_ts(timeutils.utcnow())
    written, _path = _write_temp_file('neutron_start_time', str(_time))
    if written:
        # This API worker succeed. Use the same _time written in the file.
        _start_time = _time
        return _start_time

    try:
        with open(_path) as f:
            content = f.read().strip()
            if content:
                _start_time = int(content)
                return _start_time
    except (ValueError, OSError):
        msg = 'Unable to read the start time of the WSGI server process.'
        raise RuntimeError(msg)


def get_api_worker_count() -> int | None:
    """Return the number of API worker processes.

    uWSGI:    ``uwsgi.numproc``.
    mod_wsgi: ``mod_wsgi.maximum_processes``.
    """
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        return uwsgi.numproc
    except (ImportError, ModuleNotFoundError):
        pass

    try:
        # pylint: disable=import-outside-toplevel
        import mod_wsgi  # type: ignore[import-not-found]
        return mod_wsgi.maximum_processes
    except (ImportError, ModuleNotFoundError):
        pass

    LOG.error('Unable to retrieve the API worker count: neither the '
              '``uwsgi`` nor the ``mod_wsgi`` module could be loaded')
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
