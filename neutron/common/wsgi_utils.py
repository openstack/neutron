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

from neutron._i18n import _
from neutron.common import utils


LOG = logging.getLogger(__name__)

_first_worker = None
_start_time = None

# PID of the "init" process inside a container run without
# ``--pid=host``/``hostPID: true``. When the parent is PID 1, neither its
# PID nor its start time can be used to detect a WSGI server restart,
# because the init process (and its start time) stays the same across
# every restart of the application running inside the container.
_CONTAINER_INIT_PID = 1


def _uwsgi_start_time() -> int | None:
    """Return the WSGI master's start time via uWSGI's ``start-time`` opt.

    Requires ``[uwsgi] start-time=%t`` in the uWSGI configuration file.
    uWSGI substitutes the ``%t`` magic variable with the current Unix time
    when the configuration is parsed, i.e. on every (re)start of the
    server, which makes it reliable even when the container's parent PID
    never changes across restarts (see :data:`_CONTAINER_INIT_PID`).

    :returns: start time in seconds, or None if not running under uWSGI or
              the ``start-time`` option is not configured.
    """
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        start_time = uwsgi.opt.get('start-time')
        # ``uwsgi.opt`` values are typed as
        # ``bytes | Literal[True] | list[bytes | Literal[True]]``: only
        # the ``bytes`` case is expected for a scalar option like
        # ``start-time``, but narrow explicitly rather than assume it.
        if isinstance(start_time, bytes):
            return int(start_time.decode(encoding='utf-8'))
    except (ImportError, ModuleNotFoundError, ValueError, AttributeError):
        pass
    return None


def _uwsgi_is_first_worker() -> bool | None:
    """Return whether this process is uWSGI's first worker, if known.

    ``uwsgi.worker_id()`` is assigned by the uWSGI master to each forked
    worker and is unaffected by PID reuse or by containers that keep the
    parent pinned to PID 1, unlike the temp-file-based election used as a
    fallback for other WSGI servers.

    :returns: True/False when running under uWSGI, None otherwise.
    """
    try:
        # pylint: disable=import-outside-toplevel
        import uwsgi
        return uwsgi.worker_id() == 1
    except (ImportError, ModuleNotFoundError, AttributeError):
        return None


def _write_temp_file(file_name: str, content: str) -> tuple[bool, str]:
    """Atomically create a temp file keyed by the parent PID.

    The file path is ``<tempdir>/<file_name><ppid>``. ``O_CREAT | O_EXCL``
    guarantees that exactly one process creates the file; all others get
    ``FileExistsError`` and this function returns False. No prior read of
    the file is performed: a single atomic syscall is what makes the
    "exactly once" semantics correct, so nothing here should be made to
    depend on the file's prior existence or contents. Because every WSGI
    worker in a process group shares the same parent (the daemon
    manager), the parent PID acts as a natural group key that resets
    automatically when the WSGI server restarts, as long as the OS
    assigns a genuinely new PID to that parent.

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

    uWSGI's own ``start-time=%t`` magic variable is tried first, since it
    is refreshed on every (re)start of the server regardless of any PID
    reuse, and is therefore always preferred when available.

    Otherwise, the first API worker to run records the current time in a
    temp file keyed by the parent PID; subsequent workers (and future
    calls from the same worker) read from that file. This is normally
    invalidated when the WSGI server restarts, because the OS assigns a
    new parent PID.

    That PID-based detection fundamentally cannot work in a container run
    without ``--pid=host``/``hostPID: true``: by default, the parent of
    any process inside such a container is PID 1 (the container's init
    process), which never changes across restarts of the application
    running inside the container. In that scenario this function can
    only be reliably supported when running under uWSGI; other WSGI
    servers (mod_wsgi, ASGI) have no equivalent restart signal and the
    returned value may be stale.

    :return: (int) start time in seconds.
    """
    global _start_time
    if _start_time is not None:
        return _start_time

    uwsgi_start = _uwsgi_start_time()
    if uwsgi_start is not None:
        _start_time = uwsgi_start
        return _start_time

    if os.getppid() == _CONTAINER_INIT_PID:
        LOG.warning('The parent process is PID %s, which usually means '
                    'this is running in a container without '
                    '--pid=host/hostPID enabled; without uWSGI (which '
                    'provides a restart-independent start time via the '
                    '"start-time=%%t" option), the WSGI server start '
                    'time cannot be reliably detected across restarts.',
                    _CONTAINER_INIT_PID)

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
    ASGI:     ``ASGI_WORKERS`` environment variable.
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

    # ASGI servers (Hypercorn, uvicorn) export worker count via env var
    asgi_workers = os.environ.get('ASGI_WORKERS')
    if asgi_workers:
        return int(asgi_workers)

    LOG.error('Unable to retrieve the API worker count: neither the '
              '``uwsgi`` nor the ``mod_wsgi`` module could be loaded')
    return None


def _elect_first_wsgi_worker() -> bool:
    """Elect one WSGI daemon process as the 'first' worker.

    uWSGI's own ``worker_id()`` is tried first, since it is immune to PID
    reuse and is therefore always preferred when available.

    Otherwise, all WSGI daemon processes in a group must share the same
    parent. By including ``os.getppid()`` in the flag filename, the
    election normally resets when the WSGI service restarts (new parent
    PID). ``O_CREAT | O_EXCL`` is atomic: exactly one process succeeds in
    creating the file and becomes the "first" worker.

    When the parent is PID 1 (container without ``--pid=host``/
    ``hostPID: true``), the election can only be reliably supported under
    uWSGI; see :func:`init_api_worker` and :func:`get_start_time`.
    """
    global _first_worker
    if _first_worker is not None:
        return _first_worker

    uwsgi_first = _uwsgi_is_first_worker()
    if uwsgi_first is not None:
        _first_worker = uwsgi_first
        return _first_worker

    _first_worker, __ = _write_temp_file(
        'neutron_first_worker', str(os.getpid()))
    return _first_worker


def is_first_api_worker() -> bool:
    """Return True if this is the 'first' API worker in the process group.

    Used to elect a single worker for one-time initialization tasks
    (e.g. network segment range support).
    """
    return _elect_first_wsgi_worker()


def init_api_worker() -> None:
    """Determine the API worker start time and election status up front.

    Must be called in each API worker before the paste app (and therefore
    any ML2 mechanism driver, such as OVN or OVS) is loaded. Both
    :func:`get_start_time` and :func:`is_first_api_worker` memoize their
    result per process, so every later caller gets the same value. This
    relies on each API worker being a separate process, which is always
    the case now that the eventlet-based server is no longer supported.

    In a container run without ``--pid=host``/``hostPID: true`` the parent
    process is PID 1 and never changes across restarts, so the PID-keyed
    temp files cannot detect a restart: if they survive it (e.g. ``/tmp``
    on persistent storage), no worker is elected as first and a stale
    start time is used. That deployment is only supported under uWSGI with
    ``start-time = %t`` configured; otherwise this fails explicitly.

    :raises RuntimeError: if the start time and first worker cannot be
                          reliably determined.
    """
    if (os.getppid() == _CONTAINER_INIT_PID and
            (_uwsgi_start_time() is None or
             _uwsgi_is_first_worker() is None)):
        raise RuntimeError(_(
            'The parent process of this API worker is PID %d, which means '
            'it is running in a container without --pid=host/hostPID '
            'enabled. In this case the API worker start time and the first '
            'API worker cannot be reliably determined unless the Neutron '
            'API runs under uWSGI with the "start-time = %%t" option '
            'set.') % _CONTAINER_INIT_PID)
    get_start_time()
    is_first_api_worker()
