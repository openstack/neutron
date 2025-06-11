# Copyright (C) 2025 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# NOTE(ralonsoh): this is the implementation of ``FixedIntervalLoopingCall``
# and all needed resources done in ``oslo.service`` 4.2.0, in the ``threading``
# backend. Because this code is not going to be backported or available in
# 2025.1.

import sys
import threading

import futurist
from oslo_log import log as logging
from oslo_utils import reflection
from oslo_utils import timeutils

from neutron._i18n import _


LOG = logging.getLogger(__name__)


class FutureEvent:
    """A simple event object that can carry a result or an exception."""

    def __init__(self):
        self._event = threading.Event()
        self._result = None
        self._exc_info = None

    def send(self, result):
        self._result = result
        self._event.set()

    def send_exception(self, exc_type, exc_value, tb):
        self._exc_info = (exc_type, exc_value, tb)
        self._event.set()

    def wait(self, timeout=None):
        flag = self._event.wait(timeout)

        if not flag:
            raise RuntimeError(_('Timed out waiting for event'))

        if self._exc_info:
            exc_type, exc_value, tb = self._exc_info
            raise exc_value.with_traceback(tb)
        return self._result


class LoopingCallDone(Exception):
    """Exception to break out and stop a LoopingCallBase.

    The function passed to a looping call may raise this exception to
    break out of the loop normally. An optional return value may be
    provided; this value will be returned by LoopingCallBase.wait().
    """

    def __init__(self, retvalue=True):
        """:param retvalue: Value that LoopingCallBase.wait() should return."""
        self.retvalue = retvalue


def _safe_wrapper(f, kind, func_name):
    """Wrapper that calls the wrapped function and logs errors as needed."""

    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except LoopingCallDone:
            raise  # Let the outer handler process this
        except Exception:
            LOG.error('%(kind)s %(func_name)r failed',
                      {'kind': kind, 'func_name': func_name},
                      exc_info=True)
            return 0

    return func


class LoopingCallBase:
    KIND = _("Unknown looping call")
    RUN_ONLY_ONE_MESSAGE = _(
        "A looping call can only run one function at a time")

    def __init__(self, *args, f=None, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.f = f
        self._future = None
        self.done = None
        self._abort = threading.Event()  # When set, the loop stops

    @property
    def _running(self):
        return not self._abort.is_set()

    def stop(self):
        if self._running:
            self._abort.set()

    def wait(self):
        """Wait for the looping call to complete and return its result."""
        return self.done.wait()

    def _on_done(self, future):
        self._future = None

    def _sleep(self, timeout):
        # Instead of eventlet.sleep, we wait on the abort event for timeout
        # seconds.
        self._abort.wait(timeout)

    def _start(self, idle_for, initial_delay=None, stop_on_exception=True):
        """Start the looping call.

        :param idle_for: Callable taking two arguments (last result,
            elapsed time) and returning how long to idle.
        :param initial_delay: Delay (in seconds) before starting the
            loop.
        :param stop_on_exception: Whether to stop on exception.
        :returns: A FutureEvent instance.
        """

        if self._future is not None:
            raise RuntimeError(self.RUN_ONLY_ONE_MESSAGE)

        self.done = FutureEvent()
        self._abort.clear()

        def _run_loop():
            kind = self.KIND
            func_name = reflection.get_callable_name(self.f)
            func = self.f if stop_on_exception else _safe_wrapper(self.f, kind,
                                                                  func_name)
            if initial_delay:
                self._sleep(initial_delay)
            try:
                watch = timeutils.StopWatch()

                while self._running:
                    watch.restart()
                    result = func(*self.args, **self.kwargs)
                    watch.stop()

                    if not self._running:
                        break

                    idle = idle_for(result, watch.elapsed())
                    LOG.debug(
                        '%(kind)s %(func_name)r sleeping for %(idle).02f'
                        ' seconds',
                        {'func_name': func_name, 'idle': idle, 'kind': kind})
                    self._sleep(idle)
            except LoopingCallDone as e:
                self.done.send(e.retvalue)
            except Exception:
                exc_info = sys.exc_info()
                try:
                    LOG.error('%(kind)s %(func_name)r failed',
                              {'kind': kind, 'func_name': func_name},
                              exc_info=exc_info)
                    self.done.send_exception(*exc_info)
                finally:
                    del exc_info
                return
            else:
                self.done.send(True)

        # Use futurist's ThreadPoolExecutor to run the loop in a background
        # thread.
        executor = futurist.ThreadPoolExecutor(max_workers=1)
        self._future = executor.submit(_run_loop)
        self._future.add_done_callback(self._on_done)
        return self.done

    # NOTE: _elapsed() is a thin wrapper for StopWatch.elapsed()
    def _elapsed(self, watch):
        return watch.elapsed()


class FixedIntervalLoopingCall(LoopingCallBase):
    """A fixed interval looping call."""
    RUN_ONLY_ONE_MESSAGE = _(
        "A fixed interval looping call can only run one function at a time")
    KIND = _('Fixed interval looping call')

    def start(self, interval, initial_delay=None, stop_on_exception=True):
        def _idle_for(result, elapsed):
            delay = round(elapsed - interval, 2)
            if delay > 0:
                func_name = reflection.get_callable_name(self.f)
                LOG.warning(
                    'Function %(func_name)r run outlasted interval by'
                    ' %(delay).2f sec',
                    {'func_name': func_name, 'delay': delay})
            return -delay if delay < 0 else 0

        return self._start(_idle_for, initial_delay=initial_delay,
                           stop_on_exception=stop_on_exception)
