# Copyright 2026 Red Hat, Inc.
# All Rights Reserved.
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

"""Helpers to probe whether Neutron worker lifecycle methods return or block"""

import enum
import threading

WORKER_LIFECYCLE_METHODS = ('start', 'stop', 'wait', 'reset')


class MethodCompletion(enum.Enum):
    """Whether a worker method call finished within the probe timeout."""

    RETURNED = 'returned'
    BLOCKED = 'blocked'


def probe_worker_method(worker, method_name, timeout=1.0, **kwargs):
    """Call ``worker.<method_name>`` in a thread and observe completion.

    :param worker: Any object implementing worker lifecycle methods.
    :param method_name: One of ``start``, ``stop``, ``wait``, or ``reset``.
    :param timeout: Seconds to wait before treating the call as blocking.
    :param kwargs: Keyword arguments forwarded to the worker method.
    :returns: A tuple ``(completion, exception)`` where ``completion`` is
        :class:`MethodCompletion` and ``exception`` is set when the method
        raised before returning.
    :raises AttributeError: If ``method_name`` is not defined on ``worker``.
    :raises ValueError: If ``method_name`` is not a lifecycle method.
    """
    if method_name not in WORKER_LIFECYCLE_METHODS:
        raise ValueError(
            'method_name must be one of %s, not %r' % (
                WORKER_LIFECYCLE_METHODS, method_name))

    method = getattr(worker, method_name, None)
    if method is None:
        raise AttributeError(
            'worker %r has no method %r' % (worker, method_name))

    completed = threading.Event()
    result = {'exception': None}

    def _target():
        try:
            method(**kwargs)
        except Exception as exc:
            result['exception'] = exc
        finally:
            completed.set()

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    if completed.wait(timeout):
        return MethodCompletion.RETURNED, result['exception']
    return MethodCompletion.BLOCKED, None


# Expected probe results for :class:`neutron.worker.PeriodicWorker`.
# Keys are ``(state, method_name)`` where *state* is ``idle``, ``running``,
# or ``stopped``.
PERIODIC_WORKER_EXPECTATIONS = {
    ('idle', 'start'): MethodCompletion.RETURNED,
    ('idle', 'stop'): MethodCompletion.RETURNED,
    ('idle', 'wait'): MethodCompletion.RETURNED,
    ('idle', 'reset'): MethodCompletion.RETURNED,
    ('running', 'stop'): MethodCompletion.RETURNED,
    ('running', 'wait'): MethodCompletion.BLOCKED,
    ('running', 'reset'): MethodCompletion.RETURNED,
    ('stopped', 'wait'): MethodCompletion.RETURNED,
}


def assert_worker_expectations(test_case, worker, expectations, timeout=0.5,
                              prepare_state=None):
    """Assert lifecycle method completion matches *expectations*.

    :param test_case: ``unittest`` case used for assertions.
    :param worker: Worker instance under test.
    :param expectations: Dict mapping ``(state, method)`` to
        :class:`MethodCompletion`.
    :param timeout: Per-method probe timeout in seconds.
    :param prepare_state: Optional callable taking ``(worker, state)`` that
        puts the worker into the requested state before probing.
    """
    for (state, method_name), expected in expectations.items():
        if prepare_state is not None:
            prepare_state(worker, state)
        completion, exc = probe_worker_method(
            worker, method_name, timeout=timeout)
        test_case.assertIsNone(
            exc,
            'worker %s in state %r: %s() raised %r' % (
                type(worker).__name__, state, method_name, exc))
        test_case.assertEqual(
            expected, completion,
            'worker %s in state %r: %s() expected %s got %s' % (
                type(worker).__name__, state, method_name,
                expected.value, completion.value))


def probe_worker_lifecycle(worker, timeout=1.0, start_kwargs=None):
    """Probe all lifecycle methods on ``worker`` in the idle state.

    This is useful as a quick sanity check for newly introduced workers.
    The worker is left in the same state as before the probe (methods are
    only invoked, not sequenced through a full run cycle).

    :param worker: Worker instance to inspect.
    :param timeout: Per-method probe timeout in seconds.
    :param start_kwargs: Optional keyword arguments for ``start()``.
    :returns: A dict mapping method name to :class:`MethodCompletion`.
    """
    start_kwargs = start_kwargs or {}
    results = {}
    for method_name in WORKER_LIFECYCLE_METHODS:
        kwargs = start_kwargs if method_name == 'start' else {}
        completion, _ = probe_worker_method(
            worker, method_name, timeout=timeout, **kwargs)
        results[method_name] = completion
    return results
