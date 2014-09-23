# Copyright 2013 VMware, Inc.
# All Rights Reserved
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

import collections
import uuid

from eventlet import event
from eventlet import greenthread

from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.vmware.vshield.tasks import constants

DEFAULT_INTERVAL = 1000

LOG = logging.getLogger(__name__)


def nop(task):
    return constants.TaskStatus.COMPLETED


class TaskException(exceptions.NeutronException):

    def __init__(self, message=None, **kwargs):
        if message is not None:
            self.message = message

        super(TaskException, self).__init__(**kwargs)


class InvalidState(TaskException):
    message = _("Invalid state %(state)d")


class TaskStateSkipped(TaskException):
    message = _("State %(state)d skipped. Current state %(current)d")


class Task():
    def __init__(self, name, resource_id, execute_callback,
                 status_callback=nop, result_callback=nop, userdata=None):
        self.name = name
        self.resource_id = resource_id
        self._execute_callback = execute_callback
        self._status_callback = status_callback
        self._result_callback = result_callback
        self.userdata = userdata
        self.id = None
        self.status = None

        self._monitors = {
            constants.TaskState.START: [],
            constants.TaskState.EXECUTED: [],
            constants.TaskState.RESULT: []
        }
        self._states = [None, None, None, None]
        self._state = constants.TaskState.NONE

    def _add_monitor(self, action, func):
        self._monitors[action].append(func)
        return self

    def _move_state(self, state):
        self._state = state
        if self._states[state] is not None:
            e = self._states[state]
            self._states[state] = None
            e.send()

        for s in range(state):
            if self._states[s] is not None:
                e = self._states[s]
                self._states[s] = None
                e.send_exception(
                    TaskStateSkipped(state=s, current=self._state))

    def _invoke_monitor(self, state):
        for func in self._monitors[state]:
            try:
                func(self)
            except Exception:
                msg = _("Task %(task)s encountered exception in %(func)s "
                        "at state %(state)s") % {
                            'task': str(self),
                            'func': str(func),
                            'state': state}
                LOG.exception(msg)

        self._move_state(state)

        return self

    def _start(self):
        return self._invoke_monitor(constants.TaskState.START)

    def _executed(self):
        return self._invoke_monitor(constants.TaskState.EXECUTED)

    def _update_status(self, status):
        if self.status == status:
            return self

        self.status = status

    def _finished(self):
        return self._invoke_monitor(constants.TaskState.RESULT)

    def add_start_monitor(self, func):
        return self._add_monitor(constants.TaskState.START, func)

    def add_executed_monitor(self, func):
        return self._add_monitor(constants.TaskState.EXECUTED, func)

    def add_result_monitor(self, func):
        return self._add_monitor(constants.TaskState.RESULT, func)

    def wait(self, state):
        if (state < constants.TaskState.START or
            state > constants.TaskState.RESULT or
            state == constants.TaskState.STATUS):
            raise InvalidState(state=state)

        if state <= self._state:
            # we already passed this current state, so no wait
            return

        e = event.Event()
        self._states[state] = e
        e.wait()

    def __repr__(self):
        return "Task-%s-%s-%s" % (
            self.name, self.resource_id, self.id)


class TaskManager():

    _instance = None
    _default_interval = DEFAULT_INTERVAL

    def __init__(self, interval=None):
        self._interval = interval or TaskManager._default_interval

        # A queue to pass tasks from other threads
        self._tasks_queue = collections.deque()

        # A dict to store resource -> resource's tasks
        self._tasks = {}

        # Current task being executed in main thread
        self._main_thread_exec_task = None

        # New request event
        self._req = event.Event()

        # TaskHandler stopped event
        self._stopped = False

        # Periodic function trigger
        self._monitor = None
        self._monitor_busy = False

        # Thread handling the task request
        self._thread = None

    def _execute(self, task):
        """Execute task."""
        msg = _("Start task %s") % str(task)
        LOG.debug(msg)
        task._start()
        try:
            status = task._execute_callback(task)
        except Exception:
            msg = _("Task %(task)s encountered exception in %(cb)s") % {
                'task': str(task),
                'cb': str(task._execute_callback)}
            LOG.exception(msg)
            status = constants.TaskStatus.ERROR

        LOG.debug("Task %(task)s return %(status)s", {
            'task': str(task),
            'status': status})

        task._update_status(status)
        task._executed()

        return status

    def _result(self, task):
        """Notify task execution result."""
        try:
            task._result_callback(task)
        except Exception:
            msg = _("Task %(task)s encountered exception in %(cb)s") % {
                'task': str(task),
                'cb': str(task._result_callback)}
            LOG.exception(msg)

        LOG.debug("Task %(task)s return %(status)s",
                  {'task': str(task), 'status': task.status})

        task._finished()

    def _check_pending_tasks(self):
        """Check all pending tasks status."""
        for resource_id in self._tasks.keys():
            if self._stopped:
                # Task manager is stopped, return now
                return

            tasks = self._tasks[resource_id]
            # only the first task is executed and pending
            task = tasks[0]
            try:
                status = task._status_callback(task)
            except Exception:
                msg = _("Task %(task)s encountered exception in %(cb)s") % {
                    'task': str(task),
                    'cb': str(task._status_callback)}
                LOG.exception(msg)
                status = constants.TaskStatus.ERROR
            task._update_status(status)
            if status != constants.TaskStatus.PENDING:
                self._dequeue(task, True)

    def _enqueue(self, task):
        if task.resource_id in self._tasks:
            # append to existing resource queue for ordered processing
            self._tasks[task.resource_id].append(task)
        else:
            # put the task to a new resource queue
            tasks = collections.deque()
            tasks.append(task)
            self._tasks[task.resource_id] = tasks

    def _dequeue(self, task, run_next):
        self._result(task)
        tasks = self._tasks[task.resource_id]
        tasks.remove(task)
        if not tasks:
            # no more tasks for this resource
            del self._tasks[task.resource_id]
            return

        if run_next:
            # process next task for this resource
            while tasks:
                task = tasks[0]
                status = self._execute(task)
                if status == constants.TaskStatus.PENDING:
                    break
                self._dequeue(task, False)

    def _abort(self):
        """Abort all tasks."""
        # put all tasks haven't been received by main thread to queue
        # so the following abort handling can cover them
        for t in self._tasks_queue:
            self._enqueue(t)
        self._tasks_queue.clear()

        for resource_id in self._tasks.keys():
            tasks = list(self._tasks[resource_id])
            for task in tasks:
                task._update_status(constants.TaskStatus.ABORT)
                self._dequeue(task, False)

    def _get_task(self):
        """Get task request."""
        while True:
            for t in self._tasks_queue:
                return self._tasks_queue.popleft()
            self._req.wait()
            self._req.reset()

    def run(self):
        while True:
            try:
                if self._stopped:
                    # Gracefully terminate this thread if the _stopped
                    # attribute was set to true
                    LOG.info(_("Stopping TaskManager"))
                    break

                # get a task from queue, or timeout for periodic status check
                task = self._get_task()
                if task.resource_id in self._tasks:
                    # this resource already has some tasks under processing,
                    # append the task to same queue for ordered processing
                    self._enqueue(task)
                    continue

                try:
                    self._main_thread_exec_task = task
                    self._execute(task)
                finally:
                    self._main_thread_exec_task = None
                    if task.status is None:
                        # The thread is killed during _execute(). To guarantee
                        # the task been aborted correctly, put it to the queue.
                        self._enqueue(task)
                    elif task.status != constants.TaskStatus.PENDING:
                        self._result(task)
                    else:
                        self._enqueue(task)
            except Exception:
                LOG.exception(_("TaskManager terminating because "
                                "of an exception"))
                break

    def add(self, task):
        task.id = uuid.uuid1()
        self._tasks_queue.append(task)
        if not self._req.ready():
            self._req.send()
        return task.id

    def stop(self):
        if self._thread is None:
            return
        self._stopped = True
        self._thread.kill()
        self._thread = None
        # Stop looping call and abort running tasks
        self._monitor.stop()
        if self._monitor_busy:
            self._monitor.wait()
        self._abort()
        LOG.info(_("TaskManager terminated"))

    def has_pending_task(self):
        if self._tasks_queue or self._tasks or self._main_thread_exec_task:
            return True
        else:
            return False

    def show_pending_tasks(self):
        for task in self._tasks_queue:
            LOG.info(str(task))
        for resource, tasks in self._tasks.iteritems():
            for task in tasks:
                LOG.info(str(task))
        if self._main_thread_exec_task:
            LOG.info(str(self._main_thread_exec_task))

    def count(self):
        count = 0
        for resource_id, tasks in self._tasks.iteritems():
            count += len(tasks)
        return count

    def start(self, interval=None):
        def _inner():
            self.run()

        def _loopingcall_callback():
            self._monitor_busy = True
            try:
                self._check_pending_tasks()
            except Exception:
                LOG.exception(_("Exception in _check_pending_tasks"))
            self._monitor_busy = False

        if self._thread is not None:
            return self

        if interval is None or interval == 0:
            interval = self._interval

        self._stopped = False
        self._thread = greenthread.spawn(_inner)
        self._monitor = loopingcall.FixedIntervalLoopingCall(
            _loopingcall_callback)
        self._monitor.start(interval / 1000.0,
                            interval / 1000.0)
        # To allow the created thread start running
        greenthread.sleep(0)

        return self

    @classmethod
    def set_default_interval(cls, interval):
        cls._default_interval = interval
