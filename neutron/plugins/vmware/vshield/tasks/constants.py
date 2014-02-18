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


class TaskStatus(object):
    """Task running status.

    This is used by execution/status callback function to notify the
    task manager what's the status of current task, and also used for
    indication the final task execution result.
    """
    PENDING = 1
    COMPLETED = 2
    ERROR = 3
    ABORT = 4


class TaskState(object):
    """Current state of a task.

    This is to keep track of the current state of a task.
    NONE: the task is still in the queue
    START: the task is pull out from the queue and is about to be executed
    EXECUTED: the task has been executed
    STATUS: we're running periodic status check for this task
    RESULT: the task has finished and result is ready
    """
    NONE = -1
    START = 0
    EXECUTED = 1
    STATUS = 2
    RESULT = 3
