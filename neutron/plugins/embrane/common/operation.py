# Copyright 2013 Embrane, Inc.
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


class Operation(object):
    """Defines a series of operations which shall be executed in order.

    the operations expected are procedures, return values are discarded

    """

    def __init__(self, procedure, args=(), kwargs={}, nextop=None):
        self._procedure = procedure
        self.args = args[:]
        self.kwargs = dict(kwargs)
        self.nextop = nextop

    def execute(self):
        args = self.args
        self._procedure(*args, **self.kwargs)
        return self.nextop

    def execute_all(self):
        nextop = self.execute()
        while nextop:
            nextop = self.execute_all()

    def has_next(self):
        return self.nextop is not None

    def add_bottom_operation(self, operation):
        op = self
        while op.has_next():
            op = op.nextop
        op.nextop = operation
