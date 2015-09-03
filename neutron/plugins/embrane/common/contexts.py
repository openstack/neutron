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


class DispatcherContext(object):

    def __init__(self, event, item, neutron_context, chain=None):
        self.event = event
        self.item = item
        self.n_context = neutron_context
        self.chain = chain


class OperationContext(DispatcherContext):
    """Operational context.

    contains all the parameters needed to execute a status aware operation

    """
    def __init__(self, event, context, item, chain, function, args, kwargs):
        super(OperationContext, self).__init__(event, item, context, chain)
        self.function = function
        self.args = args
        self.kwargs = kwargs
