# Copyright 2016 Red Hat, Inc.
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

import functools

from neutron.tests.common.exclusive_resources import resource_allocator
from neutron.tests.common import net_helpers


class ExclusivePort(resource_allocator.ExclusiveResource):
    """Allocate a unique port for a specific protocol.

    :ivar port: allocated port
    :type port: int
    """

    def __init__(self, protocol, start=1024, end=None):
        super().__init__(
            'ports',
            functools.partial(net_helpers.get_free_namespace_port, protocol,
                              start=start, end=end))

    def _setUp(self):
        super()._setUp()
        self.port = self.resource
