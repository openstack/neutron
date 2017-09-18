# Copyright (c) 2016 Intel Corporation.
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

from neutron.objects import l3_hamode
from neutron.tests.unit.objects import test_base as base
from neutron.tests.unit import testlib_api


class L3HARouterAgentPortBindingIfaceObjectTestCase(
    base.BaseObjectIfaceTestCase):

    _test_class = l3_hamode.L3HARouterAgentPortBinding


class L3HARouterAgentPortBindingDbObjectTestCase(base.BaseDbObjectTestCase,
                                                 testlib_api.SqlTestCase):

    _test_class = l3_hamode.L3HARouterAgentPortBinding

    def setUp(self):
        super(L3HARouterAgentPortBindingDbObjectTestCase,
              self).setUp()
        _network_id = self._create_test_network_id()

        def get_port():
            return self._create_test_port_id(network_id=_network_id)

        self.update_obj_fields({'port_id': get_port,
                                'router_id': self._create_test_router_id,
                                'l3_agent_id': self._create_test_agent_id})


class L3HARouterNetworkIfaceObjectTestCase(base.BaseObjectIfaceTestCase):

    _test_class = l3_hamode.L3HARouterNetwork


class L3HARouterNetworkDbObjectTestCase(base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = l3_hamode.L3HARouterNetwork

    def setUp(self):
        super(L3HARouterNetworkDbObjectTestCase, self).setUp()
        network = self._create_test_network()
        self.update_obj_fields({'network_id': network.id})


class L3HARouterVRIdAllocationIfaceObjectTestCase(
    base.BaseObjectIfaceTestCase):

    _test_class = l3_hamode.L3HARouterVRIdAllocation


class L3HARouterVRIdAllocationDbObjectTestCase(base.BaseDbObjectTestCase,
                                               testlib_api.SqlTestCase):

    _test_class = l3_hamode.L3HARouterVRIdAllocation

    def setUp(self):
        super(L3HARouterVRIdAllocationDbObjectTestCase, self).setUp()
        self.update_obj_fields(
            {'network_id': lambda: self._create_test_network().id})
