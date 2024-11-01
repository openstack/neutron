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

from neutron.objects import l3agent
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class RouterL3AgentBindingIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = l3agent.RouterL3AgentBinding


class RouterL3AgentBindingDbObjTestCase(test_base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = l3agent.RouterL3AgentBinding

    def setUp(self):
        super().setUp()
        router_id = self._create_test_router_id()

        index = iter(range(1, len(self.objs) + 2))
        self.update_obj_fields(
            {'router_id': router_id,
             'binding_index': lambda: next(index),
             'l3_agent_id': lambda: self._create_test_agent_id()})
