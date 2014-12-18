# Copyright (c) 2015 Openstack Foundation
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

import mock

from neutron.agent.l3 import ha_router
from neutron.tests import base


class TestBasicRouterOperations(base.BaseTestCase):
    def setUp(self):
        super(TestBasicRouterOperations, self).setUp()

    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        return ha_router.HaRouter(mock.sentinel.router_id,
                                  router,
                                  mock.sentinel.agent_conf,
                                  mock.sentinel.driver,
                                  ns_name=mock.sentinel.namespace,
                                  **kwargs)

    def test_get_router_cidrs_returns_ha_cidrs(self):
        ri = self._create_router()
        device = mock.MagicMock()
        device.name.return_value = 'eth2'
        addresses = ['15.1.2.2/24', '15.1.2.3/32']
        ri._ha_get_existing_cidrs = mock.MagicMock(return_value=addresses)
        self.assertEqual(set(addresses), ri.get_router_cidrs(device))
