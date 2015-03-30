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
from neutron.openstack.common import uuidutils
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class TestBasicRouterOperations(base.BaseTestCase):
    def setUp(self):
        super(TestBasicRouterOperations, self).setUp()

    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        # NOTE The use_namespaces config will soon be deprecated
        self.agent_conf.use_namespaces = True
        self.router_id = _uuid()
        return ha_router.HaRouter(mock.sentinel.enqueue_state,
                                  self.router_id,
                                  router,
                                  self.agent_conf,
                                  mock.sentinel.driver,
                                  **kwargs)

    def test_get_router_cidrs_returns_ha_cidrs(self):
        ri = self._create_router()
        device = mock.MagicMock()
        device.name.return_value = 'eth2'
        addresses = ['15.1.2.2/24', '15.1.2.3/32']
        ri._get_cidrs_from_keepalived = mock.MagicMock(return_value=addresses)
        self.assertEqual(set(addresses), ri.get_router_cidrs(device))
