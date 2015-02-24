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

from neutron.agent.l3 import legacy_router
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.openstack.common import uuidutils
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class BasicRouterTestCaseFramework(base.BaseTestCase):
    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        self.driver = mock.Mock()
        self.router_id = _uuid()
        return legacy_router.LegacyRouter(self.router_id,
                                          router,
                                          self.agent_conf,
                                          self.driver,
                                          **kwargs)


class TestBasicRouterOperations(BasicRouterTestCaseFramework):

    def test_remove_floating_ip(self):
        ri = self._create_router(mock.MagicMock())
        device = mock.Mock()
        cidr = '15.1.2.3/32'

        ri.remove_floating_ip(device, cidr)

        device.addr.delete.assert_called_once_with(cidr)
        self.driver.delete_conntrack_state.assert_called_once_with(
            ip=cidr,
            namespace=ri.ns_name)


@mock.patch.object(ip_lib, 'send_ip_addr_adv_notif')
class TestAddFloatingIpWithMockGarp(BasicRouterTestCaseFramework):
    def test_add_floating_ip(self, send_ip_addr_adv_notif):
        ri = self._create_router()
        ri._add_fip_addr_to_device = mock.Mock(return_value=True)
        ip = '15.1.2.3'
        result = ri.add_floating_ip({'floating_ip_address': ip},
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        ip_lib.send_ip_addr_adv_notif.assert_called_once_with(
            ri.ns_name,
            mock.sentinel.interface_name,
            ip,
            self.agent_conf)
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ACTIVE, result)

    def test_add_floating_ip_error(self, send_ip_addr_adv_notif):
        ri = self._create_router()
        ri._add_fip_addr_to_device = mock.Mock(return_value=False)
        result = ri.add_floating_ip({'floating_ip_address': '15.1.2.3'},
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        self.assertFalse(ip_lib.send_ip_addr_adv_notif.called)
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ERROR, result)
