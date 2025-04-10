# Copyright (c) 2015 OpenStack Foundation
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

from unittest import mock

from neutron_lib import constants as lib_constants
from oslo_utils import uuidutils

from neutron.agent.l3 import legacy_router
from neutron.agent.linux import ip_lib
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class BasicRouterTestCaseFramework(base.BaseTestCase):
    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        self.driver = mock.Mock()
        self.router_id = _uuid()
        return legacy_router.LegacyRouter(mock.Mock(),
                                          self.router_id,
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

        device.delete_addr_and_conntrack_state.assert_called_once_with(cidr)

    def test_remove_external_gateway_ip(self):
        ri = self._create_router(mock.MagicMock())
        device = mock.Mock()
        cidr = '172.16.0.0/24'

        ri.remove_external_gateway_ip(device, cidr)

        device.delete_addr_and_conntrack_state.assert_called_once_with(cidr)

    @mock.patch.object(ip_lib, 'IPDevice')
    def test_remove_multiple_external_gateway_ips(self, IPDevice):
        ri = self._create_router(mock.MagicMock())
        IPDevice.return_value = device = mock.Mock()
        gw_ip_pri = '172.16.5.110'
        gw_ip_sec = '172.16.5.111'
        gw_ip6_pri = '2001:db8::1'
        gw_ip6_sec = '2001:db8::2'
        v4_prefixlen = 24
        v6_prefixlen = 64
        ex_gw_port = {'fixed_ips': [
            {'ip_address': gw_ip_pri,
             'prefixlen': v4_prefixlen},
            {'ip_address': gw_ip_sec},
            {'ip_address': gw_ip6_pri,
             'prefixlen': v6_prefixlen},
            {'ip_address': gw_ip6_sec}]}

        ri.external_gateway_removed(ex_gw_port, "qg-fake-name")

        cidr_pri = f'{gw_ip_pri}/{v4_prefixlen}'
        cidr_sec = f'{gw_ip_sec}/{lib_constants.IPv4_BITS}'
        cidr_v6 = f'{gw_ip6_pri}/{v6_prefixlen}'
        cidr_v6_sec = f'{gw_ip6_sec}/{lib_constants.IPv6_BITS}'

        device.delete_addr_and_conntrack_state.assert_has_calls(
            [mock.call(cidr_pri), mock.call(cidr_sec),
             mock.call(cidr_v6), mock.call(cidr_v6_sec)])


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
            ip)
        self.assertEqual(lib_constants.FLOATINGIP_STATUS_ACTIVE, result)

    def test_add_floating_ip_error(self, send_ip_addr_adv_notif):
        ri = self._create_router()
        ri._add_fip_addr_to_device = mock.Mock(return_value=False)
        result = ri.add_floating_ip({'floating_ip_address': '15.1.2.3'},
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        self.assertFalse(ip_lib.send_ip_addr_adv_notif.called)
        self.assertEqual(lib_constants.FLOATINGIP_STATUS_ERROR, result)
