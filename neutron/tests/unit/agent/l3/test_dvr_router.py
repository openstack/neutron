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
import netaddr

from neutron.agent.l3 import dvr_router
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.openstack.common import uuidutils
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FIP_PRI = 32768
HOSTNAME = 'myhost'


class TestDvrRouterOperations(base.BaseTestCase):
    def setUp(self):
        super(TestDvrRouterOperations, self).setUp()

    def _create_router(self, router, **kwargs):
        agent_conf = mock.Mock()
        return dvr_router.DvrRouter(mock.sentinel.myhost,
                                    mock.sentinel.router_id,
                                    router,
                                    agent_conf,
                                    mock.sentinel.interface_driver,
                                    **kwargs)

    def test_get_floating_ips_dvr(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': mock.sentinel.myhost},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)

        fips = ri.get_floating_ips()

        self.assertEqual([{'host': mock.sentinel.myhost}], fips)

    @mock.patch.object(ip_lib, 'send_garp_for_proxyarp')
    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'IpRule')
    def test_floating_ip_added_dist(self, mIpRule, mIPDevice, mock_arp):
        router = mock.MagicMock()
        ri = self._create_router(router)
        ext_net_id = _uuid()
        agent_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                        'subnet_id': _uuid()}],
                         'subnet': {'gateway_ip': '20.0.0.1'},
                         'id': _uuid(),
                         'network_id': ext_net_id,
                         'mac_address': 'ca:fe:de:ad:be:ef',
                         'ip_cidr': '20.0.0.30/24'}

        fip = {'id': _uuid(),
               'host': HOSTNAME,
               'floating_ip_address': '15.1.2.3',
               'fixed_ip_address': '192.168.0.1',
               'floating_network_id': ext_net_id,
               'port_id': _uuid()}
        ri.fip_ns = mock.Mock()
        ri.fip_ns.agent_gateway_port = agent_gw_port
        ri.fip_ns.allocate_rule_priority.return_value = FIP_PRI
        ri.rtr_fip_subnet = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.dist_fip_count = 0
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        ri.floating_ip_added_dist(fip, ip_cidr)
        mIpRule().add.assert_called_with('192.168.0.1', 16, FIP_PRI)
        self.assertEqual(1, ri.dist_fip_count)
        # TODO(mrsmith): add more asserts

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'IpRule')
    def test_floating_ip_removed_dist(self, mIpRule, mIPDevice, mIPWrapper):
        router = mock.MagicMock()
        ri = self._create_router(router)

        agent_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                        'subnet_id': _uuid()}],
                         'subnet': {'gateway_ip': '20.0.0.1'},
                         'id': _uuid(),
                         'network_id': _uuid(),
                         'mac_address': 'ca:fe:de:ad:be:ef',
                         'ip_cidr': '20.0.0.30/24'}
        fip_cidr = '11.22.33.44/24'

        ri.dist_fip_count = 2
        ri.fip_ns = mock.Mock()
        ri.fip_ns.get_name.return_value = 'fip_ns_name'
        ri.floating_ips_dict['11.22.33.44'] = FIP_PRI
        ri.fip_2_rtr = '11.22.33.42'
        ri.rtr_2_fip = '11.22.33.40'
        ri.fip_ns.agent_gateway_port = agent_gw_port
        s = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.rtr_fip_subnet = s
        ri.floating_ip_removed_dist(fip_cidr)
        mIpRule().delete.assert_called_with(
            str(netaddr.IPNetwork(fip_cidr).ip), 16, FIP_PRI)
        mIPDevice().route.delete_route.assert_called_with(fip_cidr, str(s.ip))
        self.assertFalse(ri.fip_ns.unsubscribe.called)

        ri.dist_fip_count = 1
        ri.rtr_fip_subnet = lla.LinkLocalAddressPair('15.1.2.3/32')
        _, fip_to_rtr = ri.rtr_fip_subnet.get_pair()
        fip_ns = ri.fip_ns

        ri.floating_ip_removed_dist(fip_cidr)

        self.assertTrue(fip_ns.destroyed)
        mIPWrapper().del_veth.assert_called_once_with(
            fip_ns.get_int_device_name(router['id']))
        mIPDevice().route.delete_gateway.assert_called_once_with(
            str(fip_to_rtr.ip), table=16)
        fip_ns.unsubscribe.assert_called_once_with(ri.router_id)

    def _test_add_floating_ip(self, ri, fip, is_failure):
        ri._add_fip_addr_to_device = mock.Mock(return_value=is_failure)
        ri.floating_ip_added_dist = mock.Mock()

        result = ri.add_floating_ip(fip,
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        ri._add_fip_addr_to_device.assert_called_once_with(
            fip, mock.sentinel.device)
        return result

    def test_add_floating_ip(self):
        ri = self._create_router(mock.MagicMock())
        ip = '15.1.2.3'
        fip = {'floating_ip_address': ip}
        result = self._test_add_floating_ip(ri, fip, True)
        ri.floating_ip_added_dist.assert_called_once_with(fip, ip + '/32')
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ACTIVE, result)

    def test_add_floating_ip_error(self):
        ri = self._create_router(mock.MagicMock())
        result = self._test_add_floating_ip(
            ri, {'floating_ip_address': '15.1.2.3'}, False)
        self.assertFalse(ri.floating_ip_added_dist.called)
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ERROR, result)

    @mock.patch.object(router_info.RouterInfo, 'remove_floating_ip')
    def test_remove_floating_ip(self, super_remove_floating_ip):
        ri = self._create_router(mock.MagicMock())
        ri.floating_ip_removed_dist = mock.Mock()

        ri.remove_floating_ip(mock.sentinel.device, mock.sentinel.ip_cidr)

        super_remove_floating_ip.assert_called_once_with(
            mock.sentinel.device, mock.sentinel.ip_cidr)
        ri.floating_ip_removed_dist.assert_called_once_with(
            mock.sentinel.ip_cidr)
