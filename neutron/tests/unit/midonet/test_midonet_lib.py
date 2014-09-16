# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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
import sys

import mock
import testtools
import webob.exc as w_exc

from neutron.openstack.common import uuidutils
with mock.patch.dict(sys.modules, {'midonetclient': mock.Mock()}):
    from neutron.plugins.midonet import midonet_lib
import neutron.tests.unit.midonet.mock_lib as mock_lib


def _create_test_chain(id, name, tenant_id):
    return {'id': id, 'name': name, 'tenant_id': tenant_id}


def _create_test_port_group(id, name, tenant_id):
    return {"id": id, "name": name, "tenant_id": tenant_id}


class MidoClientTestCase(testtools.TestCase):

    def setUp(self):
        super(MidoClientTestCase, self).setUp()
        self._tenant_id = 'test-tenant'
        self.mock_api = mock.Mock()
        self.mock_api_cfg = mock_lib.MidoClientMockConfig(self.mock_api)
        self.mock_api_cfg.setup()
        self.client = midonet_lib.MidoClient(self.mock_api)

    def test_delete_chains_by_names(self):

        tenant_id = uuidutils.generate_uuid()
        chain1_id = uuidutils.generate_uuid()
        chain1 = _create_test_chain(chain1_id, "chain1", tenant_id)

        chain2_id = uuidutils.generate_uuid()
        chain2 = _create_test_chain(chain2_id, "chain2", tenant_id)

        calls = [mock.call.delete_chain(chain1_id),
                 mock.call.delete_chain(chain2_id)]
        self.mock_api_cfg.chains_in = [chain2, chain1]
        self.client.delete_chains_by_names(tenant_id, ["chain1", "chain2"])

        self.mock_api.assert_has_calls(calls, any_order=True)

    def test_delete_port_group_by_name(self):

        tenant_id = uuidutils.generate_uuid()
        pg1_id = uuidutils.generate_uuid()
        pg1 = _create_test_port_group(pg1_id, "pg1", tenant_id)
        pg2_id = uuidutils.generate_uuid()
        pg2 = _create_test_port_group(pg2_id, "pg2", tenant_id)

        self.mock_api_cfg.port_groups_in = [pg1, pg2]
        self.client.delete_port_group_by_name(tenant_id, "pg1")
        self.mock_api.delete_port_group.assert_called_once_with(pg1_id)

    def test_create_dhcp(self):

        bridge = mock.Mock()

        gateway_ip = "192.168.1.1"
        cidr = "192.168.1.0/24"
        host_rts = [{'destination': '10.0.0.0/24', 'nexthop': '10.0.0.1'},
                    {'destination': '10.0.1.0/24', 'nexthop': '10.0.1.1'}]
        dns_servers = ["8.8.8.8", "8.8.4.4"]

        dhcp_call = mock.call.add_bridge_dhcp(bridge, gateway_ip, cidr,
                                              host_rts=host_rts,
                                              dns_nservers=dns_servers)

        self.client.create_dhcp(bridge, gateway_ip, cidr, host_rts=host_rts,
                                dns_servers=dns_servers)
        self.mock_api.assert_has_calls([dhcp_call])

    def test_delete_dhcp(self):

        bridge = mock.Mock()
        subnet = mock.Mock()
        subnet.get_subnet_prefix.return_value = "10.0.0.0"
        subnets = mock.MagicMock(return_value=[subnet])
        bridge.get_dhcp_subnets.side_effect = subnets
        self.client.delete_dhcp(bridge, "10.0.0.0/24")
        bridge.assert_has_calls(mock.call.get_dhcp_subnets)
        subnet.assert_has_calls([mock.call.get_subnet_prefix(),
                                mock.call.delete()])

    def test_add_dhcp_host(self):

        bridge = mock.Mock()
        dhcp_subnet_call = mock.call.get_dhcp_subnet("10.0.0.0_24")
        ip_addr_call = dhcp_subnet_call.add_dhcp_host().ip_addr("10.0.0.10")
        mac_addr_call = ip_addr_call.mac_addr("2A:DB:6B:8C:19:99")
        calls = [dhcp_subnet_call, ip_addr_call, mac_addr_call,
                 mac_addr_call.create()]

        self.client.add_dhcp_host(bridge, "10.0.0.0/24", "10.0.0.10",
                                  "2A:DB:6B:8C:19:99")
        bridge.assert_has_calls(calls, any_order=True)

    def test_add_dhcp_route_option(self):

        bridge = mock.Mock()
        subnet = bridge.get_dhcp_subnet.return_value
        subnet.get_opt121_routes.return_value = None
        dhcp_subnet_call = mock.call.get_dhcp_subnet("10.0.0.0_24")
        dst_ip = "10.0.0.3/24"
        gw_ip = "10.0.0.1"
        prefix, length = dst_ip.split("/")
        routes = [{'destinationPrefix': prefix, 'destinationLength': length,
                   'gatewayAddr': gw_ip}]
        opt121_routes_call = dhcp_subnet_call.opt121_routes(routes)
        calls = [dhcp_subnet_call, opt121_routes_call,
                 opt121_routes_call.update()]

        self.client.add_dhcp_route_option(bridge, "10.0.0.0/24",
                                          gw_ip, dst_ip)
        bridge.assert_has_calls(calls, any_order=True)

    def test_get_router_error(self):
        self.mock_api.get_router.side_effect = w_exc.HTTPInternalServerError()
        self.assertRaises(midonet_lib.MidonetApiException,
                          self.client.get_router, uuidutils.generate_uuid())

    def test_get_router_not_found(self):
        self.mock_api.get_router.side_effect = w_exc.HTTPNotFound()
        self.assertRaises(midonet_lib.MidonetResourceNotFound,
                          self.client.get_router, uuidutils.generate_uuid())

    def test_get_bridge_error(self):
        self.mock_api.get_bridge.side_effect = w_exc.HTTPInternalServerError()
        self.assertRaises(midonet_lib.MidonetApiException,
                          self.client.get_bridge, uuidutils.generate_uuid())

    def test_get_bridge_not_found(self):
        self.mock_api.get_bridge.side_effect = w_exc.HTTPNotFound()
        self.assertRaises(midonet_lib.MidonetResourceNotFound,
                          self.client.get_bridge, uuidutils.generate_uuid())

    def test_get_bridge(self):
        bridge_id = uuidutils.generate_uuid()

        bridge = self.client.get_bridge(bridge_id)

        self.assertIsNotNone(bridge)
        self.assertEqual(bridge.get_id(), bridge_id)
        self.assertTrue(bridge.get_admin_state_up())

    def test_add_bridge_port(self):
        bridge_id = uuidutils.generate_uuid()

        bridge = self.client.get_bridge(bridge_id)

        self.assertIsNotNone(bridge)

        port = self.client.add_bridge_port(bridge)

        self.assertEqual(bridge.get_id(), port.get_bridge_id())
        self.assertTrue(port.get_admin_state_up())

    def test_get_router(self):
        router_id = uuidutils.generate_uuid()

        router = self.client.get_router(router_id)

        self.assertIsNotNone(router)
        self.assertEqual(router.get_id(), router_id)
        self.assertTrue(router.get_admin_state_up())
