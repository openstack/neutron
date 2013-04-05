# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
#
# @author: Rossella Sblendido, Midokura Europe SARL
# @author: Ryu Ishimoto, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK

import sys
import uuid

import mock

import quantum.tests.unit.test_db_plugin as test_plugin


MIDOKURA_PKG_PATH = "quantum.plugins.midonet.plugin"

# Need to mock the midonetclient module since the plugin will try to load it.
sys.modules["midonetclient"] = mock.Mock()


class MidonetPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)

    def setUp(self):
        self.mock_api = mock.patch('midonetclient.api.MidonetApi')
        self.instance = self.mock_api.start()
        super(MidonetPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(MidonetPluginV2TestCase, self).tearDown()
        self.mock_api.stop()

    def _setup_bridge_mock(self, bridge_id=str(uuid.uuid4()), name='net'):
        # Set up mocks needed for the parent network() method
        bridge = mock.Mock()
        bridge.get_id.return_value = bridge_id
        bridge.get_name.return_value = name

        self.instance.return_value.add_bridge.return_value.name.return_value\
            .tenant_id.return_value.create.return_value = bridge
        self.instance.return_value.get_bridges.return_value = [bridge]
        self.instance.return_value.get_bridge.return_value = bridge
        return bridge

    def _setup_subnet_mocks(self, subnet_id=str(uuid.uuid4()),
                            subnet_prefix='10.0.0.0', subnet_len=int(24)):
        # Set up mocks needed for the parent subnet() method
        bridge = self._setup_bridge_mock()
        subnet = mock.Mock()
        subnet.get_subnet_prefix.return_value = subnet_prefix
        subnet.get_subnet_length.return_value = subnet_len
        subnet.get_id.return_value = subnet_prefix + '/' + str(subnet_len)
        bridge.add_dhcp_subnet.return_value.default_gateway\
            .return_value.subnet_prefix.return_value.subnet_length\
            .return_value.create.return_value = subnet
        bridge.get_dhcp_subnets.return_value = [subnet]
        return (bridge, subnet)

    def _setup_port_mocks(self, port_id=str(uuid.uuid4())):
        # Set up mocks needed for the parent port() method
        bridge, subnet = self._setup_subnet_mocks()
        port = mock.Mock()
        port.get_id.return_value = port_id
        self.instance.return_value.create_port.return_value = port
        self.instance.return_value.get_port.return_value = port
        bridge.add_exterior_port.return_value.create.return_value = (
            port
        )

        dhcp_host = mock.Mock()
        rv1 = subnet.add_dhcp_host.return_value.ip_addr.return_value
        rv1.mac_addr.return_value.create.return_value = dhcp_host

        subnet.get_dhcp_hosts.return_value = [dhcp_host]
        return (bridge, subnet, port, dhcp_host)


class TestMidonetNetworksV2(test_plugin.TestNetworksV2,
                            MidonetPluginV2TestCase):

    def test_create_network(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2, self).test_create_network()

    def test_create_public_network(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2, self).test_create_public_network()

    def test_create_public_network_no_admin_tenant(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2,
              self).test_create_public_network_no_admin_tenant()

    def test_update_network(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2, self).test_update_network()

    def test_list_networks(self):
        self._setup_bridge_mock()
        with self.network(name='net1') as net1:
            req = self.new_list_request('networks')
            res = self.deserialize('json', req.get_response(self.api))
            self.assertEqual(res['networks'][0]['name'],
                             net1['network']['name'])

    def test_show_network(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2, self).test_show_network()

    def test_update_shared_network_noadmin_returns_403(self):
        self._setup_bridge_mock()
        super(TestMidonetNetworksV2,
              self).test_update_shared_network_noadmin_returns_403()

    def test_update_network_set_shared(self):
        pass

    def test_update_network_with_subnet_set_shared(self):
        pass

    def test_update_network_set_not_shared_single_tenant(self):
        pass

    def test_update_network_set_not_shared_other_tenant_returns_409(self):
        pass

    def test_update_network_set_not_shared_multi_tenants_returns_409(self):
        pass

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        pass

    def test_create_networks_bulk_native(self):
        pass

    def test_create_networks_bulk_native_quotas(self):
        pass

    def test_create_networks_bulk_tenants_and_quotas(self):
        pass

    def test_create_networks_bulk_tenants_and_quotas_fail(self):
        pass

    def test_create_networks_bulk_emulated(self):
        pass

    def test_create_networks_bulk_wrong_input(self):
        pass

    def test_create_networks_bulk_emulated_plugin_failure(self):
        pass

    def test_create_networks_bulk_native_plugin_failure(self):
        pass

    def test_list_networks_with_parameters(self):
        pass

    def test_list_networks_with_fields(self):
        pass

    def test_list_networks_with_parameters_invalid_values(self):
        pass

    def test_show_network_with_subnet(self):
        pass

    def test_invalid_admin_status(self):
        pass

    def test_list_networks_with_pagination_emulated(self):
        pass

    def test_list_networks_with_pagination_reverse_emulated(self):
        pass

    def test_list_networks_with_sort_emulated(self):
        pass

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        pass


class TestMidonetSubnetsV2(test_plugin.TestSubnetsV2,
                           MidonetPluginV2TestCase):

    def test_create_subnet(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet()

    def test_create_two_subnets(self):
        pass

    def test_create_two_subnets_same_cidr_returns_400(self):
        pass

    def test_create_subnet_bad_V4_cidr(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_V4_cidr()

    def test_create_subnet_bad_V6_cidr(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_V4_cidr()

    def test_create_2_subnets_overlapping_cidr_allowed_returns_200(self):
        pass

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        pass

    def test_create_subnets_bulk_native(self):
        pass

    def test_create_subnets_bulk_emulated(self):
        pass

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        pass

    def test_create_subnets_bulk_native_plugin_failure(self):
        pass

    def test_delete_subnet(self):
        _bridge, subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_delete_subnet()
        subnet.delete.assert_called_once_with()

    def test_delete_subnet_port_exists_owned_by_network(self):
        _bridge, subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_delete_subnet_port_exists_owned_by_network()

    def test_delete_subnet_port_exists_owned_by_other(self):
        pass

    def test_delete_network(self):
        bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_delete_network()
        bridge.delete.assert_called_once_with()

    def test_create_subnet_bad_tenant(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_tenant()

    def test_create_subnet_bad_ip_version(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_ip_version()

    def test_create_subnet_bad_ip_version_null(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_bad_ip_version_null()

    def test_create_subnet_bad_uuid(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_uuid()

    def test_create_subnet_bad_boolean(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_boolean()

    def test_create_subnet_bad_pools(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_pools()

    def test_create_subnet_bad_nameserver(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_nameserver()

    def test_create_subnet_bad_hostroutes(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_bad_hostroutes()

    def test_create_subnet_defaults(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_defaults()

    def test_create_subnet_gw_values(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_gw_values()

    def test_create_force_subnet_gw_values(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_force_subnet_gw_values()

    def test_create_subnet_with_allocation_pool(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_allocation_pool()

    def test_create_subnet_with_none_gateway(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_none_gateway()

    def test_create_subnet_with_none_gateway_fully_allocated(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_none_gateway_fully_allocated()

    def test_subnet_with_allocation_range(self):
        pass

    def test_create_subnet_with_none_gateway_allocation_pool(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_none_gateway_allocation_pool()

    def test_create_subnet_with_v6_allocation_pool(self):
        pass

    def test_create_subnet_with_large_allocation_pool(self):
        pass

    def test_create_subnet_multiple_allocation_pools(self):
        pass

    def test_create_subnet_with_dhcp_disabled(self):
        pass

    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
        self):
        pass

    def test_create_subnet_gateway_in_allocation_pool_returns_409(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self)\
            .test_create_subnet_gateway_in_allocation_pool_returns_409()

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self)\
            .test_create_subnet_overlapping_allocation_pools_returns_409()

    def test_create_subnet_invalid_allocation_pool_returns_400(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_invalid_allocation_pool_returns_400()

    def test_create_subnet_out_of_range_allocation_pool_returns_400(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self)\
            .test_create_subnet_out_of_range_allocation_pool_returns_400()

    def test_create_subnet_shared_returns_400(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_shared_returns_400()

    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        pass

    def test_create_subnet_inconsistent_ipv4_cidrv6(self):
        pass

    def test_create_subnet_inconsistent_ipv4_gatewayv6(self):
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        pass

    def test_update_subnet(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_update_subnet()

    def test_update_subnet_shared_returns_400(self):
        self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_update_subnet_shared_returns_400()

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        pass

    def test_show_subnet(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_show_subnet()

    def test_list_subnets(self):
        pass

    def test_list_subnets_shared(self):
        pass

    def test_list_subnets_with_parameter(self):
        pass

    def test_invalid_ip_version(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_invalid_ip_version()

    def test_invalid_subnet(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_invalid_subnet()

    def test_invalid_ip_address(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_invalid_ip_address()

    def test_invalid_uuid(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_invalid_uuid()

    def test_create_subnet_with_one_dns(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_with_one_dns()

    def test_create_subnet_with_two_dns(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_create_subnet_with_two_dns()

    def test_create_subnet_with_too_many_dns(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_too_many_dns()

    def test_create_subnet_with_one_host_route(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_one_host_route()

    def test_create_subnet_with_two_host_routes(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_two_host_routes()

    def test_create_subnet_with_too_many_routes(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_create_subnet_with_too_many_routes()

    def test_update_subnet_dns(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_update_subnet_dns()

    def test_update_subnet_dns_to_None(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_update_subnet_dns_to_None()

    def test_update_subnet_dns_with_too_many_entries(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_update_subnet_dns_with_too_many_entries()

    def test_update_subnet_route(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_update_subnet_route()

    def test_update_subnet_route_to_None(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_update_subnet_route_to_None()

    def test_update_subnet_route_with_too_many_entries(self):
        _bridge, _subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_update_subnet_route_with_too_many_entries()

    def test_delete_subnet_with_dns(self):
        _bridge, subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_delete_subnet_with_dns()
        subnet.delete.assert_called_once_with()

    def test_delete_subnet_with_route(self):
        _bridge, subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2, self).test_delete_subnet_with_route()
        subnet.delete.assert_called_once_with()

    def test_delete_subnet_with_dns_and_route(self):
        _bridge, subnet = self._setup_subnet_mocks()
        super(TestMidonetSubnetsV2,
              self).test_delete_subnet_with_dns_and_route()
        subnet.delete.assert_called_once_with()

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self._setup_port_mocks()
        super(TestMidonetSubnetsV2, self)\
            .test_update_subnet_gateway_in_allocation_pool_returns_409()

    def test_list_subnets_with_pagination_emulated(self):
        pass

    def test_list_subnets_with_pagination_reverse_emulated(self):
        pass

    def test_list_subnets_with_sort_emulated(self):
        pass


class TestMidonetPortsV2(test_plugin.TestPortsV2,
                         MidonetPluginV2TestCase):

    def test_create_port_json(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_create_port_json()

    def test_create_port_bad_tenant(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_create_port_bad_tenant()

    def test_create_port_public_network(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_create_port_public_network()

    def test_create_port_public_network_with_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2,
              self).test_create_port_public_network_with_ip()

    def test_create_ports_bulk_native(self):
        pass

    def test_create_ports_bulk_emulated(self):
        pass

    def test_create_ports_bulk_wrong_input(self):
        pass

    def test_create_ports_bulk_emulated_plugin_failure(self):
        pass

    def test_create_ports_bulk_native_plugin_failure(self):
        pass

    def test_list_ports(self):
        pass

    def test_list_ports_filtered_by_fixed_ip(self):
        pass

    def test_list_ports_public_network(self):
        pass

    def test_show_port(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_show_port()

    def test_delete_port(self):
        _bridge, _subnet, port, _dhcp = self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_delete_port()
        port.delete.assert_called_once_with()

    def test_delete_port_public_network(self):
        _bridge, _subnet, port, _dhcp = self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_delete_port_public_network()
        port.delete.assert_called_once_with()

    def test_update_port(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_port()

    def test_update_device_id_null(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_device_id_null()

    def test_delete_network_if_port_exists(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_delete_network_if_port_exists()

    def test_delete_network_port_exists_owned_by_network(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2,
              self).test_delete_network_port_exists_owned_by_network()

    def test_update_port_delete_ip(self):
        pass

    def test_no_more_port_exception(self):
        pass

    def test_update_port_update_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_port_update_ip()

    def test_update_port_update_ip_address_only(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2,
              self).test_update_port_update_ip_address_only()

    def test_update_port_update_ips(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_port_update_ips()

    def test_update_port_add_additional_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_port_add_additional_ip()

    def test_requested_duplicate_mac(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_requested_duplicate_mac()

    def test_mac_generation(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_mac_generation()

    def test_mac_generation_4octet(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_mac_generation_4octet()

    def test_bad_mac_format(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_bad_mac_format()

    def test_mac_exhaustion(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_mac_exhaustion()

    def test_requested_duplicate_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_requested_duplicate_ip()

    def test_requested_subnet_delete(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_requested_subnet_delete()

    def test_requested_subnet_id(self):
        pass

    def test_requested_subnet_id_not_on_network(self):
        pass

    def test_overlapping_subnets(self):
        pass

    def test_requested_subnet_id_v4_and_v6(self):
        pass

    def test_range_allocation(self):
        pass

    def test_requested_invalid_fixed_ips(self):
        pass

    def test_invalid_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_invalid_ip()

    def test_requested_split(self):
        pass

    def test_duplicate_ips(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_duplicate_ips()

    def test_fixed_ip_invalid_subnet_id(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_fixed_ip_invalid_subnet_id()

    def test_fixed_ip_invalid_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_fixed_ip_invalid_ip()

    def test_requested_ips_only(self):
        pass

    def test_recycling(self):
        pass

    def test_invalid_admin_state(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_invalid_admin_state()

    def test_invalid_mac_address(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_invalid_mac_address()

    def test_default_allocation_expiration(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_default_allocation_expiration()

    def test_update_fixed_ip_lease_expiration(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2,
              self).test_update_fixed_ip_lease_expiration()

    def test_port_delete_holds_ip(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_port_delete_holds_ip()

    def test_update_fixed_ip_lease_expiration_invalid_address(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2,
              self).test_update_fixed_ip_lease_expiration_invalid_address()

    def test_hold_ip_address(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_hold_ip_address()

    def test_recycle_held_ip_address(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_recycle_held_ip_address()

    def test_recycle_expired_previously_run_within_context(self):
        pass

    def test_update_port_not_admin(self):
        self._setup_port_mocks()
        super(TestMidonetPortsV2, self).test_update_port_not_admin()

    def test_list_ports_with_pagination_emulated(self):
        pass

    def test_list_ports_with_pagination_reverse_emulated(self):
        pass

    def test_list_ports_with_sort_emulated(self):
        pass

    def test_max_fixed_ips_exceeded(self):
        pass

    def test_update_max_fixed_ips_exceeded(self):
        pass
