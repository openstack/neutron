# Copyright 2015 OpenStack Foundation.
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

from unittest import mock

import netaddr
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron.ipam.drivers.neutrondb_ipam import driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.objects import ipam as ipam_obj
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin
from neutron.tests.unit import testlib_api


def convert_firstip_to_ipaddress(range_item):
    return netaddr.IPAddress(range_item['first_ip'])


class TestNeutronDbIpamMixin(object):

    def _create_network(self, plugin, ctx, shared=False):
        network = {'network': {'name': 'net',
                               'shared': shared,
                               'admin_state_up': True,
                               'tenant_id': self._tenant_id}}
        created_network = plugin.create_network(ctx, network)
        return (created_network, created_network['id'])

    def _create_subnet(self, plugin, ctx, network_id, cidr,
                       ip_version=constants.IP_VERSION_4,
                       v6_address_mode=constants.ATTR_NOT_SPECIFIED,
                       allocation_pools=constants.ATTR_NOT_SPECIFIED):
        subnet = {'subnet': {'name': 'sub',
                             'cidr': cidr,
                             'ip_version': ip_version,
                             'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                             'allocation_pools': allocation_pools,
                             'enable_dhcp': True,
                             'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                             'host_routes': constants.ATTR_NOT_SPECIFIED,
                             'ipv6_address_mode': v6_address_mode,
                             'ipv6_ra_mode': constants.ATTR_NOT_SPECIFIED,
                             'network_id': network_id,
                             'tenant_id': self._tenant_id}}
        return plugin.create_subnet(ctx, subnet)


class TestNeutronDbIpamPool(testlib_api.SqlTestCase,
                            TestNeutronDbIpamMixin):
    """Test case for the Neutron's DB IPAM driver subnet pool interface."""

    def setUp(self):
        super(TestNeutronDbIpamPool, self).setUp()
        self._tenant_id = 'test-tenant'

        # Configure plugin for tests
        self.setup_coreplugin(test_db_plugin.DB_PLUGIN_KLASS)

        # Prepare environment for tests
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.network, self.net_id = self._create_network(self.plugin,
                                                         self.ctx)

        # Allocate IPAM driver
        self.ipam_pool = driver.NeutronDbPool(None, self.ctx)

    def _verify_ipam_subnet_details(self, ipam_subnet,
                                    cidr=None,
                                    tenant_id=None,
                                    gateway_ip=None,
                                    allocation_pools=None):
        ipam_subnet_details = ipam_subnet.get_details()
        gateway_ip_address = None
        cidr_ip_network = None
        if gateway_ip:
            gateway_ip_address = netaddr.IPAddress(gateway_ip)
        if cidr:
            cidr_ip_network = netaddr.IPNetwork(cidr)
        self.assertEqual(tenant_id, ipam_subnet_details.tenant_id)
        self.assertEqual(gateway_ip_address, ipam_subnet_details.gateway_ip)
        self.assertEqual(cidr_ip_network, ipam_subnet_details.subnet_cidr)
        self.assertEqual(allocation_pools,
                         ipam_subnet_details.allocation_pools)

    def test_allocate_ipam_subnet_no_neutron_subnet_id(self):
        cidr = '10.0.0.0/24'
        allocation_pools = [netaddr.IPRange('10.0.0.100', '10.0.0.150'),
                            netaddr.IPRange('10.0.0.200', '10.0.0.250')]
        subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            None,
            cidr,
            allocation_pools=allocation_pools,
            gateway_ip='10.0.0.101')
        ipam_subnet = self.ipam_pool.allocate_subnet(subnet_req)
        self._verify_ipam_subnet_details(ipam_subnet,
                                         cidr,
                                         self._tenant_id,
                                         '10.0.0.101',
                                         allocation_pools)

    def _prepare_specific_subnet_request(self, cidr):
        subnet = self._create_subnet(
            self.plugin, self.ctx, self.net_id, cidr)
        subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            subnet['id'],
            cidr,
            gateway_ip=subnet['gateway_ip'])
        return subnet, subnet_req

    def test_allocate_ipam_subnet_with_neutron_subnet_id(self):
        cidr = '10.0.0.0/24'
        subnet, subnet_req = self._prepare_specific_subnet_request(cidr)
        ipam_subnet = self.ipam_pool.allocate_subnet(subnet_req)
        self._verify_ipam_subnet_details(
            ipam_subnet,
            cidr, self._tenant_id, subnet['gateway_ip'],
            [netaddr.IPRange('10.0.0.2', '10.0.0.254')])

    def test_allocate_any_subnet_fails(self):
        self.assertRaises(
            ipam_exc.InvalidSubnetRequestType,
            self.ipam_pool.allocate_subnet,
            ipam_req.AnySubnetRequest(self._tenant_id, 'meh',
                                      constants.IPv4, 24))

    def _test_update_subnet_pools(self, allocation_pools, expected_pools=None):
        if expected_pools is None:
            expected_pools = allocation_pools
        cidr = '10.0.0.0/24'
        subnet, subnet_req = self._prepare_specific_subnet_request(cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        update_subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            subnet['id'],
            cidr,
            gateway_ip=subnet['gateway_ip'],
            allocation_pools=allocation_pools)
        self.ipam_pool.update_subnet(update_subnet_req)
        ipam_subnet = self.ipam_pool.get_subnet(subnet['id'])
        self._verify_ipam_subnet_details(
            ipam_subnet,
            cidr, self._tenant_id, subnet['gateway_ip'], expected_pools)

    def test_update_subnet_pools(self):
        allocation_pools = [netaddr.IPRange('10.0.0.100', '10.0.0.150'),
                            netaddr.IPRange('10.0.0.200', '10.0.0.250')]
        self._test_update_subnet_pools(allocation_pools)

    def test_update_subnet_pools_with_blank_pools(self):
        allocation_pools = []
        self._test_update_subnet_pools(allocation_pools)

    def test_update_subnet_pools_with_none_pools(self):
        allocation_pools = None
        expected_pools = [netaddr.IPRange('10.0.0.2', '10.0.0.254')]
        # Pools should not be changed on update
        self._test_update_subnet_pools(allocation_pools,
                                       expected_pools=expected_pools)

    def test_get_subnet(self):
        cidr = '10.0.0.0/24'
        subnet, subnet_req = self._prepare_specific_subnet_request(cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        # Retrieve the subnet
        ipam_subnet = self.ipam_pool.get_subnet(subnet['id'])
        self._verify_ipam_subnet_details(
            ipam_subnet,
            cidr, self._tenant_id, subnet['gateway_ip'],
            [netaddr.IPRange('10.0.0.2', '10.0.0.254')])

    def test_get_non_existing_subnet_fails(self):
        self.assertRaises(n_exc.SubnetNotFound,
                          self.ipam_pool.get_subnet,
                          'boo')

    def test_remove_ipam_subnet(self):
        cidr = '10.0.0.0/24'
        subnet, subnet_req = self._prepare_specific_subnet_request(cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        # Remove ipam subnet by neutron subnet id
        self.ipam_pool.remove_subnet(subnet['id'])

    def test_remove_non_existent_subnet_fails(self):
        self.assertRaises(n_exc.SubnetNotFound,
                          self.ipam_pool.remove_subnet,
                          'non-existent-id')

    def test_get_details_for_invalid_subnet_id_fails(self):
        cidr = '10.0.0.0/24'
        non_existent_id = uuidutils.generate_uuid()
        subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            non_existent_id,
            cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        # Neutron subnet does not exist, so get_subnet should fail
        self.assertRaises(n_exc.SubnetNotFound,
                          self.ipam_pool.get_subnet,
                          'non-existent-id')


class TestNeutronDbIpamSubnet(testlib_api.SqlTestCase,
                              TestNeutronDbIpamMixin):
    """Test case for Subnet interface for Neutron's DB IPAM driver.

    This test case exercises the reference IPAM driver.
    Even if it loads a plugin, the unit tests in this class do not exercise
    it at all; they simply perform white box testing on the IPAM driver.
    The plugin is exclusively used to create the neutron objects on which
    the IPAM driver will operate.
    """

    def _create_and_allocate_ipam_subnet(
            self, cidr, allocation_pools=constants.ATTR_NOT_SPECIFIED,
            ip_version=constants.IP_VERSION_4, v6_auto_address=False,
            tenant_id=None):
        v6_address_mode = constants.ATTR_NOT_SPECIFIED
        if v6_auto_address:
            # set ip version to 6 regardless of what's been passed to the
            # method
            ip_version = constants.IP_VERSION_6
            v6_address_mode = constants.IPV6_SLAAC
        subnet = self._create_subnet(
            self.plugin, self.ctx, self.net_id, cidr,
            ip_version=ip_version,
            allocation_pools=allocation_pools,
            v6_address_mode=v6_address_mode)
        # Build netaddr.IPRanges from allocation pools since IPAM SubnetRequest
        # objects are strongly typed
        allocation_pool_ranges = [netaddr.IPRange(
            pool['start'], pool['end']) for pool in
            subnet['allocation_pools']]
        subnet_req = ipam_req.SpecificSubnetRequest(
            tenant_id,
            subnet['id'],
            cidr,
            gateway_ip=subnet['gateway_ip'],
            allocation_pools=allocation_pool_ranges)
        ipam_subnet = self.ipam_pool.allocate_subnet(subnet_req)
        return ipam_subnet, subnet

    def setUp(self):
        super(TestNeutronDbIpamSubnet, self).setUp()
        self._tenant_id = 'test-tenant'

        # Configure plugin for tests
        self.setup_coreplugin(test_db_plugin.DB_PLUGIN_KLASS)

        # Prepare environment for tests
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.network, self.net_id = self._create_network(self.plugin,
                                                         self.ctx)

        # Allocate IPAM driver
        self.ipam_pool = driver.NeutronDbPool(None, self.ctx)

    def test__verify_ip_succeeds(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        ipam_subnet._verify_ip(self.ctx, '10.0.0.2')

    def test__verify_ip_not_in_subnet_fails(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx,
                          '192.168.0.2')

    def test__verify_ip_bcast_and_network_fail(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx,
                          '10.0.0.255')
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx,
                          '10.0.0.0')

    def _allocate_address(self, cidr, ip_version, address_request):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            cidr, ip_version=ip_version)[0]
        return ipam_subnet.allocate(address_request)

    def test_allocate_any_v4_address_succeeds(self):
        self._test_allocate_any_address_succeeds('10.0.0.0/24', 4)

    def test_allocate_any_v6_address_succeeds(self):
        self._test_allocate_any_address_succeeds('fde3:abcd:4321:1::/64', 6)

    def _test_allocate_any_address_succeeds(self, subnet_cidr, ip_version):
        ip_address = self._allocate_address(
            subnet_cidr, ip_version, ipam_req.AnyAddressRequest)
        self.assertIn(netaddr.IPAddress(ip_address),
                      netaddr.IPSet(netaddr.IPNetwork(subnet_cidr)))

    def test_allocate_specific_v4_address_succeeds(self):
        ip_address = self._allocate_address(
            '10.0.0.0/24', 4, ipam_req.SpecificAddressRequest('10.0.0.33'))
        self.assertEqual('10.0.0.33', ip_address)

    def test_allocate_specific_v6_address_succeeds(self):
        ip_address = self._allocate_address(
            'fde3:abcd:4321:1::/64', 6,
            ipam_req.SpecificAddressRequest('fde3:abcd:4321:1::33'))
        self.assertEqual('fde3:abcd:4321:1::33', ip_address)

    def test_allocate_specific_v4_address_out_of_range_fails(self):
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          self._allocate_address,
                          '10.0.0.0/24', 4,
                          ipam_req.SpecificAddressRequest('192.168.0.1'))

    def test_allocate_specific_v6_address_out_of_range_fails(self):
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          self._allocate_address,
                          'fde3:abcd:4321:1::/64', 6,
                          ipam_req.SpecificAddressRequest(
                              'fde3:abcd:eeee:1::33'))

    def test_allocate_specific_address_in_use_fails(self):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            'fde3:abcd:4321:1::/64', ip_version=constants.IP_VERSION_6)[0]
        addr_req = ipam_req.SpecificAddressRequest('fde3:abcd:4321:1::33')
        ipam_subnet.allocate(addr_req)
        self.assertRaises(ipam_exc.IpAddressAlreadyAllocated,
                          ipam_subnet.allocate,
                          addr_req)

    def test_allocate_any_address_exhausted_pools_fails(self):
        # Same as above, the ranges will be recalculated always
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '192.168.0.0/30', ip_version=constants.IP_VERSION_4)[0]
        ipam_subnet.allocate(ipam_req.AnyAddressRequest)
        # The second address generation request on a /30 for v4 net must fail
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.allocate,
                          ipam_req.AnyAddressRequest)

    def test_bulk_allocate_v4_address(self):
        target_ip_count = 10
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '192.168.0.0/28', ip_version=constants.IP_VERSION_4)[0]
        ip_addresses = ipam_subnet.bulk_allocate(
                ipam_req.BulkAddressRequest(target_ip_count))
        self.assertEqual(target_ip_count, len(ip_addresses))
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.bulk_allocate,
                          ipam_req.BulkAddressRequest(target_ip_count))

    def test_bulk_allocate_v6_address(self):
        target_ip_count = 10
        ipam_subnet = self._create_and_allocate_ipam_subnet(
                'fd00::/124', ip_version=constants.IP_VERSION_6)[0]
        ip_addresses = ipam_subnet.bulk_allocate(
                ipam_req.BulkAddressRequest(target_ip_count))
        self.assertEqual(target_ip_count, len(ip_addresses))
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.bulk_allocate,
                          ipam_req.BulkAddressRequest(target_ip_count))

    def test_bulk_allocate_multiple_address_pools(self):
        target_ip_count = 10
        # 11 addresses available
        allocation_pools = [{'start': '192.168.0.5', 'end': '192.168.0.9'},
                            {'start': '192.168.0.15', 'end': '192.168.0.20'}]
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '192.168.0.0/24', allocation_pools=allocation_pools,
            ip_version=constants.IP_VERSION_4)[0]
        ip_addresses = ipam_subnet.bulk_allocate(
            ipam_req.BulkAddressRequest(target_ip_count))
        self.assertEqual(target_ip_count, len(ip_addresses))
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.bulk_allocate,
                          ipam_req.BulkAddressRequest(2))

    def test_prefernext_allocate_multiple_address_pools(self):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '192.168.0.0/30', ip_version=constants.IP_VERSION_4)[0]

        ipam_subnet.allocate(ipam_req.PreferNextAddressRequest())
        # The second address generation request on a /30 for v4 net must fail
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.allocate,
                          ipam_req.PreferNextAddressRequest)

    def _test_deallocate_address(self, cidr, ip_version):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            cidr, ip_version=ip_version)[0]
        ip_address = ipam_subnet.allocate(ipam_req.AnyAddressRequest)
        ipam_subnet.deallocate(ip_address)

    def test_deallocate_v4_address(self):
        self._test_deallocate_address('10.0.0.0/24', 4)

    def test_deallocate_v6_address(self):
        # This test does not really exercise any different code path wrt
        # test_deallocate_v4_address. It is provided for completeness and for
        # future proofing in case v6-specific logic will be added.
        self._test_deallocate_address('fde3:abcd:4321:1::/64', 6)

    def test_allocate_all_pool_addresses_triggers_range_recalculation(self):
        # This test instead might be made to pass, but for the wrong reasons!
        pass

    def test_allocate_subnet_for_non_existent_subnet_pass(self):
        # This test should pass because ipam subnet is no longer
        # have foreign key relationship with neutron subnet.
        # Creating ipam subnet before neutron subnet is a valid case.
        tenant_id = uuidutils.generate_uuid()
        subnet_id = uuidutils.generate_uuid()
        subnet_req = ipam_req.SpecificSubnetRequest(
            tenant_id, subnet_id, '192.168.0.0/24')
        self.ipam_pool.allocate_subnet(subnet_req)

    def test_update_allocation_pools_with_no_pool_change(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            cidr)[0]
        ipam_subnet.subnet_manager.delete_allocation_pools = mock.Mock()
        ipam_subnet.create_allocation_pools = mock.Mock()
        alloc_pools = [netaddr.IPRange('10.0.0.2', '10.0.0.254')]
        # Make sure allocation pools recreation does not happen in case of
        # unchanged allocation pools
        ipam_subnet.update_allocation_pools(alloc_pools, cidr)
        self.assertFalse(
            ipam_subnet.subnet_manager.delete_allocation_pools.called)
        self.assertFalse(ipam_subnet.create_allocation_pools.called)

    def _test__no_pool_changes(self, new_pools):
        id = uuidutils.generate_uuid()
        ipam_subnet = driver.NeutronDbSubnet(id, self.ctx)
        pools = [ipam_obj.IpamAllocationPool(self.ctx,
                                             ipam_subnet_id=id,
                                             first_ip='192.168.10.20',
                                             last_ip='192.168.10.41'),
                 ipam_obj.IpamAllocationPool(self.ctx,
                                             ipam_subnet_id=id,
                                             first_ip='192.168.10.50',
                                             last_ip='192.168.10.60')]

        ipam_subnet.subnet_manager.list_pools = mock.Mock(return_value=pools)
        return ipam_subnet._no_pool_changes(self.ctx, new_pools)

    def test__no_pool_changes_negative(self):
        pool_list = [[netaddr.IPRange('192.168.10.2', '192.168.10.254')],
                     [netaddr.IPRange('192.168.10.20', '192.168.10.41')],
                     [netaddr.IPRange('192.168.10.20', '192.168.10.41'),
                      netaddr.IPRange('192.168.10.51', '192.168.10.60')]]
        for pools in pool_list:
            self.assertFalse(self._test__no_pool_changes(pools))

    def test__no_pool_changes_positive(self):
        pools = [netaddr.IPRange('192.168.10.20', '192.168.10.41'),
                 netaddr.IPRange('192.168.10.50', '192.168.10.60')]
        self.assertTrue(self._test__no_pool_changes(pools))
