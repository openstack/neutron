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

import netaddr

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.ipam.drivers.neutrondb_ipam import driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron import manager

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

    def _create_subnet(self, plugin, ctx, network_id, cidr, ip_version=4,
                       v6_address_mode=attributes.ATTR_NOT_SPECIFIED,
                       allocation_pools=attributes.ATTR_NOT_SPECIFIED):
        subnet = {'subnet': {'name': 'sub',
                             'cidr': cidr,
                             'ip_version': ip_version,
                             'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                             'allocation_pools': allocation_pools,
                             'enable_dhcp': True,
                             'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                             'host_routes': attributes.ATTR_NOT_SPECIFIED,
                             'ipv6_address_mode': v6_address_mode,
                             'ipv6_ra_mode': attributes.ATTR_NOT_SPECIFIED,
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
        self.plugin = manager.NeutronManager.get_plugin()
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

    def test_update_subnet_pools(self):
        cidr = '10.0.0.0/24'
        subnet, subnet_req = self._prepare_specific_subnet_request(cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        allocation_pools = [netaddr.IPRange('10.0.0.100', '10.0.0.150'),
                            netaddr.IPRange('10.0.0.200', '10.0.0.250')]
        update_subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            subnet['id'],
            cidr,
            gateway_ip=subnet['gateway_ip'],
            allocation_pools=allocation_pools)
        ipam_subnet = self.ipam_pool.update_subnet(update_subnet_req)
        self._verify_ipam_subnet_details(
            ipam_subnet,
            cidr, self._tenant_id, subnet['gateway_ip'], allocation_pools)

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
        subnet_req = ipam_req.SpecificSubnetRequest(
            self._tenant_id,
            'non-existent-id',
            cidr)
        self.ipam_pool.allocate_subnet(subnet_req)
        # Neutron subnet does not exist, so get_subnet should fail
        self.assertRaises(n_exc.SubnetNotFound,
                          self.ipam_pool.get_subnet,
                          'non-existent-id')


class TestNeutronDbIpamSubnet(testlib_api.SqlTestCase,
                              TestNeutronDbIpamMixin):
    """Test case for Subnet interface for Nuetron's DB IPAM driver.

    This test case exercises the reference IPAM driver.
    Even if it loads a plugin, the unit tests in this class do not exercise
    it at all; they simply perform white box testing on the IPAM driver.
    The plugin is exclusively used to create the neutron objects on which
    the IPAM driver will operate.
    """

    def _create_and_allocate_ipam_subnet(
        self, cidr, allocation_pools=attributes.ATTR_NOT_SPECIFIED,
        ip_version=4, v6_auto_address=False, tenant_id=None):
        v6_address_mode = attributes.ATTR_NOT_SPECIFIED
        if v6_auto_address:
            # set ip version to 6 regardless of what's been passed to the
            # method
            ip_version = 6
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
        self.plugin = manager.NeutronManager.get_plugin()
        self.ctx = context.get_admin_context()
        self.network, self.net_id = self._create_network(self.plugin,
                                                         self.ctx)

        # Allocate IPAM driver
        self.ipam_pool = driver.NeutronDbPool(None, self.ctx)

    def test__verify_ip_succeeds(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        ipam_subnet._verify_ip(self.ctx.session, '10.0.0.2')

    def test__verify_ip_not_in_subnet_fails(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx.session,
                          '192.168.0.2')

    def test__verify_ip_bcast_and_network_fail(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx.session,
                          '10.0.0.255')
        self.assertRaises(ipam_exc.InvalidIpForSubnet,
                          ipam_subnet._verify_ip,
                          self.ctx.session,
                          '10.0.0.0')

    def test__allocate_specific_ip(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(cidr)[0]
        with self.ctx.session.begin():
            ranges = ipam_subnet._allocate_specific_ip(
                self.ctx.session, '10.0.0.33')
        self.assertEqual(2, len(ranges))
        # 10.0.0.1 should be allocated for gateway ip
        ranges.sort(key=convert_firstip_to_ipaddress)
        self.assertEqual('10.0.0.2', ranges[0]['first_ip'])
        self.assertEqual('10.0.0.32', ranges[0]['last_ip'])
        self.assertEqual('10.0.0.34', ranges[1]['first_ip'])
        self.assertEqual('10.0.0.254', ranges[1]['last_ip'])
        # Limit test - first address in range
        ranges = ipam_subnet._allocate_specific_ip(
            self.ctx.session, '10.0.0.2')
        self.assertEqual(2, len(ranges))
        ranges.sort(key=convert_firstip_to_ipaddress)
        self.assertEqual('10.0.0.3', ranges[0]['first_ip'])
        self.assertEqual('10.0.0.32', ranges[0]['last_ip'])
        self.assertEqual('10.0.0.34', ranges[1]['first_ip'])
        self.assertEqual('10.0.0.254', ranges[1]['last_ip'])
        # Limit test - last address in range
        ranges = ipam_subnet._allocate_specific_ip(
            self.ctx.session, '10.0.0.254')
        self.assertEqual(2, len(ranges))
        ranges.sort(key=convert_firstip_to_ipaddress)
        self.assertEqual('10.0.0.3', ranges[0]['first_ip'])
        self.assertEqual('10.0.0.32', ranges[0]['last_ip'])
        self.assertEqual('10.0.0.34', ranges[1]['first_ip'])
        self.assertEqual('10.0.0.253', ranges[1]['last_ip'])

    def test__allocate_specific_ips_multiple_ranges(self):
        cidr = '10.0.0.0/24'
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            cidr,
            allocation_pools=[{'start': '10.0.0.10', 'end': '10.0.0.19'},
                              {'start': '10.0.0.30', 'end': '10.0.0.39'}])[0]
        with self.ctx.session.begin():
            ranges = ipam_subnet._allocate_specific_ip(
                self.ctx.session, '10.0.0.33')
        self.assertEqual(3, len(ranges))
        # 10.0.0.1 should be allocated for gateway ip
        ranges.sort(key=convert_firstip_to_ipaddress)
        self.assertEqual('10.0.0.10', ranges[0]['first_ip'])
        self.assertEqual('10.0.0.19', ranges[0]['last_ip'])
        self.assertEqual('10.0.0.30', ranges[1]['first_ip'])
        self.assertEqual('10.0.0.32', ranges[1]['last_ip'])
        self.assertEqual('10.0.0.34', ranges[2]['first_ip'])
        self.assertEqual('10.0.0.39', ranges[2]['last_ip'])

    def test__allocate_specific_ip_out_of_range(self):
        cidr = '10.0.0.0/24'
        subnet = self._create_subnet(
            self.plugin, self.ctx, self.net_id, cidr)
        subnet_req = ipam_req.SpecificSubnetRequest(
            'tenant_id', subnet['id'], cidr, gateway_ip=subnet['gateway_ip'])
        ipam_subnet = self.ipam_pool.allocate_subnet(subnet_req)
        with self.ctx.session.begin():
            ranges = ipam_subnet._allocate_specific_ip(
                self.ctx.session, '192.168.0.1')
        # In this case _allocate_specific_ips does not fail, but
        # simply does not update availability ranges at all
        self.assertEqual(1, len(ranges))
        # 10.0.0.1 should be allocated for gateway ip
        ranges.sort(key=convert_firstip_to_ipaddress)
        self.assertEqual('10.0.0.2', ranges[0]['first_ip'])
        self.assertEqual('10.0.0.254', ranges[0]['last_ip'])

    def _allocate_address(self, cidr, ip_version, address_request):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            cidr, ip_version=ip_version)[0]
        return ipam_subnet.allocate(address_request)

    def test_allocate_any_v4_address_succeeds(self):
        ip_address = self._allocate_address(
            '10.0.0.0/24', 4, ipam_req.AnyAddressRequest)
        # As the DB IPAM driver allocation logic is strictly sequential, we can
        # expect this test to allocate the .2 address as .1 is used by default
        # as subnet gateway
        self.assertEqual('10.0.0.2', ip_address)

    def test_allocate_any_v6_address_succeeds(self):
        ip_address = self._allocate_address(
            'fde3:abcd:4321:1::/64', 6, ipam_req.AnyAddressRequest)
        # As the DB IPAM driver allocation logic is strictly sequential, we can
        # expect this test to allocate the .2 address as .1 is used by default
        # as subnet gateway
        self.assertEqual('fde3:abcd:4321:1::2', ip_address)

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
            'fde3:abcd:4321:1::/64', ip_version=6)[0]
        addr_req = ipam_req.SpecificAddressRequest('fde3:abcd:4321:1::33')
        ipam_subnet.allocate(addr_req)
        self.assertRaises(ipam_exc.IpAddressAlreadyAllocated,
                          ipam_subnet.allocate,
                          addr_req)

    def test_allocate_any_address_exhausted_pools_fails(self):
        # Same as above, the ranges will be recalculated always
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '192.168.0.0/30', ip_version=4)[0]
        ipam_subnet.allocate(ipam_req.AnyAddressRequest)
        # The second address generation request on a /30 for v4 net must fail
        self.assertRaises(ipam_exc.IpAddressGenerationFailure,
                          ipam_subnet.allocate,
                          ipam_req.AnyAddressRequest)

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

    def test_allocate_unallocated_address_fails(self):
        ipam_subnet = self._create_and_allocate_ipam_subnet(
            '10.0.0.0/24', ip_version=4)[0]
        self.assertRaises(ipam_exc.IpAddressAllocationNotFound,
                          ipam_subnet.deallocate, '10.0.0.2')

    def test_allocate_all_pool_addresses_triggers_range_recalculation(self):
        # This test instead might be made to pass, but for the wrong reasons!
        pass

    def test_allocate_subnet_for_non_existent_subnet_pass(self):
        # This test should pass because ipam subnet is no longer
        # have foreign key relationship with neutron subnet.
        # Creating ipam subnet before neutron subnet is a valid case.
        subnet_req = ipam_req.SpecificSubnetRequest(
            'tenant_id', 'meh', '192.168.0.0/24')
        self.ipam_pool.allocate_subnet(subnet_req)
