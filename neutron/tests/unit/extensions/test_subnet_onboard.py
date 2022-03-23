# (c) Copyright 2019 SUSE LLC
#
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

import contextlib

import netaddr
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from oslo_utils import uuidutils

from neutron.objects import subnet as subnet_obj
from neutron.objects import subnetpool as subnetpool_obj
from neutron.tests.unit.plugins.ml2 import test_plugin

_uuid = uuidutils.generate_uuid


class SubnetOnboardTestsBase(object):

    @contextlib.contextmanager
    def address_scope(self, ip_version, prefixes=None, shared=False,
                      admin=True, name='test-scope', is_default_pool=False,
                      project_id=None, **kwargs):
        tenant_id = project_id if project_id else kwargs.get(
            'tenant_id', None)
        if not tenant_id:
            tenant_id = _uuid()

        scope_data = {'tenant_id': tenant_id, 'ip_version': ip_version,
                      'shared': shared, 'name': name + '-scope'}
        with db_api.CONTEXT_WRITER.using(self.context):
            yield self.driver.create_address_scope(
                self.context,
                {'address_scope': scope_data})

    @contextlib.contextmanager
    def subnetpool(self, ip_version, prefixes=None, shared=False, admin=True,
                   name='test-pool', is_default_pool=False, project_id=None,
                   address_scope_id=None, **kwargs):
        tenant_id = project_id if project_id else kwargs.get(
            'tenant_id', None)
        if not tenant_id:
            tenant_id = _uuid()
        pool_data = {'tenant_id': tenant_id, 'shared': shared, 'name': name,
                     'address_scope_id': address_scope_id,
                     'prefixes': prefixes, 'is_default': is_default_pool}
        for key in kwargs:
            pool_data[key] = kwargs[key]

        with db_api.CONTEXT_WRITER.using(self.context):
            yield self.driver.create_subnetpool(self.context,
                                                {'subnetpool': pool_data})

    def test_onboard_subnet_no_address_scope(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self._test_onboard_cidr(subnetpool['id'], self.cidr_to_onboard)

    def test_onboard_subnet_address_scope(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes,
                             address_scope_id=addr_scope['id']) as subnetpool:
                self._test_onboard_cidr(subnetpool['id'], self.cidr_to_onboard)

    def test_onboard_subnet_overlapping_cidr_no_address_scope(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            with self.subnet(cidr=self.overlapping_cidr,
                             subnetpool_id=subnetpool['id'],
                             ip_version=self.ip_version):
                self.assertRaises(exc.IllegalSubnetPoolUpdate,
                                  self._test_onboard_cidr,
                                  subnetpool['id'],
                                  self.overlapping_cidr)

    def test_onboard_subnet_address_scope_multiple_pools(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(self.ip_version,
                          prefixes=[self.subnetpool_prefixes[0]],
                          address_scope_id=addr_scope['id']) as onboard_pool,\
                self.subnetpool(self.ip_version,
                             prefixes=[self.subnetpool_prefixes[1]],
                             address_scope_id=addr_scope['id']):
                self._test_onboard_cidr(onboard_pool['id'],
                                        self.cidr_to_onboard)

    def test_onboard_subnet_address_scope_overlap_multiple_pools(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(self.ip_version,
                          prefixes=[self.subnetpool_prefixes[0]],
                          address_scope_id=addr_scope['id']) as onboard_pool,\
                self.subnetpool(self.ip_version,
                             prefixes=[self.subnetpool_prefixes[1]],
                             address_scope_id=addr_scope['id']) as other_pool:
                self.assertRaises(exc.AddressScopePrefixConflict,
                              self._test_onboard_cidr,
                              onboard_pool['id'],
                              other_pool['prefixes'][0])

    def test_onboard_subnet_move_between_pools_same_address_scope(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(self.ip_version,
                                 prefixes=[self.cidr_to_onboard],
                                 address_scope_id=addr_scope['id']) as source:
                with self.subnetpool(self.ip_version,
                        address_scope_id=addr_scope['id'],
                        prefixes=self.subnetpool_prefixes) as target:
                    with self.subnet(cidr=self.cidr_to_onboard,
                            ip_version=self.ip_version) as subnet_to_onboard:
                        subnet_to_onboard = subnet_to_onboard['subnet']

                        # Onboard subnet into an initial subnet pool
                        self._test_onboard_network_subnets(
                            subnet_to_onboard['network_id'], source['id'])
                        source_pool_subnets = subnet_obj.Subnet.get_objects(
                                                self.context,
                                                subnetpool_id=source['id'])
                        self.assertEqual(1, len(source_pool_subnets))

                        # Attempt to move the subnet to the target pool
                        self.assertRaises(exc.AddressScopePrefixConflict,
                              self._test_onboard_network_subnets,
                              subnet_to_onboard['network_id'], target['id'])

    def test_onboard_subnet_move_between_pools(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as source:
            with self.subnetpool(self.ip_version,
                                 prefixes=self.subnetpool_prefixes) as target:
                with self.subnet(cidr=self.cidr_to_onboard,
                        ip_version=self.ip_version) as subnet_to_onboard:
                    subnet_to_onboard = subnet_to_onboard['subnet']

                    # Onboard subnet into an initial subnet pool
                    self._test_onboard_network_subnets(
                        subnet_to_onboard['network_id'], source['id'])
                    source_pool_subnets = subnet_obj.Subnet.get_objects(
                                            self.context,
                                            subnetpool_id=source['id'])
                    self.assertEqual(1, len(source_pool_subnets))

                    # Attempt to onboard subnet into a different pool
                    self._test_onboard_network_subnets(
                        subnet_to_onboard['network_id'], target['id'])
                    source_pool_subnets = subnet_obj.Subnet.get_objects(
                                            self.context,
                                            subnetpool_id=source['id'])
                    target_pool_subnets = subnet_obj.Subnet.get_objects(
                                            self.context,
                                            subnetpool_id=target['id'])
                    source_subnetpool = subnetpool_obj.SubnetPool.get_object(
                                                             self.context,
                                                             id=source['id'])

                    # Assert that the subnet prefix has not been removed
                    # from the the source prefix list. The prefix should
                    # simply be released back to the pool, not removed.
                    self.assertIn(
                        netaddr.IPNetwork(self.cidr_to_onboard),
                        netaddr.IPSet(source_subnetpool['prefixes']))
                    # Assert the subnet is associated with the proper pool
                    self.assertEqual(0, len(source_pool_subnets))
                    self.assertEqual(1, len(target_pool_subnets))

    def test_onboard_subnet_invalid_request(self):
        with self.subnetpool(self.ip_version,
                prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(exc.InvalidInput,
                              self._test_onboard_subnet_no_network_id,
                              subnetpool['id'], self.cidr_to_onboard)

    def test_onboard_subnet_network_not_found(self):
        with self.subnetpool(self.ip_version,
                prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(exc.NetworkNotFound,
                              self._test_onboard_subnet_non_existing_network,
                              subnetpool['id'], self.cidr_to_onboard)

    def _test_onboard_subnet_no_network_id(self, subnetpool_id,
                                           cidr_to_onboard):
        with self.subnet(cidr=cidr_to_onboard,
                         ip_version=self.ip_version) as subnet_to_onboard:
            subnet_to_onboard = subnet_to_onboard['subnet']
            self.driver.onboard_network_subnets(
                self.context, subnetpool_id, {})

    def _test_onboard_subnet_non_existing_network(self, subnetpool_id,
                                                  cidr_to_onboard):
        with self.subnet(cidr=cidr_to_onboard,
                         ip_version=self.ip_version) as subnet_to_onboard:
            subnet_to_onboard = subnet_to_onboard['subnet']
            self.driver.onboard_network_subnets(
                self.context, subnetpool_id,
                {'network_id': _uuid()})

    def _test_onboard_network_subnets(self, network_id, subnetpool_id):
        response = self.driver.onboard_network_subnets(
                                                   self.context,
                                                   subnetpool_id,
                                                   {'network_id': network_id})
        subnetpool = subnetpool_obj.SubnetPool.get_object(self.context,
                                                          id=subnetpool_id)
        subnetpool_prefixes = netaddr.IPSet(subnetpool.prefixes)

        for onboarded_subnet in subnet_obj.Subnet.get_objects(
                                       self.context,
                                       ip_version=self.ip_version,
                                       network_id=network_id):
            onboarded_prefix = netaddr.IPNetwork(onboarded_subnet.cidr)
            self.assertIn({'id': onboarded_subnet.id,
                           'cidr': onboarded_subnet.cidr}, response)
            self.assertEqual(subnetpool_id,
                             onboarded_subnet.subnetpool_id)
            self.assertIn(onboarded_prefix, subnetpool_prefixes)

    def _test_onboard_cidr(self, subnetpool_id, cidr_to_onboard):
        with self.subnet(cidr=cidr_to_onboard,
                         ip_version=self.ip_version) as subnet_to_onboard:
            subnet_to_onboard = subnet_to_onboard['subnet']
            self._test_onboard_network_subnets(
                subnet_to_onboard['network_id'],
                subnetpool_id)


class SubnetOnboardTestsIpv4(SubnetOnboardTestsBase,
                             test_plugin.Ml2PluginV2TestCase):

    subnetpool_prefixes = ["192.168.1.0/24", "192.168.2.0/24"]
    cidr_to_onboard = "10.0.0.0/24"
    overlapping_cidr = "192.168.1.128/25"
    default_prefixlen = 24
    ip_version = 4


class SubnetOnboardTestsIpv6(SubnetOnboardTestsBase,
                             test_plugin.Ml2PluginV2TestCase):

    subnetpool_prefixes = ["2001:db8:1234::/48",
                           "2001:db8:1235::/48"]
    cidr_to_onboard = "2001:db8:4321::/48"
    overlapping_cidr = "2001:db8:1234:1111::/64"
    default_prefixlen = 64
    ip_version = 6
