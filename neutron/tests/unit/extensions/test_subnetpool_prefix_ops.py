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
import webob.exc

from neutron.objects import subnetpool as subnetpool_obj
from neutron.tests.unit.plugins.ml2 import test_plugin

_uuid = uuidutils.generate_uuid


class SubnetpoolPrefixOpsTestBase:

    @contextlib.contextmanager
    def address_scope(self, ip_version, prefixes=None, shared=False,
                      admin=True, name='test-scope', is_default_pool=False,
                      project_id=None, **kwargs):
        tenant_id = project_id if project_id else kwargs.get(
            'tenant_id', None)
        if not tenant_id:
            tenant_id = self._tenant_id

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
            tenant_id = self._tenant_id
        pool_data = {'tenant_id': tenant_id, 'shared': shared, 'name': name,
                     'address_scope_id': address_scope_id,
                     'prefixes': prefixes, 'is_default': is_default_pool}
        for key in kwargs:
            pool_data[key] = kwargs[key]

        with db_api.CONTEXT_WRITER.using(self.context):
            yield self.driver.create_subnetpool(self.context,
                                                {'subnetpool': pool_data})

    def _make_request_payload(self, prefixes):
        return {'prefixes': prefixes}

    def test_add_prefix_no_address_scope(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self.driver.add_prefixes(
                self.context,
                subnetpool['id'],
                self._make_request_payload([self.cidr_to_add]))
            self._validate_prefix_list(subnetpool['id'],
                                       [self.cidr_to_add])

    def test_add_prefix_invalid_request_body_structure(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(webob.exc.HTTPBadRequest,
                              self.driver.add_prefixes,
                              self.context,
                              subnetpool['id'],
                              [self.cidr_to_add])

    def test_add_prefix_invalid_request_data(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(webob.exc.HTTPBadRequest,
                              self.driver.add_prefixes,
                              self.context,
                              subnetpool['id'],
                              ['not a CIDR'])

    def test_add_prefix_no_address_scope_overlapping_cidr(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            prefixes_to_add = [self.cidr_to_add, self.overlapping_cidr]
            self.driver.add_prefixes(
                self.context,
                subnetpool['id'],
                self._make_request_payload([self.cidr_to_add]))
            self._validate_prefix_list(subnetpool['id'], prefixes_to_add)

    def test_add_prefix_with_address_scope_overlapping_cidr(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(
                    self.ip_version,
                    prefixes=[self.subnetpool_prefixes[0]],
                    address_scope_id=addr_scope['id']) as sp_to_augment,\
                self.subnetpool(self.ip_version,
                                prefixes=[self.subnetpool_prefixes[1]],
                                address_scope_id=addr_scope['id']):
                prefixes_to_add = [self.cidr_to_add]
                self.driver.add_prefixes(
                    self.context,
                    sp_to_augment['id'],
                    self._make_request_payload([self.cidr_to_add]))
                self._validate_prefix_list(sp_to_augment['id'],
                                           prefixes_to_add)

    def test_add_prefix_with_address_scope(self):
        with self.address_scope(self.ip_version) as addr_scope:
            with self.subnetpool(
                    self.ip_version,
                    prefixes=[self.subnetpool_prefixes[1]],
                    address_scope_id=addr_scope['id']) as sp_to_augment,\
                self.subnetpool(self.ip_version,
                                prefixes=[self.subnetpool_prefixes[0]],
                                address_scope_id=addr_scope['id']):
                prefixes_to_add = [self.overlapping_cidr]
                self.assertRaises(exc.AddressScopePrefixConflict,
                                  self.driver.add_prefixes,
                                  self.context,
                                  sp_to_augment['id'],
                                  self._make_request_payload(prefixes_to_add))

    def test_remove_prefix(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            prefixes_to_remove = [self.subnetpool_prefixes[0]]
            self.driver.remove_prefixes(
                self.context,
                subnetpool['id'],
                self._make_request_payload(prefixes_to_remove))
            self._validate_prefix_list(subnetpool['id'],
                                       [self.subnetpool_prefixes[1]],
                                       excluded_prefixes=prefixes_to_remove)

    def test_remove_prefix_invalid_request_body_structure(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(webob.exc.HTTPBadRequest,
                              self.driver.remove_prefixes,
                              self.context,
                              subnetpool['id'],
                              [self.subnetpool_prefixes[0]])

    def test_remove_prefix_invalid_request_data(self):
        with self.subnetpool(self.ip_version,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            self.assertRaises(webob.exc.HTTPBadRequest,
                              self.driver.remove_prefixes,
                              self.context,
                              subnetpool['id'],
                              ['not a CIDR'])

    def test_remove_prefix_with_allocated_subnet(self):
        with self.subnetpool(self.ip_version,
                             default_prefixlen=self.default_prefixlen,
                             min_prefixlen=self.default_prefixlen,
                             prefixes=self.subnetpool_prefixes) as subnetpool:
            with self.subnet(cidr=None, subnetpool_id=subnetpool['id'],
                             ip_version=self.ip_version) as subnet:
                subnet = subnet['subnet']
                prefixes_to_remove = [subnet['cidr']]
                self.assertRaises(
                    exc.IllegalSubnetPoolPrefixUpdate,
                    self.driver.remove_prefixes,
                    self.context,
                    subnetpool['id'],
                    self._make_request_payload(prefixes_to_remove))

    def test_remove_overlapping_prefix_with_allocated_subnet(self):
        with self.subnetpool(
                        self.ip_version,
                        default_prefixlen=self.default_prefixlen,
                        min_prefixlen=self.default_prefixlen,
                        prefixes=[self.subnetpool_prefixes[0]]) as subnetpool:
            with self.subnet(cidr=None, subnetpool_id=subnetpool['id'],
                             ip_version=self.ip_version) as subnet:
                subnet = subnet['subnet']
                prefixes_to_remove = [self.overlapping_cidr]
                self.assertRaises(
                    exc.IllegalSubnetPoolPrefixUpdate,
                    self.driver.remove_prefixes,
                    self.context,
                    subnetpool['id'],
                    self._make_request_payload(prefixes_to_remove))

    def _validate_prefix_list(self, subnetpool_id, expected_prefixes,
                              excluded_prefixes=None):
        if not excluded_prefixes:
            excluded_prefixes = []

        subnetpool = subnetpool_obj.SubnetPool.get_object(
                                                 self.context,
                                                 id=subnetpool_id)
        current_prefix_set = netaddr.IPSet(list(subnetpool.prefixes))
        expected_prefix_set = netaddr.IPSet(expected_prefixes)
        excluded_prefix_set = netaddr.IPSet(excluded_prefixes)
        self.assertTrue(expected_prefix_set.issubset(current_prefix_set))
        self.assertTrue(excluded_prefix_set.isdisjoint(current_prefix_set))


class SubnetpoolPrefixOpsTestsIpv4(SubnetpoolPrefixOpsTestBase,
                                   test_plugin.Ml2PluginV2TestCase):

    subnetpool_prefixes = ["192.168.1.0/24", "192.168.2.0/24"]
    cidr_to_add = "10.0.0.0/24"
    overlapping_cidr = "192.168.1.128/25"
    default_prefixlen = 24
    ip_version = 4


class SubnetpoolPrefixOpsTestsIpv6(SubnetpoolPrefixOpsTestBase,
                                   test_plugin.Ml2PluginV2TestCase):

    subnetpool_prefixes = ["2001:db8:1234::/48",
                           "2001:db8:1235::/48"]
    cidr_to_add = "2001:db8:4321::/48"
    overlapping_cidr = "2001:db8:1234:1111::/64"
    default_prefixlen = 48
    ip_version = 6
