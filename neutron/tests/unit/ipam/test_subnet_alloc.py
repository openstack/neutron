# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# All rights reserved.
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
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils

from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit import testlib_api


class TestSubnetAllocation(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestSubnetAllocation, self).setUp()
        self._tenant_id = 'test-tenant'
        self.setup_coreplugin(test_db_base_plugin_v2.DB_PLUGIN_KLASS)
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        cfg.CONF.set_override('allow_overlapping_ips', True)

    def _create_subnet_pool(self, plugin, ctx, name, prefix_list,
                            min_prefixlen, ip_version,
                            max_prefixlen=constants.ATTR_NOT_SPECIFIED,
                            default_prefixlen=constants.ATTR_NOT_SPECIFIED,
                            default_quota=constants.ATTR_NOT_SPECIFIED,
                            shared=False, is_default=False):
        subnetpool = {'subnetpool': {'name': name,
                                     'tenant_id': self._tenant_id,
                                     'prefixes': prefix_list,
                                     'min_prefixlen': min_prefixlen,
                                     'max_prefixlen': max_prefixlen,
                                     'default_prefixlen': default_prefixlen,
                                     'shared': shared,
                                     'is_default': is_default,
                                     'default_quota': default_quota}}
        return plugin.create_subnetpool(ctx, subnetpool)

    def _get_subnetpool(self, ctx, plugin, id):
        return plugin.get_subnetpool(ctx, id)

    def test_allocate_any_subnet(self):
        prefix_list = ['10.1.0.0/16', '192.168.1.0/24']
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      prefix_list, 21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
            req = ipam_req.AnySubnetRequest(self._tenant_id,
                                        uuidutils.generate_uuid(),
                                        constants.IPv4, 21)
            res = sa.allocate_subnet(req)
            detail = res.get_details()
            prefix_set = netaddr.IPSet(iterable=prefix_list)
            allocated_set = netaddr.IPSet(iterable=[detail.subnet_cidr])
            self.assertTrue(allocated_set.issubset(prefix_set))
            self.assertEqual(21, detail.prefixlen)

    def test_allocate_specific_subnet(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
            sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
            req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                             uuidutils.generate_uuid(),
                                             '10.1.2.0/24')
            res = sa.allocate_subnet(req)
            detail = res.get_details()
            sp = self._get_subnetpool(self.ctx, self.plugin, sp['id'])
            self.assertEqual('10.1.2.0/24', str(detail.subnet_cidr))
            self.assertEqual(24, detail.prefixlen)

    def test_insufficient_prefix_space_for_any_allocation(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.1.0/24', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
        req = ipam_req.AnySubnetRequest(self._tenant_id,
                                    uuidutils.generate_uuid(),
                                    constants.IPv4,
                                    21)
        self.assertRaises(exceptions.SubnetAllocationError,
                          sa.allocate_subnet, req)

    def test_insufficient_prefix_space_for_specific_allocation(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
        req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                         uuidutils.generate_uuid(),
                                         '10.1.0.0/21')
        self.assertRaises(exceptions.SubnetAllocationError,
                          sa.allocate_subnet, req)

    def test_allocate_any_subnet_gateway(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
            req = ipam_req.AnySubnetRequest(self._tenant_id,
                                        uuidutils.generate_uuid(),
                                        constants.IPv4, 21)
            res = sa.allocate_subnet(req)
            detail = res.get_details()
            self.assertEqual(detail.gateway_ip,
                             detail.subnet_cidr.network + 1)

    def test_allocate_specific_subnet_specific_gateway(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
            req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                             uuidutils.generate_uuid(),
                                             '10.1.2.0/24',
                                             gateway_ip='10.1.2.254')
            res = sa.allocate_subnet(req)
            detail = res.get_details()
            self.assertEqual(netaddr.IPAddress('10.1.2.254'),
                             detail.gateway_ip)

    def test_allocate_specific_ipv6_subnet_specific_gateway(self):
        # Same scenario as described in bug #1466322
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['2210::/64'],
                                      64, 6)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
            req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                                 uuidutils.generate_uuid(),
                                                 '2210::/64',
                                                 '2210::ffff:ffff:ffff:ffff')
            res = sa.allocate_subnet(req)
            detail = res.get_details()
            self.assertEqual(netaddr.IPAddress('2210::ffff:ffff:ffff:ffff'),
                             detail.gateway_ip)

    def test__allocation_value_for_tenant_no_allocations(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
        value = sa._allocations_used_by_tenant(32)
        self.assertEqual(0, value)

    def test_subnetpool_default_quota_exceeded(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['fe80::/48'],
                                      48, 6, default_quota=1)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
        req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                         uuidutils.generate_uuid(),
                                         'fe80::/63')
        self.assertRaises(exceptions.SubnetPoolQuotaExceeded,
                          sa.allocate_subnet,
                          req)

    def test_subnetpool_concurrent_allocation_exception(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['fe80::/48'],
                                      48, 6, default_quota=1)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp, self.ctx)
        req = ipam_req.SpecificSubnetRequest(self._tenant_id,
                                         uuidutils.generate_uuid(),
                                         'fe80::/63')
        with mock.patch("sqlalchemy.orm.query.Query.update", return_value=0):
            self.assertRaises(db_exc.RetryRequest, sa.allocate_subnet, req)
