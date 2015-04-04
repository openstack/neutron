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

import netaddr
from oslo_config import cfg

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
import neutron.ipam as ipam
from neutron.ipam import subnet_alloc
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit import testlib_api


class TestSubnetAllocation(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestSubnetAllocation, self).setUp()
        self._tenant_id = 'test-tenant'
        self.setup_coreplugin(test_db_base_plugin_v2.DB_PLUGIN_KLASS)
        self.plugin = manager.NeutronManager.get_plugin()
        self.ctx = context.get_admin_context()
        cfg.CONF.set_override('allow_overlapping_ips', True)

    def _create_subnet_pool(self, plugin, ctx, name, prefix_list,
                            min_prefixlen, ip_version,
                            max_prefixlen=attributes.ATTR_NOT_SPECIFIED,
                            default_prefixlen=attributes.ATTR_NOT_SPECIFIED,
                            default_quota=attributes.ATTR_NOT_SPECIFIED,
                            shared=False):
        subnetpool = {'subnetpool': {'name': name,
                                     'tenant_id': self._tenant_id,
                                     'prefixes': prefix_list,
                                     'min_prefixlen': min_prefixlen,
                                     'max_prefixlen': max_prefixlen,
                                     'default_prefixlen': default_prefixlen,
                                     'shared': shared,
                                     'default_quota': default_quota}}
        return plugin.create_subnetpool(ctx, subnetpool)

    def _get_subnetpool(self, ctx, plugin, id):
        return plugin.get_subnetpool(ctx, id)

    def test_allocate_any_subnet(self):
        prefix_list = ['10.1.0.0/16', '192.168.1.0/24']
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      prefix_list, 21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with self.ctx.session.begin(subtransactions=True):
            sa = subnet_alloc.SubnetAllocator(sp)
            req = ipam.AnySubnetRequest(self._tenant_id,
                                        uuidutils.generate_uuid(),
                                        constants.IPv4, 21)
            res = sa.allocate_subnet(self.ctx.session, req)
            detail = res.get_details()
            prefix_set = netaddr.IPSet(iterable=prefix_list)
            allocated_set = netaddr.IPSet(iterable=[detail.subnet.cidr])
            self.assertTrue(allocated_set.issubset(prefix_set))
            self.assertEqual(detail.prefixlen, 21)

    def test_allocate_specific_subnet(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        with self.ctx.session.begin(subtransactions=True):
            sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
            sa = subnet_alloc.SubnetAllocator(sp)
            req = ipam.SpecificSubnetRequest(self._tenant_id,
                                             uuidutils.generate_uuid(),
                                             '10.1.2.0/24')
            res = sa.allocate_subnet(self.ctx.session, req)
            detail = res.get_details()
            sp = self._get_subnetpool(self.ctx, self.plugin, sp['id'])
            self.assertEqual(str(detail.subnet.cidr), '10.1.2.0/24')
            self.assertEqual(detail.prefixlen, 24)

    def test_insufficient_prefix_space_for_any_allocation(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.1.0/24', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp)
        req = ipam.AnySubnetRequest(self._tenant_id,
                                    uuidutils.generate_uuid(),
                                    constants.IPv4,
                                    21)
        self.assertRaises(n_exc.SubnetAllocationError,
                          sa.allocate_subnet, self.ctx.session, req)

    def test_insufficient_prefix_space_for_specific_allocation(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp)
        req = ipam.SpecificSubnetRequest(self._tenant_id,
                                         uuidutils.generate_uuid(),
                                         '10.1.0.0/21')
        self.assertRaises(n_exc.SubnetAllocationError,
                          sa.allocate_subnet, self.ctx.session, req)

    def test_allocate_any_subnet_gateway(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with self.ctx.session.begin(subtransactions=True):
            sa = subnet_alloc.SubnetAllocator(sp)
            req = ipam.AnySubnetRequest(self._tenant_id,
                                        uuidutils.generate_uuid(),
                                        constants.IPv4, 21)
            res = sa.allocate_subnet(self.ctx.session, req)
            detail = res.get_details()
            self.assertEqual(detail.gateway_ip, detail.subnet.network + 1)

    def test_allocate_specific_subnet_specific_gateway(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        with self.ctx.session.begin(subtransactions=True):
            sa = subnet_alloc.SubnetAllocator(sp)
            req = ipam.SpecificSubnetRequest(self._tenant_id,
                                             uuidutils.generate_uuid(),
                                             '10.1.2.0/24',
                                             gateway_ip='10.1.2.254')
            res = sa.allocate_subnet(self.ctx.session, req)
            detail = res.get_details()
            self.assertEqual(detail.gateway_ip,
                             netaddr.IPAddress('10.1.2.254'))

    def test__allocation_value_for_tenant_no_allocations(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['10.1.0.0/16', '192.168.1.0/24'],
                                      21, 4)
        sa = subnet_alloc.SubnetAllocator(sp)
        value = sa._allocations_used_by_tenant(self.ctx.session, 32)
        self.assertEqual(value, 0)

    def test_subnetpool_default_quota_exceeded(self):
        sp = self._create_subnet_pool(self.plugin, self.ctx, 'test-sp',
                                      ['fe80::/48'],
                                      48, 6, default_quota=1)
        sp = self.plugin._get_subnetpool(self.ctx, sp['id'])
        sa = subnet_alloc.SubnetAllocator(sp)
        req = ipam.SpecificSubnetRequest(self._tenant_id,
                                         uuidutils.generate_uuid(),
                                         'fe80::/63')
        self.assertRaises(n_exc.SubnetPoolQuotaExceeded,
                          sa.allocate_subnet,
                          self.ctx.session,
                          req)
