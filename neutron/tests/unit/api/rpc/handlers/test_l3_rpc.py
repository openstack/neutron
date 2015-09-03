# Copyright (c) 2015 Cisco Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg

from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants
from neutron import context
from neutron import manager
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit import testlib_api


class TestL3RpcCallback(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestL3RpcCallback, self).setUp()
        self.setup_coreplugin(test_db_base_plugin_v2.DB_PLUGIN_KLASS)
        self.plugin = manager.NeutronManager.get_plugin()
        self.ctx = context.get_admin_context()
        cfg.CONF.set_override('default_ipv6_subnet_pool',
                              constants.IPV6_PD_POOL_ID)
        self.callbacks = l3_rpc.L3RpcCallback()
        self.network = self._prepare_network()

    def _prepare_network(self):
        network = {'network': {'name': 'abc',
                               'shared': False,
                               'admin_state_up': True}}
        return self.plugin.create_network(self.ctx, network)

    def _prepare_ipv6_pd_subnet(self):
        subnet = {'subnet': {'network_id': self.network['id'],
                             'cidr': None,
                             'ip_version': 6,
                             'name': 'ipv6_pd',
                             'enable_dhcp': True,
                             'host_routes': None,
                             'dns_nameservers': None,
                             'allocation_pools': None,
                             'ipv6_ra_mode': constants.IPV6_SLAAC,
                             'ipv6_address_mode': constants.IPV6_SLAAC}}
        return self.plugin.create_subnet(self.ctx, subnet)

    def test_process_prefix_update(self):
        subnet = self._prepare_ipv6_pd_subnet()
        data = {subnet['id']: '2001:db8::/64'}
        allocation_pools = [{'start': '2001:db8::2',
                             'end': '2001:db8::ffff:ffff:ffff:ffff'}]
        res = self.callbacks.process_prefix_update(self.ctx, subnets=data)
        updated_subnet = res[0]
        self.assertEqual(updated_subnet['cidr'], data[subnet['id']])
        self.assertEqual(updated_subnet['allocation_pools'], allocation_pools)
