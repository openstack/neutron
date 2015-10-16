# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import mock

from neutron.db import l3_db
from neutron import manager
from neutron.tests import base


class TestL3_NAT_dbonly_mixin(base.BaseTestCase):
    def setUp(self):
        super(TestL3_NAT_dbonly_mixin, self).setUp()
        self.db = l3_db.L3_NAT_dbonly_mixin()

    def test__each_port_having_fixed_ips_none(self):
        """Be sure the method returns an empty list when None is passed"""
        filtered = l3_db.L3_NAT_dbonly_mixin._each_port_having_fixed_ips(None)
        self.assertEqual([], list(filtered))

    def test__each_port_having_fixed_ips(self):
        """Basic test that ports without fixed ips are filtered out"""
        ports = [{'id': 'a', 'fixed_ips': [mock.sentinel.fixedip]},
                 {'id': 'b'}]
        filtered = l3_db.L3_NAT_dbonly_mixin._each_port_having_fixed_ips(ports)
        ids = [p['id'] for p in filtered]
        self.assertEqual(['a'], ids)

    def test__get_subnets_by_network_no_query(self):
        """Basic test that no query is performed if no Ports are passed"""
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            self.db._get_subnets_by_network_list(mock.sentinel.context, [])
        self.assertFalse(get_p().get_subnets.called)

    def test__get_subnets_by_network(self):
        """Basic test that the right query is called"""
        network_ids = ['a', 'b']
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            self.db._get_subnets_by_network_list(
                mock.sentinel.context, network_ids)
        get_p().get_subnets.assert_called_once_with(
            mock.sentinel.context,
            {'network_id': network_ids},
            mock.ANY)

    def test__populate_ports_for_subnets_none(self):
        """Basic test that the method runs correctly with no ports"""
        ports = []
        self.db._populate_subnets_for_ports(mock.sentinel.context, ports)
        self.assertEqual([], ports)

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_get_subnets_by_network_list')
    def test__populate_ports_for_subnets(self, get_subnets_by_network):
        cidr = "2001:db8::/64"
        subnet = {'id': mock.sentinel.subnet_id,
                  'cidr': cidr,
                  'gateway_ip': mock.sentinel.gateway_ip,
                  'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode,
                  'subnetpool_id': mock.sentinel.subnetpool_id}
        get_subnets_by_network.return_value = {'net_id': [subnet]}

        ports = [{'network_id': 'net_id',
                  'id': 'port_id',
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}]}]
        self.db._populate_subnets_for_ports(mock.sentinel.context, ports)
        self.assertEqual([{'extra_subnets': [],
                           'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id,
                                          'prefixlen': 64}],
                           'id': 'port_id',
                           'network_id': 'net_id',
                           'subnets': [subnet]}], ports)
