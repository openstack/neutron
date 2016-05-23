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
import testtools

from neutron.common import exceptions as n_exc
from neutron.db import l3_db
from neutron.extensions import l3
from neutron import manager
from neutron.tests import base


class TestL3_NAT_dbonly_mixin(base.BaseTestCase):
    def setUp(self):
        super(TestL3_NAT_dbonly_mixin, self).setUp()
        self.db = l3_db.L3_NAT_dbonly_mixin()

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_deletion_port_not_found(self, gp):
        # port not found doesn't prevent
        gp.return_value.get_port.side_effect = n_exc.PortNotFound(port_id='1')
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_device_owner_not_router(self, gp):
        # ignores other device owners
        gp.return_value.get_port.return_value = {'device_owner': 'cat'}
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_no_fixed_ips(self, gp):
        # without fixed IPs is allowed
        gp.return_value.get_port.return_value = {
            'device_owner': 'network:router_interface', 'fixed_ips': [],
            'id': 'f'
        }
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_no_router(self, gp):
        # without router is allowed
        gp.return_value.get_port.return_value = {
            'device_owner': 'network:router_interface',
            'device_id': '44', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        self.db.get_router = mock.Mock()
        self.db.get_router.side_effect = l3.RouterNotFound(router_id='44')
        self.db.prevent_l3_port_deletion(mock.Mock(), None)

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_existing_router(self, gp):
        gp.return_value.get_port.return_value = {
            'device_owner': 'network:router_interface',
            'device_id': 'some_router', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        self.db.get_router = mock.Mock()
        with testtools.ExpectedException(n_exc.ServicePortInUse):
            self.db.prevent_l3_port_deletion(mock.Mock(), None)

    @mock.patch.object(manager.NeutronManager, 'get_plugin')
    def test_prevent_l3_port_existing_floating_ip(self, gp):
        gp.return_value.get_port.return_value = {
            'device_owner': 'network:floatingip',
            'device_id': 'some_flip', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        self.db.get_floatingip = mock.Mock()
        with testtools.ExpectedException(n_exc.ServicePortInUse):
            self.db.prevent_l3_port_deletion(mock.Mock(), None)

    def test__populate_ports_for_subnets_none(self):
        """Basic test that the method runs correctly with no ports"""
        ports = []
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            get_p().get_networks.return_value = []
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)
        self.assertEqual([], ports)

    def test__populate_ports_for_subnets(self):
        ports = [{'network_id': 'net_id',
                  'id': 'port_id',
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}]}]
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            get_p().get_networks.return_value = [{'id': 'net_id', 'mtu': 1446}]
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)
            self.assertEqual([{'extra_subnets': [],
                               'fixed_ips': [{'subnet_id':
                                              mock.sentinel.subnet_id}],
                               'id': 'port_id',
                               'mtu': 1446,
                               'network_id': 'net_id',
                               'subnets': []}],
                             ports)
