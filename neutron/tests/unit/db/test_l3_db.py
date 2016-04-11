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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron.db import l3_db
from neutron.extensions import l3
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
        context = mock.Mock()
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            self.db._get_subnets_by_network_list(context, [])
        self.assertFalse(context.session.query.called)
        self.assertFalse(get_p.called)

    def test__get_subnets_by_network(self):
        """Basic test that the right query is called"""
        context = mock.MagicMock()
        query = context.session.query().outerjoin().filter()
        query.__iter__.return_value = [(mock.sentinel.subnet_db,
                                        mock.sentinel.address_scope_id)]

        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            get_p()._make_subnet_dict.return_value = {
                'network_id': mock.sentinel.network_id}
            subnets = self.db._get_subnets_by_network_list(
                context, [mock.sentinel.network_id])
        self.assertEqual({
            mock.sentinel.network_id: [{
                'address_scope_id': mock.sentinel.address_scope_id,
                'network_id': mock.sentinel.network_id}]}, subnets)

    def test__populate_ports_for_subnets_none(self):
        """Basic test that the method runs correctly with no ports"""
        ports = []
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            get_p().get_networks.return_value = []
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)
        self.assertEqual([], ports)

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_get_subnets_by_network_list')
    def test__populate_ports_for_subnets(self, get_subnets_by_network):
        cidr = "2001:db8::/64"
        subnet = {'id': mock.sentinel.subnet_id,
                  'cidr': cidr,
                  'gateway_ip': mock.sentinel.gateway_ip,
                  'dns_nameservers': mock.sentinel.dns_nameservers,
                  'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode,
                  'subnetpool_id': mock.sentinel.subnetpool_id,
                  'address_scope_id': mock.sentinel.address_scope_id}
        get_subnets_by_network.return_value = {'net_id': [subnet]}

        ports = [{'network_id': 'net_id',
                  'id': 'port_id',
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}]}]
        with mock.patch.object(manager.NeutronManager, 'get_plugin') as get_p:
            get_p().get_networks.return_value = [{'id': 'net_id', 'mtu': 1446}]
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)
            keys = ('id', 'cidr', 'gateway_ip', 'ipv6_ra_mode',
                    'subnetpool_id', 'dns_nameservers')
            address_scopes = {4: None, 6: mock.sentinel.address_scope_id}
            self.assertEqual([{'extra_subnets': [],
                               'fixed_ips': [{'subnet_id':
                                              mock.sentinel.subnet_id,
                                              'prefixlen': 64}],
                               'id': 'port_id',
                               'mtu': 1446,
                               'network_id': 'net_id',
                               'subnets': [{k: subnet[k] for k in keys}],
                               'address_scopes': address_scopes}], ports)

    def test__get_sync_floating_ips_no_query(self):
        """Basic test that no query is performed if no router ids are passed"""
        db = l3_db.L3_NAT_dbonly_mixin()
        context = mock.Mock()
        db._get_sync_floating_ips(context, [])
        self.assertFalse(context.session.query.called)

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_make_floatingip_dict')
    def test__make_floatingip_dict_with_scope(self, make_fip_dict):
        db = l3_db.L3_NAT_dbonly_mixin()
        make_fip_dict.return_value = {'id': mock.sentinel.fip_ip}
        result = db._make_floatingip_dict_with_scope(
            mock.sentinel.floating_ip_db, mock.sentinel.address_scope_id)
        self.assertEqual({
            'fixed_ip_address_scope': mock.sentinel.address_scope_id,
            'id': mock.sentinel.fip_ip}, result)

    def test__unique_floatingip_iterator(self):
        query = mock.MagicMock()
        query.order_by().__iter__.return_value = [
            ({'id': 'id1'}, 'scope1'),
            ({'id': 'id1'}, 'scope1'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id3'}, 'scope3')]
        query.reset_mock()
        result = list(
            l3_db.L3_NAT_dbonly_mixin._unique_floatingip_iterator(query))
        query.order_by.assert_called_once_with(l3_db.FloatingIP.id)
        self.assertEqual([({'id': 'id1'}, 'scope1'),
                          ({'id': 'id2'}, 'scope2'),
                          ({'id': 'id3'}, 'scope3')], result)

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

    @mock.patch.object(l3_db, '_notify_subnetpool_address_scope_update')
    def test_subscribe_address_scope_of_subnetpool(self, notify):
        l3_db.subscribe()
        registry.notify(resources.SUBNETPOOL_ADDRESS_SCOPE,
                        events.AFTER_UPDATE, mock.ANY, context=mock.ANY,
                        subnetpool_id='fake_id')
        notify.assert_called_once_with(resources.SUBNETPOOL_ADDRESS_SCOPE,
                                       events.AFTER_UPDATE, mock.ANY,
                                       context=mock.ANY,
                                       subnetpool_id='fake_id')


class L3_NAT_db_mixin(base.BaseTestCase):
    def setUp(self):
        super(L3_NAT_db_mixin, self).setUp()
        self.db = l3_db.L3_NAT_db_mixin()

    def _test_create_router(self, external_gateway_info=None):
        router_db = l3_db.Router(id='123')
        router_dict = {'id': '123', 'tenant_id': '456',
                       'external_gateway_info': external_gateway_info}
        # Need to use a copy here as the create_router method pops the gateway
        # information
        router_input = {'router': router_dict.copy()}

        with mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_create_router_db',
                               return_value=router_db) as crd,\
            mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_make_router_dict',
                              return_value=router_dict),\
            mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                              '_update_router_gw_info') as urgi,\
            mock.patch.object(l3_db.L3_NAT_db_mixin, 'notify_router_updated')\
            as nru:

            self.db.create_router(mock.ANY, router_input)
            self.assertTrue(crd.called)
            if external_gateway_info:
                self.assertTrue(urgi.called)
                self.assertTrue(nru.called)
            else:
                self.assertFalse(urgi.called)
                self.assertFalse(nru.called)

    def test_create_router_no_gateway(self):
        self._test_create_router()

    def test_create_router_gateway(self):
        ext_gateway_info = {'network_id': 'net-id', 'enable_snat': True,
                            'external_fixed_ips': [
                                {'subnet_id': 'subnet-id',
                                 'ip_address': 'ip'}]}
        self._test_create_router(ext_gateway_info)
