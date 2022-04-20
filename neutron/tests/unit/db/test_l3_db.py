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
import netaddr
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_utils import uuidutils
import testtools

from neutron.db import l3_db
from neutron.db.models import l3 as l3_models
from neutron.objects import base as base_obj
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2


class TestL3_NAT_dbonly_mixin(base.BaseTestCase):
    def setUp(self):
        super(TestL3_NAT_dbonly_mixin, self).setUp()
        self.db = l3_db.L3_NAT_dbonly_mixin()

    def test__each_port_having_fixed_ips_none(self):
        """Be sure the method returns an empty list when None is passed"""
        filtered = l3_db.L3_NAT_dbonly_mixin._each_port_having_fixed_ips(None)
        self.assertEqual([], list(filtered))

    def test__new__passes_args(self):
        class T(l3_db.L3_NAT_db_mixin):
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

        t = T(1, 2, a=3)
        self.assertEqual((1, 2), t.args)
        self.assertEqual({'a': 3}, t.kwargs)

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
        with mock.patch.object(directory, 'get_plugin') as get_p:
            self.db._get_subnets_by_network_list(context, [])
        self.assertFalse(context.session.query.called)
        self.assertFalse(get_p.called)

    def test__get_subnets_by_network(self):
        """Basic test that the right query is called"""
        context = mock.MagicMock()
        query = context.session.query().outerjoin().filter()
        query.__iter__.return_value = [(mock.sentinel.subnet_db,
                                        mock.sentinel.address_scope_id)]

        with mock.patch.object(directory, 'get_plugin') as get_p:
            get_p()._make_subnet_dict.return_value = {
                'network_id': mock.sentinel.network_id}
            subnets = self.db._get_subnets_by_network_list(
                context, [mock.sentinel.network_id])
        self.assertEqual({
            mock.sentinel.network_id: [{
                'address_scope_id': mock.sentinel.address_scope_id,
                'network_id': mock.sentinel.network_id}]}, subnets)

    def test__get_mtus_by_network_list(self):
        """Basic test that the query get_networks is correctly"""
        network = {'id': mock.sentinel.network_id,
                   'name': mock.sentinel.name,
                   'mtu': mock.sentinel.mtu}
        with mock.patch.object(directory, 'get_plugin') as get_p:
            get_p().get_networks.return_value = [network]
            result = self.db._get_mtus_by_network_list(
                mock.sentinel.context, [mock.sentinel.network_id])
            get_p().get_networks.assert_called_once_with(
                mock.sentinel.context,
                filters={'id': [mock.sentinel.network_id]},
                fields=['id', 'mtu'])
            self.assertEqual({mock.sentinel.network_id: mock.sentinel.mtu},
                             result)

    def test__populate_ports_for_subnets_none(self):
        """Basic test that the method runs correctly with no ports"""
        ports = []
        with mock.patch.object(directory, 'get_plugin') as get_p:
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
        with mock.patch.object(directory, 'get_plugin') as get_p:
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

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_get_subnets_by_network_list')
    def test__populate_ports_for_subnets_mixed_address_scopes(
            self, get_subnets_by_network):
        subnets = [{'id': mock.sentinel.subnet_id_a,
                    'cidr': '10.180.0.0/24',
                    'gateway_ip': mock.sentinel.gateway_ip_a,
                    'dns_nameservers': mock.sentinel.dns_nameservers_a,
                    'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode_a,
                    'subnetpool_id': mock.sentinel.subnetpool_id,
                    'address_scope_id': mock.sentinel.address_scope_id},
                   {'id': mock.sentinel.subnet_id_b,
                    'cidr': '10.180.1.0/24',
                    'gateway_ip': mock.sentinel.gateway_ip_b,
                    'dns_nameservers': mock.sentinel.dns_nameservers_b,
                    'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode_b,
                    'subnetpool_id': None,
                    'address_scope_id': None}]
        get_subnets_by_network.return_value = {'net_id': subnets}

        ports = [{'network_id': 'net_id',
                  'id': 'port_id_a',
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id_a}]},
                 {'network_id': 'net_id',
                  'id': 'port_id_b',
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id_b}]}]
        with mock.patch.object(directory, 'get_plugin') as get_p:
            get_p().get_networks.return_value = [{'id': 'net_id', 'mtu': 1446}]
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)

            self.assertEqual(mock.sentinel.address_scope_id,
                             ports[0]['address_scopes'][n_const.IP_VERSION_4])
            self.assertIsNone(ports[1]['address_scopes'][n_const.IP_VERSION_4])

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
        context = mock.MagicMock()
        query = mock.MagicMock()
        query.order_by().__iter__.return_value = [
            ({'id': 'id1'}, 'scope1'),
            ({'id': 'id1'}, 'scope1'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id2'}, 'scope2'),
            ({'id': 'id3'}, 'scope3')]
        query.reset_mock()
        with mock.patch.object(
                l3_obj.FloatingIP, '_load_object',
                side_effect=({'id': 'id1'}, {'id': 'id2'}, {'id': 'id3'})):
            result = list(
                l3_obj.FloatingIP._unique_floatingip_iterator(context, query))
            query.order_by.assert_called_once_with(l3_models.FloatingIP.id)
            self.assertEqual([({'id': 'id1'}, 'scope1'),
                              ({'id': 'id2'}, 'scope2'),
                              ({'id': 'id3'}, 'scope3')], result)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_deletion_port_not_found(self, gp):
        # port not found doesn't prevent
        gp.return_value.get_port.side_effect = n_exc.PortNotFound(port_id='1')
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_device_owner_not_router(self, gp):
        # ignores other device owners
        gp.return_value.get_port.return_value = {'device_owner': 'cat'}
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_no_fixed_ips(self, gp):
        # without fixed IPs is allowed
        gp.return_value.get_port.return_value = {
            'device_owner': n_const.DEVICE_OWNER_ROUTER_INTF, 'fixed_ips': [],
            'id': 'f'
        }
        self.db.prevent_l3_port_deletion(None, None)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_no_router(self, gp):
        # without router is allowed
        gp.return_value.get_port.return_value = {
            'device_owner': n_const.DEVICE_OWNER_ROUTER_INTF,
            'device_id': '44', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        self.db.get_router = mock.Mock()
        self.db.get_router.side_effect = l3_exc.RouterNotFound(router_id='44')
        self.db.prevent_l3_port_deletion(mock.Mock(), None)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_existing_router(self, gp):
        gp.return_value.get_port.return_value = {
            'device_owner': n_const.DEVICE_OWNER_ROUTER_INTF,
            'device_id': 'some_router', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        self.db.get_router = mock.Mock()
        with testtools.ExpectedException(n_exc.ServicePortInUse):
            self.db.prevent_l3_port_deletion(mock.Mock(), None)

    @mock.patch.object(directory, 'get_plugin')
    def test_prevent_l3_port_existing_floating_ip(self, gp):
        ctx = context.get_admin_context()
        gp.return_value.get_port.return_value = {
            'device_owner': n_const.DEVICE_OWNER_FLOATINGIP,
            'device_id': 'some_flip', 'id': 'f',
            'fixed_ips': [{'ip_address': '1.1.1.1', 'subnet_id': '4'}]}
        with mock.patch.object(l3_obj.FloatingIP, 'objects_exist',
                               return_value=mock.Mock()),\
                testtools.ExpectedException(n_exc.ServicePortInUse):

            self.db.prevent_l3_port_deletion(ctx, None)

    @mock.patch.object(directory, 'get_plugin')
    def test_subscribe_address_scope_of_subnetpool(self, gp):
        l3_db.L3RpcNotifierMixin()
        registry.publish(resources.SUBNETPOOL_ADDRESS_SCOPE,
                         events.AFTER_UPDATE, mock.ANY,
                         payload=events.DBEventPayload(
                             mock.MagicMock(), resource_id='fake_id'))
        self.assertTrue(gp.return_value.notify_routers_updated.called)

    def test__check_and_get_fip_assoc_with_extra_association_no_change(self):
        fip = {'extra_key': 'value'}
        context = mock.MagicMock()
        floatingip_obj = l3_obj.FloatingIP(
            context,
            id=uuidutils.generate_uuid(),
            floating_network_id=uuidutils.generate_uuid(),
            floating_ip_address=netaddr.IPAddress('8.8.8.8'),
            fixed_port_id=uuidutils.generate_uuid(),
            floating_port_id=uuidutils.generate_uuid())
        with mock.patch.object(
                l3_db.L3_NAT_dbonly_mixin,
                '_get_assoc_data',
                return_value=('1', '2', '3')) as mock_get_assoc_data:
            self.db._check_and_get_fip_assoc(context, fip, floatingip_obj)
            context.session.query.assert_not_called()
            mock_get_assoc_data.assert_called_once_with(
                mock.ANY, fip, floatingip_obj)

    def test__notify_attaching_interface(self):
        with mock.patch.object(l3_db.registry, 'notify') as mock_notify:
            context = mock.MagicMock()
            router_id = 'router_id'
            net_id = 'net_id'
            router_db = mock.Mock()
            router_db.id = router_id
            port = {'network_id': net_id}
            intf = {}
            self.db._notify_attaching_interface(context, router_db, port, intf)
            kwargs = {'context': context, 'router_id': router_id,
                      'network_id': net_id, 'interface_info': intf,
                      'router_db': router_db, 'port': port}
            mock_notify.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.BEFORE_CREATE, self.db,
                **kwargs)

    def test__create_gw_port(self):
        router_id = '2afb8434-7380-43a2-913f-ba3a5ad5f349'
        router = l3_models.Router(id=router_id)
        new_network_id = 'net-id'
        ext_ips = [{'subnet_id': 'subnet-id', 'ip_address': '1.1.1.1'}]
        gw_port = {'fixed_ips': [{'subnet_id': 'subnet-id',
                                  'ip_address': '1.1.1.1'}],
                   'id': '8742d007-6f05-4b7e-abdb-11818f608959'}
        ctx = context.get_admin_context()

        with mock.patch.object(directory, 'get_plugin') as get_p, \
                mock.patch.object(get_p(), 'get_subnets_by_network',
                                  return_value=mock.ANY), \
                mock.patch.object(get_p(), '_get_port',
                                  return_value=gw_port), \
                mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                                  '_check_for_dup_router_subnets') as cfdrs,\
                mock.patch.object(plugin_utils, 'create_port',
                                  return_value=gw_port), \
                mock.patch.object(ctx.session, 'add'), \
                mock.patch.object(base_obj.NeutronDbObject, 'create'), \
                mock.patch.object(l3_db.registry, 'publish') as mock_notify:

            self.db._create_gw_port(ctx, router_id=router_id,
                                    router=router,
                                    new_network_id=new_network_id,
                                    ext_ips=ext_ips)

            expected_gw_ips = ['1.1.1.1']

            self.assertTrue(cfdrs.called)
            mock_notify.assert_called_with(
                resources.ROUTER_GATEWAY, events.AFTER_CREATE,
                self.db._create_gw_port, payload=mock.ANY)
            cb_payload = mock_notify.mock_calls[1][2]['payload']
            self.assertEqual(ctx, cb_payload.context)
            self.assertEqual(expected_gw_ips,
                             cb_payload.metadata.get('gateway_ips'))
            self.assertEqual(new_network_id,
                             cb_payload.metadata.get('network_id'))
            self.assertEqual(router_id, cb_payload.resource_id)


class L3_NAT_db_mixin(base.BaseTestCase):
    def setUp(self):
        super(L3_NAT_db_mixin, self).setUp()
        self.db = l3_db.L3_NAT_db_mixin()

    def _test_create_router(self, external_gateway_info=None):
        router_db = l3_models.Router(id='123')
        router_dict = {'id': '123', 'tenant_id': '456',
                       'external_gateway_info': external_gateway_info}
        # Need to use a copy here as the create_router method pops the gateway
        # information
        router_input = {'router': router_dict.copy()}

        with mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_create_router_db',
                               return_value=router_db) as crd,\
                mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                                  '_make_router_dict',
                                  return_value=router_dict),\
                mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                                  '_update_router_gw_info') as urgi,\
                mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_get_router',
                                  return_value=router_db),\
                mock.patch.object(l3_db.L3_NAT_db_mixin,
                                  'notify_router_updated') as nru:

            self.db.create_router(mock.Mock(), router_input)
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

    def test_add_router_interface_no_interface_info(self):
        router_db = l3_models.Router(id='123')
        with mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_get_router',
                               return_value=router_db):
            self.assertRaises(
                n_exc.BadRequest,
                self.db.add_router_interface, mock.Mock(), router_db.id)


class FakeL3Plugin(l3_db.L3_NAT_dbonly_mixin):
    pass


class L3TestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    GET_PORTS_BY_ROUTER_MSG = (
        'The following ports, assigned to router %(router_id)s, do not have a '
        '"routerport" register: %(port_ids)s')

    def setUp(self, *args, **kwargs):
        super(L3TestCase, self).setUp(plugin='ml2')
        self.core_plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.mixin = FakeL3Plugin()
        directory.add_plugin(plugin_constants.L3, self.mixin)
        self.network = self.create_network()
        self.subnets = []
        self.subnets.append(self.create_subnet(self.network, '1.1.1.1',
                                               '1.1.1.0/24'))
        self.subnets.append(self.create_subnet(self.network, '1.1.2.1',
                                               '1.1.2.0/24'))
        router = {'router': {'name': 'foo_router', 'admin_state_up': True,
                             'tenant_id': 'foo_tenant'}}
        self.router = self.create_router(router)
        self.ports = []
        for subnet in self.subnets:
            ipa = str(netaddr.IPNetwork(subnet['subnet']['cidr']).ip + 10)
            fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                          'ip_address': ipa}]
            self.ports.append(self.create_port(
                self.network['network']['id'], {'fixed_ips': fixed_ips}))
        self.addCleanup(self._clean_objs)

    def _clean_objs(self):
        port_obj.Port.delete_objects(
            self.ctx, network_id=self.network['network']['id'])
        subnet_obj.Subnet.delete_objects(
            self.ctx, network_id=self.network['network']['id'])
        network_obj.Network.get_object(
            self.ctx, id=self.network['network']['id']).delete()
        l3_obj.Router.get_object(self.ctx, id=self.router['id']).delete()

    def create_router(self, router):
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.create_router(self.ctx, router)

    def create_port(self, net_id, port_info):
        with self.ctx.session.begin(subtransactions=True):
            return self._make_port(self.fmt, net_id, **port_info)

    def create_network(self, name=None, **kwargs):
        name = name or 'network1'
        with self.ctx.session.begin(subtransactions=True):
            return self._make_network(self.fmt, name, True, **kwargs)

    def create_subnet(self, network, gateway, cidr, **kwargs):
        with self.ctx.session.begin(subtransactions=True):
            return self._make_subnet(self.fmt, network, gateway, cidr,
                                     **kwargs)

    def _add_router_interfaces(self):
        return [self.mixin.add_router_interface(
            self.ctx, self.router['id'],
            interface_info={'port_id': port['port']['id']})
            for port in self.ports]

    def _check_routerports(self, ri_statuses):
        port_ids = []
        for idx, ri_status in enumerate(ri_statuses):
            rp_obj = l3_obj.RouterPort.get_object(
                self.ctx, port_id=self.ports[idx]['port']['id'],
                router_id=self.router['id'])
            if ri_status:
                self.assertEqual(self.ports[idx]['port']['id'], rp_obj.port_id)
                port_ids.append(rp_obj.port_id)
            else:
                self.assertIsNone(rp_obj)

        _router_obj = l3_obj.Router.get_object(self.ctx, id=self.router['id'])
        router_port_ids = [rp.port_id for rp in
                           _router_obj.db_obj.attached_ports]
        self.assertEqual(sorted(port_ids), sorted(router_port_ids))

    @mock.patch.object(port_obj, 'LOG')
    def test_remove_router_interface_by_port(self, mock_log):
        self._add_router_interfaces()
        self._check_routerports((True, True))

        interface_info = {'port_id': self.ports[0]['port']['id']}
        self.mixin.remove_router_interface(self.ctx, self.router['id'],
                                           interface_info)
        mock_log.warning.assert_not_called()
        self._check_routerports((False, True))

    @mock.patch.object(port_obj, 'LOG')
    def test_remove_router_interface_by_port_removed_rport(self, mock_log):
        self._add_router_interfaces()
        self._check_routerports((True, True))

        rp_obj = l3_obj.RouterPort.get_object(
            self.ctx, router_id=self.router['id'],
            port_id=self.ports[0]['port']['id'])
        rp_obj.delete()

        interface_info = {'port_id': self.ports[0]['port']['id']}
        self.mixin.remove_router_interface(self.ctx, self.router['id'],
                                           interface_info)
        msg_vars = {'router_id': self.router['id'],
                    'port_ids': {self.ports[0]['port']['id']}}
        mock_log.warning.assert_called_once_with(self.GET_PORTS_BY_ROUTER_MSG,
                                                 msg_vars)
        self._check_routerports((False, True))

    @mock.patch.object(port_obj, 'LOG')
    def test_remove_router_interface_by_subnet(self, mock_log):
        self._add_router_interfaces()
        self._check_routerports((True, True))

        interface_info = {'subnet_id': self.subnets[1]['subnet']['id']}
        self.mixin.remove_router_interface(self.ctx, self.router['id'],
                                           interface_info)
        mock_log.warning.not_called_once()
        self._check_routerports((True, False))

    @mock.patch.object(port_obj, 'LOG')
    def test_remove_router_interface_by_subnet_removed_rport(self, mock_log):
        self._add_router_interfaces()
        self._check_routerports((True, True))

        rp_obj = l3_obj.RouterPort.get_object(
            self.ctx, router_id=self.router['id'],
            port_id=self.ports[0]['port']['id'])
        rp_obj.delete()

        interface_info = {'subnet_id': self.subnets[0]['subnet']['id']}
        self.mixin.remove_router_interface(self.ctx, self.router['id'],
                                           interface_info)
        msg_vars = {'router_id': self.router['id'],
                    'port_ids': {self.ports[0]['port']['id']}}
        mock_log.warning.assert_called_once_with(self.GET_PORTS_BY_ROUTER_MSG,
                                                 msg_vars)
        self._check_routerports((False, True))
