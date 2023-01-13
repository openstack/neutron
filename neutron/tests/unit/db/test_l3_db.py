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

from unittest import mock

import ddt
import netaddr
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import extraroute as xroute_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_utils import uuidutils
import testtools
import webob.exc

from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3_attrs
from neutron.db import models_v2
from neutron.extensions import segment as segment_ext
from neutron.objects import base as base_obj
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2


@ddt.ddt
class TestL3_NAT_dbonly_mixin(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, *args, **kwargs):
        super(TestL3_NAT_dbonly_mixin, self).setUp(*args, **kwargs)
        # "extraroute_db.ExtraRoute_dbonly_mixin" inherits from
        # "l3_db.L3_NAT_dbonly_mixin()", the class under test. This is used
        # instead to test the validation of router routes and GW change because
        # implements "_validate_routes".
        self.db = extraroute_db.ExtraRoute_dbonly_mixin()
        self.ctx = mock.Mock()

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
                  'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}],
                  'device_owner': 'compute:nova'}]
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
                               'address_scopes': address_scopes,
                               'device_owner': 'compute:nova'}], ports)

    @ddt.unpack
    @ddt.data({'plugin_loaded': False, 'seg1': None, 'seg2': None},
              {'plugin_loaded': True, 'seg1': None, 'seg2': None},
              {'plugin_loaded': True, 'seg1': 'seg1', 'seg2': 'seg2'})
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_get_subnets_by_network_list')
    def test__populate_ports_for_subnets_gw_port(self, get_subnets_by_network,
                                                 plugin_loaded, seg1, seg2):
        subnets = [
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.1.0.0/24',
             'gateway_ip': mock.sentinel.gateway_ip,
             'dns_nameservers': mock.sentinel.dns_nameservers,
             'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode,
             'subnetpool_id': mock.sentinel.subnetpool_id,
             'address_scope_id': mock.sentinel.address_scope_id,
             'segment_id': seg1},
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.2.0.0/24',
             'gateway_ip': mock.sentinel.gateway_ip,
             'dns_nameservers': mock.sentinel.dns_nameservers,
             'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode,
             'subnetpool_id': mock.sentinel.subnetpool_id,
             'address_scope_id': mock.sentinel.address_scope_id,
             'segment_id': seg1},
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.3.0.0/24',
             'gateway_ip': mock.sentinel.gateway_ip,
             'dns_nameservers': mock.sentinel.dns_nameservers,
             'ipv6_ra_mode': mock.sentinel.ipv6_ra_mode,
             'subnetpool_id': mock.sentinel.subnetpool_id,
             'address_scope_id': mock.sentinel.address_scope_id,
             'segment_id': seg2}]
        get_subnets_by_network.return_value = {'net_id': subnets}

        ports = [{'network_id': 'net_id',
                  'id': 'port_id',
                  'fixed_ips': [{'subnet_id': subnets[0]['id']}],
                  'device_owner': n_const.DEVICE_OWNER_ROUTER_GW}]
        with mock.patch.object(directory, 'get_plugin') as get_p, \
                mock.patch.object(segment_ext.SegmentPluginBase,
                                  'is_loaded', return_value=plugin_loaded):
            get_p().get_networks.return_value = [{'id': 'net_id', 'mtu': 1446}]
            self.db._populate_mtu_and_subnets_for_ports(mock.sentinel.context,
                                                        ports)
            keys = ('id', 'cidr', 'gateway_ip', 'ipv6_ra_mode',
                    'subnetpool_id', 'dns_nameservers')
            address_scopes = {4: mock.sentinel.address_scope_id, 6: None}
            reference = {'fixed_ips': [{'subnet_id': subnets[0]['id'],
                                        'prefixlen': 24}],
                         'id': 'port_id',
                         'mtu': 1446,
                         'network_id': 'net_id',
                         'subnets': [{k: subnets[0][k] for k in keys}],
                         'address_scopes': address_scopes,
                         'device_owner': n_const.DEVICE_OWNER_ROUTER_GW,
                         'extra_subnets': [{k: subnets[1][k] for k in keys}]}
            # If RPN plugin is not enabled or the network subnets do not have
            # associated segments (that means this is not a RPN), all subnets
            # should be passed in "subnets" + "extra_subnets".
            if not plugin_loaded or subnets[0]['segment_id'] is None:
                reference['extra_subnets'].append(
                    {k: subnets[2][k] for k in keys})
            self.assertEqual([reference], ports)

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
        with mock.patch.object(l3_obj.Router, 'objects_exist',
                               return_value=False):
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
        with mock.patch.object(l3_db.registry, 'publish') as mock_notify:
            context = mock.MagicMock()
            router_id = 'router_id'
            net_id = 'net_id'
            router_db = mock.Mock()
            router_db.id = router_id
            port = {'network_id': net_id}
            intf = {}
            self.db._notify_attaching_interface(context, router_db, port, intf)

            mock_notify.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.BEFORE_CREATE, self.db,
                payload=mock.ANY)
            payload = mock_notify.mock_calls[0][2]['payload']
            self.assertEqual(context, payload.context)
            self.assertEqual(router_id, payload.resource_id)
            self.assertEqual(net_id, payload.metadata.get('network_id'))
            self.assertEqual(intf, payload.metadata.get('interface_info'))
            self.assertEqual(router_db, payload.latest_state)
            self.assertEqual(port, payload.metadata.get('port'))

    def test__create_gw_port(self):
        # NOTE(slaweq): this test is probably wrong
        # returning dict as gw_port breaks test later in L334 in
        # neutron.db.l3_db file
        router_id = '2afb8434-7380-43a2-913f-ba3a5ad5f349'
        router = l3_models.Router(id=router_id)
        new_network_id = 'net-id'
        ext_ips = [{'subnet_id': 'subnet-id', 'ip_address': '1.1.1.1'}]
        gw_port = {'fixed_ips': [{'subnet_id': 'subnet-id',
                                  'ip_address': '1.1.1.1'}],
                   'id': '8742d007-6f05-4b7e-abdb-11818f608959'}
        ctx = context.get_admin_context()

        with db_api.CONTEXT_WRITER.using(ctx):
            with mock.patch.object(directory, 'get_plugin') as get_p, \
                    mock.patch.object(get_p(), 'get_subnets_by_network',
                                      return_value=mock.ANY), \
                    mock.patch.object(get_p(), '_get_port',
                                      return_value=gw_port), \
                    mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                                      '_check_for_dup_router_subnets') as \
                    cfdrs, \
                    mock.patch.object(plugin_utils, 'create_port',
                                      return_value=gw_port), \
                    mock.patch.object(ctx.session, 'add'), \
                    mock.patch.object(base_obj.NeutronDbObject, 'create'), \
                    mock.patch.object(l3_db.registry, 'publish') as \
                    mock_notify, \
                    mock.patch.object(l3_db.L3_NAT_dbonly_mixin, '_get_router',
                                      return_value=router):

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

    def _create_router(self, gw_port=True, num_ports=2, create_routes=True):
        # GW CIDR: 10.0.0.0/24
        # Interface CIDRS: 10.0.1.0/24, 10.0.2.0/24, etc.
        router_id = uuidutils.generate_uuid()
        port_gw_cidr = netaddr.IPNetwork('10.0.0.0/24')
        rports = []
        if gw_port:
            port_gw = models_v2.Port(
                id=uuidutils.generate_uuid(),
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(port_gw_cidr.ip + 1))])
            rports.append(l3_models.RouterPort(router_id=router_id,
                                               port=port_gw))
        else:
            port_gw = None

        port_cidrs = []
        port_subnets = []
        for idx in range(num_ports):
            cidr = port_gw_cidr.cidr.next(idx + 1)
            port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(cidr.ip + 1))])
            port_cidrs.append(cidr)
            rports.append(l3_models.RouterPort(router_id=router_id, port=port))
            port_subnets.append({'cidr': str(cidr)})

        routes = []
        if create_routes:
            for cidr in [*port_cidrs, port_gw_cidr]:
                routes.append(l3_models.RouterRoute(
                    destination=str(cidr.next(100)),
                    nexthop=str(cidr.ip + 10)))
        return (l3_models.Router(
            id=router_id, attached_ports=rports, route_list=routes,
            gw_port_id=port_gw.id if port_gw else None), port_subnets)

    def test__validate_gw_info(self):
        gw_network = mock.Mock(subnets=[mock.Mock(cidr='10.0.0.0/24')],
                               external=True)
        router, port_subnets = self._create_router(gw_port=False)
        info = {'network_id': 'net_id'}
        with mock.patch.object(self.db._core_plugin, '_get_network',
                               return_value=gw_network), \
                mock.patch.object(self.db._core_plugin, 'get_subnet',
                                  side_effect=port_subnets):
            self.assertEqual(
                'net_id',
                self.db._validate_gw_info(self.ctx, info, [], router))

    def test__validate_gw_info_no_route_connectivity(self):
        gw_network = mock.Mock(subnets=[mock.Mock(cidr='10.50.0.0/24')],
                               external=True)
        router, port_subnets = self._create_router(gw_port=False)
        info = {'network_id': 'net_id'}
        with mock.patch.object(self.db._core_plugin, '_get_network',
                               return_value=gw_network), \
                mock.patch.object(self.db._core_plugin, 'get_subnet',
                                  side_effect=port_subnets):
            self.assertRaises(
                xroute_exc.InvalidRoutes, self.db._validate_gw_info, self.ctx,
                info, [], router)

    def test__validate_gw_info_delete_gateway(self):
        router, port_subnets = self._create_router()
        info = {'network_id': None}
        with mock.patch.object(self.db._core_plugin, '_get_network',
                               return_value=None), \
                mock.patch.object(self.db._core_plugin, 'get_subnet',
                                  side_effect=port_subnets):
            self.assertRaises(
                xroute_exc.InvalidRoutes, self.db._validate_gw_info, self.ctx,
                info, [], router)

    def test__validate_gw_info_delete_gateway_no_route(self):
        gw_network = mock.Mock(subnets=[mock.Mock(cidr='10.50.0.0/24')],
                               external=True)
        router, port_subnets = self._create_router(create_routes=False)
        info = {'network_id': None}
        with mock.patch.object(self.db._core_plugin, '_get_network',
                               return_value=gw_network), \
                mock.patch.object(self.db._core_plugin, 'get_subnet',
                                  side_effect=port_subnets):
            self.assertIsNone(
                self.db._validate_gw_info(mock.ANY, info, [], router))

    def test__raise_on_subnets_overlap_does_not_raise(self):
        subnets = [
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.1.0.0/24'},
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.2.0.0/24'}]
        self.db._raise_on_subnets_overlap(subnets[0], subnets[1])

    def test__raise_on_subnets_overlap_raises(self):
        subnets = [
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.1.0.0/20'},
            {'id': uuidutils.generate_uuid(),
             'cidr': '10.1.10.0/24'}]
        self.assertRaises(
            n_exc.BadRequest, self.db._raise_on_subnets_overlap, subnets[0],
            subnets[1])

    def test__validate_one_router_ipv6_port_per_network(self):
        port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 1),
                    subnet_id='foo_subnet')])
        rports = [l3_models.RouterPort(router_id='foo_router', port=port)]
        router = l3_models.Router(
            id='foo_router', attached_ports=rports, route_list=[],
            gw_port_id=None)
        new_port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network2',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 2),
                    subnet_id='foo_subnet')])
        self.db._validate_one_router_ipv6_port_per_network(
            router, new_port)

    def test__validate_one_router_ipv6_port_per_network_mix_ipv4_ipv6(self):
        port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '10.1.10.0/24').ip + 1),
                    subnet_id='foo_subnet')])
        rports = [l3_models.RouterPort(router_id='foo_router', port=port)]
        router = l3_models.Router(
            id='foo_router', attached_ports=rports, route_list=[],
            gw_port_id=None)
        new_port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 2),
                    subnet_id='foo_subnet')])
        self.db._validate_one_router_ipv6_port_per_network(
            router, new_port)

    def test__validate_one_router_ipv6_port_per_network_distributed_port(self):
        port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                device_owner=n_const.DEVICE_OWNER_DVR_INTERFACE,
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 1),
                    subnet_id='foo_subnet')])
        rports = [l3_models.RouterPort(router_id='foo_router', port=port)]
        router = l3_models.Router(
            id='foo_router', attached_ports=rports, route_list=[],
            gw_port_id=None)
        new_port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                device_owner=n_const.DEVICE_OWNER_ROUTER_SNAT,
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 2),
                    subnet_id='foo_subnet')])
        self.db._validate_one_router_ipv6_port_per_network(router, new_port)

    def test__validate_one_router_ipv6_port_per_network_centralized_snat_port(
            self):
        port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                device_owner=n_const.DEVICE_OWNER_ROUTER_SNAT,
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 1),
                    subnet_id='foo_subnet')])
        rports = [l3_models.RouterPort(router_id='foo_router', port=port)]
        router = l3_models.Router(
            id='foo_router', attached_ports=rports, route_list=[],
            gw_port_id=None)
        new_port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                device_owner=n_const.DEVICE_OWNER_DVR_INTERFACE,
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 2),
                    subnet_id='foo_subnet')])
        self.db._validate_one_router_ipv6_port_per_network(router, new_port)

    def test__validate_one_router_ipv6_port_per_network_failed(self):
        port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 1),
                    subnet_id='foo_subnet')])
        rports = [l3_models.RouterPort(router_id='foo_router', port=port)]
        router = l3_models.Router(
            id='foo_router', attached_ports=rports, route_list=[],
            gw_port_id=None)
        new_port = models_v2.Port(
                id=uuidutils.generate_uuid(),
                network_id='foo_network',
                fixed_ips=[models_v2.IPAllocation(
                    ip_address=str(netaddr.IPNetwork(
                        '2001:db8::/32').ip + 2),
                    subnet_id='foo_subnet')])
        self.assertRaises(
            n_exc.BadRequest,
            self.db._validate_one_router_ipv6_port_per_network,
            router,
            new_port)


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
        router_ports = l3_obj.RouterPort.get_objects(
            self.ctx, **{'router_id': self.router['id']})
        for router_port in router_ports:
            router_port.delete()
        l3_obj.Router.get_object(self.ctx, id=self.router['id']).delete()

    def create_router(self, router):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self.mixin.create_router(self.ctx, router)

    def create_port(self, net_id, port_info):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self._make_port(self.fmt, net_id, **port_info)

    def create_network(self, name=None, **kwargs):
        name = name or 'network1'
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self._make_network(self.fmt, name, True, **kwargs)

    def create_subnet(self, network, gateway, cidr, **kwargs):
        with db_api.CONTEXT_WRITER.using(self.ctx):
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

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_check_for_dup_router_subnets')
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_raise_on_subnets_overlap')
    def test_add_router_interface_by_port_overlap_detected(
            self, mock_raise_on_subnets_overlap, mock_check_dup):
        # NOTE(froyo): On a normal behaviour this overlapping would be detected
        # by _check_for_dup_router_subnets, in order to evalue the code
        # implemented to cover the race condition when two ports are added
        # simultaneously using colliding cidrs we need to "fake" this method
        # to overpass it and check we achieve the code part that cover the case
        mock_check_dup.return_value = True
        network2 = self.create_network('network2')
        subnet = self.create_subnet(network2, '1.1.1.1', '1.1.1.0/24')
        ipa = str(netaddr.IPNetwork(subnet['subnet']['cidr']).ip + 10)
        fixed_ips = [{'subnet_id': subnet['subnet']['id'], 'ip_address': ipa}]
        port = self.create_port(
                network2['network']['id'], {'fixed_ips': fixed_ips})
        self.mixin.add_router_interface(
            self.ctx, self.router['id'],
            interface_info={'port_id': port['port']['id']})
        mock_raise_on_subnets_overlap.assert_not_called()
        self.mixin.add_router_interface(
            self.ctx, self.router['id'],
            interface_info={'port_id': self.ports[0]['port']['id']})
        mock_raise_on_subnets_overlap.assert_called_once()

    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_check_for_dup_router_subnets')
    @mock.patch.object(l3_db.L3_NAT_dbonly_mixin,
                       '_raise_on_subnets_overlap')
    def test_add_router_interface_by_subnet_overlap_detected(
            self, mock_raise_on_subnets_overlap, mock_check_dup):
        # NOTE(froyo): On a normal behaviour this overlapping would be detected
        # by _check_for_dup_router_subnets, in order to evalue the code
        # implemented to cover the race condition when two ports are added
        # simultaneously using colliding cidrs we need to "fake" this method
        # to overpass it and check we achieve the code part that cover the case
        mock_check_dup.return_value = True
        network2 = self.create_network('network2')
        subnet = self.create_subnet(network2, '1.1.1.1', '1.1.1.0/24')
        self.mixin.add_router_interface(
            self.ctx, self.router['id'],
            interface_info={'subnet_id': subnet['subnet']['id']})
        mock_raise_on_subnets_overlap.assert_not_called()
        self.mixin.add_router_interface(
            self.ctx, self.router['id'],
            interface_info={'subnet_id': self.subnets[0]['subnet']['id']})
        mock_raise_on_subnets_overlap.assert_called_once()

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

    def test_create_router_notify(self):
        with mock.patch.object(l3_db.registry, 'publish') as mock_publish:
            router = {'router': {'name': 'foo_router',
                                 'admin_state_up': True,
                                 'tenant_id': 'foo_tenant'}}
            self.create_router(router)
            expected_calls = [
                mock.call(resources.ROUTER, events.BEFORE_CREATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.PRECOMMIT_CREATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.AFTER_CREATE,
                          self.mixin, payload=mock.ANY),
            ]
            mock_publish.assert_has_calls(expected_calls)

    def test_create_router_extra_attr(self):
        router_args = {'router': {'name': 'foo_router',
                                  'admin_state_up': True,
                                  'tenant_id': 'foo_tenant'}
                       }
        router_dict = self.create_router(router_args)
        with db_api.CONTEXT_READER.using(self.ctx) as session:
            r_extra_attrs = session.query(
                l3_attrs.RouterExtraAttributes).filter(
                    l3_attrs.RouterExtraAttributes.router_id ==
                    router_dict['id']).all()
        self.assertEqual(1, len(r_extra_attrs))
        self.assertEqual(router_dict['id'], r_extra_attrs[0].router_id)

    def test_update_router_notify(self):
        with mock.patch.object(l3_db.registry, 'publish') as mock_publish:
            self.mixin.update_router(self.ctx, self.router['id'],
                                     {'router': {'name': 'test1'}})
            expected_calls = [
                mock.call(resources.ROUTER, events.PRECOMMIT_UPDATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.AFTER_UPDATE,
                         self.mixin, payload=mock.ANY),
            ]
            mock_publish.assert_has_calls(expected_calls)

    def _create_external_network(self, name=None, **kwargs):
        name = name or 'network1'
        kwargs[extnet_apidef.EXTERNAL] = True
        with db_api.CONTEXT_WRITER.using(self.ctx):
            res = self._create_network(
                self.fmt, name, True,
                arg_list=(extnet_apidef.EXTERNAL,), **kwargs)
            if res.status_int >= webob.exc.HTTPClientError.code:
                raise webob.exc.HTTPClientError(code=res.status_int)
            return self.deserialize(self.fmt, res)

    def test_update_router_gw_notify(self):
        with mock.patch.object(l3_db.registry, 'publish') as mock_publish:
            ext_net = self._create_external_network()
            self.create_subnet(ext_net, '1.1.2.1', '1.1.2.0/24')
            update_data = {
                l3_apidef.EXTERNAL_GW_INFO: {
                    'network_id': ext_net['network']['id']}}
            self.mixin.update_router(
                self.ctx, self.router['id'], {'router': update_data})
            expected_calls = [
                mock.call(resources.NETWORK, events.BEFORE_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.SEGMENT, events.PRECOMMIT_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.NETWORK, events.PRECOMMIT_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.NETWORK, events.AFTER_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.NETWORK, events.BEFORE_RESPONSE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.SUBNET, events.BEFORE_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.SUBNET, events.AFTER_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.SUBNET, events.BEFORE_RESPONSE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.ROUTER_GATEWAY, events.BEFORE_CREATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.PORT, events.BEFORE_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.PORT, events.PRECOMMIT_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.PORT, events.AFTER_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.ROUTER_GATEWAY, events.AFTER_CREATE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.ROUTER, events.PRECOMMIT_UPDATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.AFTER_UPDATE,
                          self.mixin, payload=mock.ANY)]
            mock_publish.assert_has_calls(expected_calls)
            mock_publish.reset_mock()
            update_data = {l3_apidef.EXTERNAL_GW_INFO: {}}
            self.mixin.update_router(
                self.ctx, self.router['id'], {'router': update_data})
            expected_calls = [
                mock.call(resources.ROUTER_GATEWAY, events.BEFORE_DELETE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.PORT, events.BEFORE_DELETE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.PORT, events.PRECOMMIT_DELETE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.PORT, events.AFTER_DELETE,
                          mock.ANY, payload=mock.ANY),
                mock.call(resources.ROUTER_GATEWAY, events.AFTER_DELETE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.PRECOMMIT_UPDATE,
                          self.mixin, payload=mock.ANY),
                mock.call(resources.ROUTER, events.AFTER_UPDATE,
                          self.mixin, payload=mock.ANY)]
            mock_publish.assert_has_calls(expected_calls)
