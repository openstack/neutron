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
#

import copy
from unittest import mock

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import availability_zone as az_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.api.v2 import router as api_router
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config
from neutron import manager as neutron_manager
from neutron.plugins.ml2 import managers
from neutron.services.ovn_l3 import exceptions as ovn_l3_exc
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_extraroute
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_l3_ext_gw_mode as test_l3_gw
from neutron.tests.unit import fake_resources
from neutron.tests.unit.plugins.ml2 import test_plugin as test_mech_driver


# TODO(mjozefcz): Find out a way to not inherit from
# Ml2PluginV2TestCase.
class TestOVNL3RouterPlugin(test_mech_driver.Ml2PluginV2TestCase):

    _mechanism_drivers = ['ovn']
    l3_plugin = 'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin'

    def _start_mock(self, path, return_value, new_callable=None):
        patcher = mock.patch(path, return_value=return_value,
                             new_callable=new_callable)
        patch = patcher.start()
        self.addCleanup(patcher.stop)
        return patch

    def setUp(self):
        mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                   'impl_idl_ovn.Backend.schema_helper').start()
        cfg.CONF.set_override('max_header_size', 38, group='ml2_type_geneve')
        super(TestOVNL3RouterPlugin, self).setUp()
        revision_plugin.RevisionPlugin()
        # MTU needs to be 1442 instead of 1500 because GENEVE headers size
        # must be at least 38 when using OVN
        network_attrs = {external_net.EXTERNAL: True, 'mtu': 1442}
        self.fake_network = \
            fake_resources.FakeNetwork.create_one_network(
                attrs=network_attrs).info()
        self.fake_router_port = {'device_id': '',
                                 'network_id': self.fake_network['id'],
                                 'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'status': constants.PORT_STATUS_ACTIVE,
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}
        self.fake_router_port_assert = {
            'lrouter': 'neutron-router-id',
            'mac': 'aa:aa:aa:aa:aa:aa',
            'name': 'lrp-router-port-id',
            'may_exist': True,
            'networks': ['10.0.0.100/24'],
            'options': {},
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY: 'subnet-id',
                ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(self.fake_network['id'])}}
        self.fake_router_ports = [self.fake_router_port]
        self.fake_subnet = {'id': 'subnet-id',
                            'ip_version': 4,
                            'cidr': '10.0.0.0/24'}
        self.fake_router = {'id': 'router-id',
                            'name': 'router',
                            'admin_state_up': False,
                            'routes': [{'destination': '1.1.1.0/24',
                                        'nexthop': '10.0.0.2'}]}
        self.fake_router_interface_info = {
            'port_id': 'router-port-id',
            'device_id': '',
            'mac_address': 'aa:aa:aa:aa:aa:aa',
            'subnet_id': 'subnet-id',
            'subnet_ids': ['subnet-id'],
            'fixed_ips': [{'ip_address': '10.0.0.100',
                           'subnet_id': 'subnet-id'}],
            'id': 'router-port-id'}
        self.fake_external_fixed_ips = {
            'network_id': 'ext-network-id',
            'external_fixed_ips': [{'ip_address': '192.168.1.1',
                                    'subnet_id': 'ext-subnet-id'}]}
        self.fake_router_with_ext_gw = {
            'id': 'router-id',
            'name': 'router',
            'admin_state_up': True,
            'external_gateway_info': self.fake_external_fixed_ips,
            'gw_port_id': 'gw-port-id'
        }
        self.fake_router_without_ext_gw = {
            'id': 'router-id',
            'name': 'router',
            'admin_state_up': True,
        }
        self.fake_ext_subnet = {'id': 'ext-subnet-id',
                                'ip_version': 4,
                                'cidr': '192.168.1.0/24',
                                'gateway_ip': '192.168.1.254'}
        self.fake_ext_gw_port = {'device_id': '',
                                 'device_owner': 'network:router_gateway',
                                 'fixed_ips': [{'ip_address': '192.168.1.1',
                                                'subnet_id': 'ext-subnet-id'}],
                                 'mac_address': '00:00:00:02:04:06',
                                 'network_id': self.fake_network['id'],
                                 'id': 'gw-port-id'}
        self.fake_ext_gw_port_assert = {
            'lrouter': 'neutron-router-id',
            'mac': '00:00:00:02:04:06',
            'name': 'lrp-gw-port-id',
            'networks': ['192.168.1.1/24'],
            'may_exist': True,
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY: 'ext-subnet-id',
                ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(self.fake_network['id'])},
            'gateway_chassis': ['hv1'],
            'options': {}}
        self.fake_floating_ip_attrs = {'floating_ip_address': '192.168.0.10',
                                       'fixed_ip_address': '10.0.0.10'}
        self.fake_floating_ip = fake_resources.FakeFloatingIp.create_one_fip(
            attrs=self.fake_floating_ip_attrs)
        self.fake_floating_ip_new_attrs = {
            'router_id': 'new-router-id',
            'floating_ip_address': '192.168.0.10',
            'fixed_ip_address': '10.10.10.10',
            'port_id': 'new-port_id'}
        self.fake_floating_ip_new = (
            fake_resources.FakeFloatingIp.create_one_fip(
                attrs=self.fake_floating_ip_new_attrs))
        self.fake_ovn_nat_rule = (
            fake_resources.FakeOvsdbRow.create_one_ovsdb_row({
                'logical_ip': self.fake_floating_ip['fixed_ip_address'],
                'external_ip': self.fake_floating_ip['floating_ip_address'],
                'type': 'dnat_and_snat',
                'external_ids': {
                    ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
                    ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                        self.fake_floating_ip['port_id'],
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                        self.fake_floating_ip['router_id'])},
            }))
        self.l3_inst = directory.get_plugin(plugin_constants.L3)
        self.lb_id = uuidutils.generate_uuid()
        self.member_subnet = {'id': 'subnet-id',
                              'ip_version': 4,
                              'cidr': '10.0.0.0/24',
                              'network_id': self.fake_network['id']}
        self.member_id = uuidutils.generate_uuid()
        self.member_port_id = uuidutils.generate_uuid()
        self.member_address = '10.0.0.10'
        self.member_l4_port = '80'
        self.member_port = {
            'network_id': self.fake_network['id'],
            'mac_address': 'aa:aa:aa:aa:aa:aa',
            'fixed_ips': [{'ip_address': self.member_address,
                           'subnet_id': self.member_subnet['id']}],
            'id': 'fake-port-id'}
        self.member_lsp = fake_resources.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'addresses': ['10.0.0.10 ff:ff:ff:ff:ff:ff'],
                'uuid': self.member_port['id']})
        self.listener_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.protocol = ['tcp']
        self.ovn_lb.uuid = uuidutils.generate_uuid()
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_l4_port, self.member_subnet['id']))
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
            'enabled': True,
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.lb_vip_lsp = fake_resources.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                                    '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                              self.ovn_lb.uuid)},
                   'name': uuidutils.generate_uuid(),
                   'addresses': ['10.0.0.100 ff:ff:ff:ff:ff:ee'],
                   'uuid': uuidutils.generate_uuid()})
        self.lb_network = fake_resources.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'load_balancer': [self.ovn_lb],
                   'name': 'neutron-%s' % self.fake_network['id'],
                   'ports': [self.lb_vip_lsp, self.member_lsp],
                   'uuid': self.fake_network['id']})
        self.nb_idl = self._start_mock(
            'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin._nb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fake_resources.FakeOvsdbNbOvnIdl())
        self.sb_idl = self._start_mock(
            'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fake_resources.FakeOvsdbSbOvnIdl())
        self._start_mock(
            'neutron.plugins.ml2.plugin.Ml2Plugin.get_network',
            return_value=self.fake_network)
        self.get_port = self._start_mock(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port',
            return_value=self.fake_router_port)
        self.get_subnet = self._start_mock(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet',
            return_value=self.fake_subnet)
        self.get_router = self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router',
            return_value=self.fake_router)
        self._start_mock(
            'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.update_router',
            return_value=self.fake_router)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.remove_router_interface',
            return_value=self.fake_router_interface_info)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_router',
            return_value=self.fake_router_with_ext_gw)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_router',
            return_value={})
        self.mock_candidates = self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.get_candidates_for_scheduling',
            return_value=[])
        self.mock_schedule = self._start_mock(
            'neutron.scheduler.l3_ovn_scheduler.'
            'OVNGatewayLeastLoadedScheduler._schedule_gateway',
            return_value=['hv1'])
        # FIXME(lucasagomes): We shouldn't be mocking the creation of
        # floating IPs here, that makes the FIP to not be registered in
        # the standardattributes table and therefore we also need to mock
        # bump_revision.
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_floatingip',
            return_value=self.fake_floating_ip)
        self._get_floatingip = self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip',
            return_value=self.fake_floating_ip)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.update_floatingip_status',
            return_value=None)
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.update_floatingip_status',
            return_value=None)
        self.bump_rev_p = self._start_mock(
            'neutron.db.ovn_revision_numbers_db.bump_revision',
            return_value=None)
        self.del_rev_p = self._start_mock(
            'neutron.db.ovn_revision_numbers_db.delete_revision',
            return_value=None)
        self.get_rev_p = self._start_mock(
            'neutron.common.ovn.utils.get_revision_number',
            return_value=1)
        self.admin_context = mock.Mock()
        self._start_mock(
            'neutron_lib.context.get_admin_context',
            return_value=self.admin_context)
        self.mock_is_lb_member_fip = mock.patch(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
            '.OVNClient._is_lb_member_fip',
            return_value=False)
        self.mock_is_lb_member_fip.start()
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.delete_mac_binding_entries_by_mac',
            return_value=1)

    def test__plugin_driver(self):
        # No valid mech drivers should raise an exception.
        self._mechanism_drivers = None
        self.l3_inst._plugin.mechanism_manager.mech_drivers = {}
        self.l3_inst._mech = None
        self.assertRaises(n_exc.NotFound, lambda: self.l3_inst._plugin_driver)
        # Populate the mechanism driver map with keys the code under test looks
        # for and validate it finds them.
        fake_mech_driver = mock.MagicMock()
        for driver in ('ovn', 'ovn-sync'):
            self.l3_inst._plugin.mechanism_manager.mech_drivers[
                driver] = fake_mech_driver
            result = self.l3_inst._plugin_driver
            self.l3_inst._plugin.mechanism_manager.mech_drivers.pop(
                driver, None)
            self.assertEqual(fake_mech_driver.obj, result)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface(self, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        func.return_value = self.fake_router_interface_info
        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)
        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=False,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.bump_rev_p.assert_called_once_with(
            mock.ANY, self.fake_router_port,
            ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_update_lrouter_port(self, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        func.return_value = {'id': router_id,
                             'port_id': 'router-port-id',
                             'subnet_id': 'subnet-id1',
                             'subnet_ids': ['subnet-id1'],
                             'fixed_ips': [
                                 {'ip_address': '2001:db8::1',
                                  'subnet_id': 'subnet-id1'},
                                 {'ip_address': '2001:dba::1',
                                  'subnet_id': 'subnet-id2'}],
                             'mac_address': 'aa:aa:aa:aa:aa:aa'
                             }
        self.get_port.return_value = {
            'id': 'router-port-id',
            'fixed_ips': [
                {'ip_address': '2001:db8::1', 'subnet_id': 'subnet-id1'},
                {'ip_address': '2001:dba::1', 'subnet_id': 'subnet-id2'}],
            'mac_address': 'aa:aa:aa:aa:aa:aa',
            'network_id': 'network-id1'}
        fake_rtr_intf_networks = ['2001:db8::1/24', '2001:dba::1/24']
        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)
        called_args_dict = (
            self.l3_inst._nb_ovn.update_lrouter_port.call_args_list[0][1])

        self.assertEqual(1,
                         self.l3_inst._nb_ovn.update_lrouter_port.call_count)
        self.assertCountEqual(fake_rtr_intf_networks,
                              called_args_dict.get('networks', []))
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=False,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)

    def test_remove_router_interface(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.get_port.side_effect = n_exc.PortNotFound(
                                        port_id='router-port-id')

        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_inst._nb_ovn.lrp_del.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=True)
        self.del_rev_p.assert_called_once_with(
            self.context, 'router-port-id', ovn_const.TYPE_ROUTER_PORTS)

    def test_remove_router_interface_update_lrouter_port(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_inst._nb_ovn.update_lrouter_port.assert_called_once_with(
            if_exists=False, name='lrp-router-port-id',
            ipv6_ra_configs={},
            networks=['10.0.0.100/24'],
            options={},
            external_ids={
                ovn_const.OVN_SUBNET_EXT_IDS_KEY: 'subnet-id',
                ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(self.fake_network['id'])})

    def test_remove_router_interface_router_not_found(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.get_port.side_effect = n_exc.PortNotFound(
                                        port_id='router-port-id')
        self.get_router.side_effect = l3_exc.RouterNotFound(
            router_id='router-id')

        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.get_router.assert_called_once_with(self.context, 'router-id')
        self.l3_inst._nb_ovn.lrp_del.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=True)
        self.del_rev_p.assert_called_once_with(
            self.context, 'router-port-id', ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb'
                '.ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_update_router_admin_state_change(self, get_rps, func):
        router_id = 'router-id'
        new_router = self.fake_router.copy()
        updated_data = {'admin_state_up': True}
        new_router.update(updated_data)
        func.return_value = new_router
        self.l3_inst.update_router(self.context, router_id,
                                   {'router': updated_data})
        self.l3_inst._nb_ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=True, external_ids={
                ovn_const.OVN_GW_PORT_EXT_ID_KEY: '',
                ovn_const.OVN_GW_NETWORK_EXT_ID_KEY: '',
                ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router',
                ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: ''})

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_update_router_name_change(self, get_rps, func):
        router_id = 'router-id'
        new_router = self.fake_router.copy()
        updated_data = {'name': 'test'}
        new_router.update(updated_data)
        func.return_value = new_router
        self.l3_inst.update_router(self.context, router_id,
                                   {'router': updated_data})
        self.l3_inst._nb_ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=False,
            external_ids={ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'test',
                          ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                          ovn_const.OVN_GW_PORT_EXT_ID_KEY: '',
                          ovn_const.OVN_GW_NETWORK_EXT_ID_KEY: '',
                          ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: ''})

    @mock.patch.object(utils, 'get_lrouter_non_gw_routes')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb'
                '.ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_update_router_static_route_no_change(self, get_rps, get_r, func,
                                                  mock_routes):
        router_id = 'router-id'
        get_rps.return_value = [{'device_id': '',
                                'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}]
        mock_routes.return_value = self.fake_router['routes']
        update_data = {'router': {'routes': [{'destination': '1.1.1.0/24',
                                              'nexthop': '10.0.0.2'}]}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_inst._nb_ovn.add_static_route.called)
        self.assertFalse(self.l3_inst._nb_ovn.delete_static_route.called)

    @mock.patch.object(utils, 'get_lrouter_non_gw_routes')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_update_router_static_route_change(self, get_rps, func,
                                               mock_routes):
        router_id = 'router-id'
        get_rps.return_value = [{'device_id': '',
                                'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}]

        mock_routes.return_value = self.fake_router['routes']
        new_router = self.fake_router.copy()
        updated_data = {'routes': [{'destination': '2.2.2.0/24',
                                    'nexthop': '10.0.0.3'}]}
        new_router.update(updated_data)
        func.return_value = new_router
        self.l3_inst.update_router(self.context, router_id,
                                   {'router': updated_data})
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='2.2.2.0/24', nexthop='10.0.0.3')
        self.l3_inst._nb_ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='10.0.0.2')

    @mock.patch.object(utils, 'get_lrouter_non_gw_routes')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_update_router_static_route_clear(self, get_rps, func,
                                              mock_routes):
        router_id = 'router-id'
        get_rps.return_value = [{'device_id': '',
                                 'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}]

        mock_routes.return_value = self.fake_router['routes']
        new_router = self.fake_router.copy()
        updated_data = {'routes': []}
        new_router.update(updated_data)
        func.return_value = new_router
        self.l3_inst.update_router(self.context, router_id,
                                   {'router': updated_data})
        self.l3_inst._nb_ovn.add_static_route.assert_not_called()
        self.l3_inst._nb_ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='10.0.0.2')

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    def test_create_router_with_ext_gw(self, get_rps):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        router = {'router': {'name': 'router'}}
        self.get_subnet.return_value = self.fake_ext_subnet
        self.get_port.return_value = self.fake_ext_gw_port
        get_rps.return_value = self.fake_ext_subnet['cidr']

        self.l3_inst.create_router(self.context, router)

        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router',
                        ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                        ovn_const.OVN_GW_PORT_EXT_ID_KEY: 'gw-port-id',
                        ovn_const.OVN_GW_NETWORK_EXT_ID_KEY: 'ext-network-id',
                        ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: ''}
        self.l3_inst._nb_ovn.create_lrouter.assert_called_once_with(
            'neutron-router-id', external_ids=external_ids,
            enabled=True, options={'always_learn_from_arp_request': 'false',
                                   'dynamic_neigh_routers': 'true'})
        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        expected_calls = [
            mock.call('neutron-router-id', ip_prefix='0.0.0.0/0',
                      nexthop='192.168.1.254',
                      external_ids={
                          ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet-id'})]
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'gw-port-id', 'lrp-gw-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_static_route.assert_has_calls(expected_calls)

        bump_rev_calls = [mock.call(mock.ANY, self.fake_ext_gw_port,
                                    ovn_const.TYPE_ROUTER_PORTS),
                          mock.call(mock.ANY,
                                    self.fake_router_with_ext_gw,
                                    ovn_const.TYPE_ROUTERS),
                          ]

        self.assertEqual(len(bump_rev_calls), self.bump_rev_p.call_count)
        self.bump_rev_p.assert_has_calls(bump_rev_calls, any_order=False)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    def test_delete_router_with_ext_gw(self, gprs):
        self.get_router.return_value = self.fake_router_with_ext_gw
        self.get_subnet.return_value = self.fake_ext_subnet
        self.l3_inst._nb_ovn.get_lrouter.return_value = (
            fake_resources.FakeOVNRouter.from_neutron_router(
                self.fake_router_with_ext_gw))

        self.l3_inst.delete_router(self.context, 'router-id')

        self.l3_inst._nb_ovn.delete_lrouter.assert_called_once_with(
            'neutron-router-id')

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set(self, ari, grps):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = self.fake_router_interface_info
        self.get_router.return_value = self.fake_router_with_ext_gw

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=False,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')
        self.bump_rev_p.assert_called_with(
            mock.ANY, self.fake_router_port,
            ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set_and_snat_disabled(
            self, ari, grps):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = self.fake_router_interface_info
        get_router = self.fake_router_with_ext_gw
        get_router['external_gateway_info']['enable_snat'] = False
        self.get_router.return_value = get_router

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=False,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_network')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_vlan_network(self, ari, grps, gn):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = self.fake_router_interface_info
        self.get_router.return_value = self.fake_router_with_ext_gw

        # Set the type to be VLAN
        fake_network_vlan = self.fake_network
        fake_network_vlan[pnet.NETWORK_TYPE] = constants.TYPE_VLAN
        gn.return_value = fake_network_vlan

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        # Make sure that the "reside-on-redirect-chassis" option was
        # set to the new router port
        fake_router_port_assert = self.fake_router_port_assert
        fake_router_port_assert['options'] = {
            'reside-on-redirect-chassis': 'true'}

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **fake_router_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=False,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')

        self.bump_rev_p.assert_called_with(
            mock.ANY, self.fake_router_port,
            ovn_const.TYPE_ROUTER_PORTS)

    def test_remove_router_interface_with_gateway_set(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id',
                          'subnet_id': 'subnet-id'}
        self.get_router.return_value = self.fake_router_with_ext_gw
        self.get_port.side_effect = n_exc.PortNotFound(
                                        port_id='router-port-id')
        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.lrp_del.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=True)
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')
        self.del_rev_p.assert_called_with(
            self.context, 'router-port-id', ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_update_router_with_ext_gw(self, ur, grps):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        router = {'router': {'name': 'router'}}
        self.get_router.return_value = self.fake_router_without_ext_gw
        ur.return_value = self.fake_router_with_ext_gw
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'gw-port-id', 'lrp-gw-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            external_ids={ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet-id'},
            nexthop='192.168.1.254')
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat',
            logical_ip='10.0.0.0/24', external_ip='192.168.1.1')
        self.bump_rev_p.assert_called_with(
            mock.ANY, self.fake_ext_gw_port,
            ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch.object(utils, 'get_lrouter_ext_gw_static_route')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_update_router_ext_gw_change_subnet(self, ur,
                                                grps, mock_get_gw):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        mock_get_gw.return_value = [mock.sentinel.GwRoute]
        router = {'router': {'name': 'router'}}
        fake_old_ext_subnet = {'id': 'old-ext-subnet-id',
                               'ip_version': 4,
                               'cidr': '192.168.2.0/24',
                               'gateway_ip': '192.168.2.254'}
        # Old gateway info with same network and different subnet
        self.get_router.return_value = copy.copy(self.fake_router_with_ext_gw)
        self.get_router.return_value['external_gateway_info'] = {
            'network_id': 'ext-network-id',
            'external_fixed_ips': [{'ip_address': '192.168.2.1',
                                    'subnet_id': 'old-ext-subnet-id'}]}
        self.get_router.return_value['gw_port_id'] = 'old-gw-port-id'
        ur.return_value = self.fake_router_with_ext_gw
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet,
            'old-ext-subnet-id': fake_old_ext_subnet}.get(sid,
                                                          self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Check deleting old router gateway
        self.l3_inst._nb_ovn.delete_lrouter_ext_gw.assert_called_once_with(
            'neutron-router-id')

        # Check adding new router gateway
        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'gw-port-id', 'lrp-gw-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254',
            external_ids={ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet-id'})
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')

        self.bump_rev_p.assert_called_with(
            mock.ANY, self.fake_ext_gw_port,
            ovn_const.TYPE_ROUTER_PORTS)
        self.del_rev_p.assert_called_once_with(
            mock.ANY, 'old-gw-port-id', ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch.object(utils, 'get_lrouter_ext_gw_static_route')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
                'OVNClient._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_update_router_ext_gw_change_ip_address(self, ur,
                                                    grps, mock_get_gw):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        mock_get_gw.return_value = [mock.sentinel.GwRoute]
        router = {'router': {'name': 'router'}}
        # Old gateway info with same subnet and different ip address
        gr_value = copy.deepcopy(self.fake_router_with_ext_gw)
        gr_value['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address'] = '192.168.1.2'
        gr_value['gw_port_id'] = 'old-gw-port-id'
        self.get_router.return_value = gr_value
        ur.return_value = self.fake_router_with_ext_gw
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Check deleting old router gateway
        self.l3_inst._nb_ovn.delete_lrouter_ext_gw.assert_called_once_with(
            'neutron-router-id')
        # Check adding new router gateway
        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'gw-port-id', 'lrp-gw-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254',
            external_ids={ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet-id'})
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_v4_network_of_all_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_update_router_ext_gw_no_change(self, ur, get_rps):
        router = {'router': {'name': 'router'}}
        nb_ovn = self.l3_inst._nb_ovn
        self.get_router.return_value = self.fake_router_with_ext_gw
        ur.return_value = self.fake_router_with_ext_gw
        nb_ovn.get_lrouter.return_value = (
            fake_resources.FakeOVNRouter.from_neutron_router(
                self.fake_router_with_ext_gw))

        self.l3_inst.update_router(self.context, 'router-id', router)

        nb_ovn.lrp_del.assert_not_called()
        nb_ovn.delete_static_route.assert_not_called()
        nb_ovn.delete_nat_rule_in_lrouter.assert_not_called()
        nb_ovn.add_lrouter_port.assert_not_called()
        nb_ovn.set_lrouter_port_in_lswitch_port.assert_not_called()
        nb_ovn.add_static_route.assert_not_called()
        nb_ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_v4_network_of_all_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_update_router_with_ext_gw_and_disabled_snat(self, ur, grps):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        router = {'router': {'name': 'router'}}
        self.get_router.return_value = self.fake_router_without_ext_gw
        ur.return_value = self.fake_router_with_ext_gw
        ur.return_value['external_gateway_info']['enable_snat'] = False
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Need not check lsp and lrp here, it has been tested in other cases
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            external_ids={ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                          ovn_const.OVN_SUBNET_EXT_ID_KEY: 'ext-subnet-id'},
            nexthop='192.168.1.254')
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client'
                '.OVNClient._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_enable_snat(self, ur, grps):
        router = {'router': {'name': 'router'}}
        gr_value = copy.deepcopy(self.fake_router_with_ext_gw)
        gr_value['external_gateway_info']['enable_snat'] = False
        self.get_router.return_value = gr_value
        ur.return_value = self.fake_router_with_ext_gw
        self.l3_inst._nb_ovn.get_lrouter.return_value = (
            fake_resources.FakeOVNRouter.from_neutron_router(
                self.fake_router_with_ext_gw))
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._nb_ovn.delete_static_route.assert_not_called()
        self.l3_inst._nb_ovn.delete_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._nb_ovn.add_static_route.assert_not_called()
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._check_external_ips_changed')
    @mock.patch.object(utils, 'get_lrouter_snats')
    @mock.patch.object(utils, 'get_lrouter_ext_gw_static_route')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    def test_disable_snat(self, ur, grps, mock_get_gw, mock_snats,
                          mock_ext_ips):
        mock_get_gw.return_value = [mock.sentinel.GwRoute]
        mock_snats.return_value = [mock.sentinel.NAT]
        mock_ext_ips.return_value = False
        router = {'router': {'name': 'router'}}
        self.get_router.return_value = self.fake_router_with_ext_gw
        ur.return_value = copy.deepcopy(self.fake_router_with_ext_gw)
        ur.return_value['external_gateway_info']['enable_snat'] = False
        self.get_subnet.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        self.get_port.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.delete_static_route.assert_not_called()
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')
        nb_ovn.add_static_route.assert_not_called()
        nb_ovn.add_nat_rule_in_lrouter.assert_not_called()

    def test_create_floatingip(self):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self._get_floatingip.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    def test_create_floatingip_distributed(self):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.get_port.return_value = {'mac_address': '00:01:02:03:04:05',
                                      'network_id': 'port-network-id'}
        self._get_floatingip.return_value = {'floating_port_id': 'fip-port-id'}
        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: '00:01:02:03:04:05',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='dnat_and_snat', logical_ip='10.0.0.10',
            external_ip='192.168.0.10', external_mac='00:01:02:03:04:05',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    def test_create_floatingip_distributed_logical_port_down(self):
        # Check that when the port is down, the external_mac field is not
        # populated. This falls back to centralized routing for ports that
        # are not bound to a chassis.
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.l3_inst._nb_ovn.lsp_get_up.return_value.execute.return_value = (
            False)
        self.get_port.return_value = {'mac_address': '00:01:02:03:04:05'}
        self._get_floatingip.return_value = {'floating_port_id': 'fip-port-id'}
        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: '00:01:02:03:04:05',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='dnat_and_snat', logical_ip='10.0.0.10',
            external_ip='192.168.0.10',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    def test_create_floatingip_external_ip_present_in_nat_rule(self):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self._get_floatingip.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst._nb_ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.6',
             'type': 'dnat_and_snat', 'uuid': 'uuid1'}]
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    def test_create_floatingip_external_ip_present_type_snat(self):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self._get_floatingip.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst._nb_ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.0/24',
             'type': 'snat', 'uuid': 'uuid1'}]
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        self.l3_inst._nb_ovn.set_nat_rule_in_lrouter.assert_not_called()
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    def test_create_floatingip_lsp_external_id(self):
        foo_lport = fake_resources.FakeOvsdbRow.create_one_ovsdb_row()
        foo_lport.uuid = 'foo-port'
        self.l3_inst._nb_ovn.get_lswitch_port.return_value = foo_lport
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        calls = [mock.call(
            'Logical_Switch_Port',
            'foo-port',
            ('external_ids', {ovn_const.OVN_PORT_FIP_EXT_ID_KEY:
                              '192.168.0.10'}))]
        self.l3_inst._nb_ovn.db_set.assert_has_calls(calls)

    def test_create_floatingip_lb_member_fip(self):
        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        # Stop this mock.
        self.mock_is_lb_member_fip.stop()
        self.get_port.return_value = self.member_port
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.l3_inst._nb_ovn.lookup.return_value = self.lb_network
        self.l3_inst._nb_ovn.get_lswitch_port.return_value = self.member_lsp
        fip = self.l3_inst.create_floatingip(self.context, 'floatingip')
        # Validate that there is no external_mac and logical_port while
        # setting the NAT entry.
        expected_ext_ids = {
              ovn_const.OVN_FIP_EXT_ID_KEY: fip['id'],
              ovn_const.OVN_REV_NUM_EXT_ID_KEY: mock.ANY,
              ovn_const.OVN_FIP_PORT_EXT_ID_KEY: fip['port_id'],
              ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'neutron-router-id',
              ovn_const.OVN_FIP_EXT_MAC_KEY: self.member_port['mac_address'],
              ovn_const.OVN_FIP_NET_ID: fip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            external_ip='192.168.0.10',
            logical_ip='10.0.0.10',
            type='dnat_and_snat',
            external_ids=expected_ext_ids)

    def test_create_floatingip_lb_vip_fip(self):
        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        self.get_subnet.return_value = self.member_subnet
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.l3_inst._nb_ovn.get_lswitch_port.return_value = self.lb_vip_lsp
        self.l3_inst._nb_ovn.db_find_rows.return_value.execute.side_effect = [
            [self.ovn_lb],
            [self.lb_network],
            [self.fake_ovn_nat_rule],
        ]
        self.l3_inst._nb_ovn.lookup.return_value = self.lb_network
        fip = self.l3_inst.create_floatingip(self.context, 'floatingip')
        expected_ext_ids = {
              ovn_const.OVN_FIP_EXT_ID_KEY: fip['id'],
              ovn_const.OVN_REV_NUM_EXT_ID_KEY: mock.ANY,
              ovn_const.OVN_FIP_PORT_EXT_ID_KEY: fip['port_id'],
              ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'neutron-router-id',
              ovn_const.OVN_FIP_EXT_MAC_KEY: self.member_port['mac_address'],
              ovn_const.OVN_FIP_NET_ID: fip['floating_network_id']}

        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            external_ip='192.168.0.10',
            external_mac='aa:aa:aa:aa:aa:aa',
            logical_ip='10.0.0.10',
            logical_port='port_id',
            type='dnat_and_snat',
            external_ids=expected_ext_ids)
        self.l3_inst._nb_ovn.db_find_rows.assert_called_with(
            'NAT', ('external_ids', '=', {ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                                          self.member_lsp.name}))
        # Validate that it clears external_mac/logical_port for member NAT.
        self.l3_inst._nb_ovn.db_clear.assert_has_calls([
            mock.call('NAT', self.fake_ovn_nat_rule.uuid, 'external_mac'),
            mock.call('NAT', self.fake_ovn_nat_rule.uuid, 'logical_port')])

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip(self, df):
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        self.l3_inst.delete_floatingip(self.context, 'floatingip-id')
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip_lb_vip_fip(self, df):
        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        self.get_subnet.return_value = self.member_subnet
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        nb_ovn.get_lswitch_port.return_value = self.lb_vip_lsp
        nb_ovn.db_find_rows.return_value.execute.side_effect = [
            [self.ovn_lb],
            [self.lb_network],
            [self.fake_ovn_nat_rule],
        ]
        nb_ovn.lookup.return_value = self.lb_network

        self.l3_inst.delete_floatingip(self.context, 'floatingip-id')
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        nb_ovn.db_find_rows.assert_called_with(
            'NAT', ('external_ids', '=',
                    {ovn_const.OVN_FIP_PORT_EXT_ID_KEY: self.member_lsp.name}))
        self.l3_inst._plugin.get_port.assert_called_once_with(
            mock.ANY, self.member_lsp.name)
        # Validate that it adds external_mac/logical_port back.
        nb_ovn.db_set.assert_has_calls([
            mock.call('NAT', self.fake_ovn_nat_rule.uuid,
                      ('logical_port', self.member_lsp.name)),
            mock.call('NAT', self.fake_ovn_nat_rule.uuid,
                      ('external_mac', 'aa:aa:aa:aa:aa:aa'))])

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip_lsp_external_id(self, df):
        self.l3_inst._nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)

        foo_lport = fake_resources.FakeOvsdbRow.create_one_ovsdb_row()
        foo_lport.uuid = 'foo-port'
        foo_lport.external_ids = {
            ovn_const.OVN_PORT_FIP_EXT_ID_KEY: 'foo-port'}
        self.l3_inst._nb_ovn.get_lswitch_port.return_value = foo_lport

        self.l3_inst.delete_floatingip(self.context, 'floatingip-id')
        calls = [mock.call(
            'Logical_Switch_Port', 'foo-port',
            'external_ids', ovn_const.OVN_PORT_FIP_EXT_ID_KEY)]
        self.l3_inst._nb_ovn.db_remove.assert_has_calls(calls)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip_no_lsp_external_id(self, df):
        self.l3_inst._nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        self.l3_inst._nb_ovn.get_lswitch_port.return_value = None
        self.l3_inst.delete_floatingip(self.context, 'floatingip-id')
        self.l3_inst._nb_ovn.db_remove.assert_not_called()

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip(self, uf):
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.is_col_present.return_value = True
        uf.return_value = self.fake_floating_ip_new
        nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip_new['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip_new['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip_new['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10',
            logical_port='new-port_id',
            external_ids=expected_ext_ids)

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_associate(self, uf):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.fake_floating_ip.update({'fixed_port_id': None})
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        self.l3_inst._nb_ovn.delete_nat_rule_in_lrouter.assert_not_called()
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip_new['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip_new['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip_new['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10',
            logical_port='new-port_id',
            external_ids=expected_ext_ids)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_network')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_associate_distributed(self, uf, gn):
        self.l3_inst._nb_ovn.is_col_present.return_value = True
        self.fake_floating_ip.update({'fixed_port_id': None})
        self.get_port.return_value = {'mac_address': '00:01:02:03:04:05',
                                      'network_id': 'port-network-id'}
        uf.return_value = self.fake_floating_ip_new

        fake_network_vlan = self.fake_network
        fake_network_vlan[pnet.NETWORK_TYPE] = constants.TYPE_FLAT
        gn.return_value = fake_network_vlan

        config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        self.l3_inst._nb_ovn.delete_nat_rule_in_lrouter.assert_not_called()
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip_new['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip_new['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip_new['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: '00:01:02:03:04:05',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id', type='dnat_and_snat',
            logical_ip='10.10.10.10', external_ip='192.168.0.10',
            external_mac='00:01:02:03:04:05', logical_port='new-port_id',
            external_ids=expected_ext_ids)

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_association_empty_update(self, uf):
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.is_col_present.return_value = True
        nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        self.fake_floating_ip.update({'fixed_port_id': 'foo'})
        self.fake_floating_ip_new.update({'port_id': 'foo'})
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip_new['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip_new['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip_new['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10',
            logical_port='foo',
            external_ids=expected_ext_ids)

    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_reassociate_to_same_port_diff_fixed_ip(
            self, uf):
        nb_ovn = self.l3_inst._nb_ovn
        nb_ovn.is_col_present.return_value = True
        nb_ovn.get_floatingip.return_value = (
            self.fake_ovn_nat_rule)
        self.fake_floating_ip_new.update({'port_id': 'port_id',
                                          'fixed_port_id': 'port_id'})
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')

        nb_ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        expected_ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: self.fake_floating_ip_new['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY:
                self.fake_floating_ip_new['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: utils.ovn_name(
                self.fake_floating_ip_new['router_id']),
            ovn_const.OVN_FIP_EXT_MAC_KEY: 'aa:aa:aa:aa:aa:aa',
            ovn_const.OVN_FIP_NET_ID:
                self.fake_floating_ip['floating_network_id']}
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10',
            logical_port='port_id',
            external_ids=expected_ext_ids)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_floatingips')
    def test_disassociate_floatingips(self, gfs):
        gfs.return_value = [{'id': 'fip-id1',
                             'floating_ip_address': '192.168.0.10',
                             'router_id': 'router-id',
                             'port_id': 'port_id',
                             'floating_port_id': 'fip-port-id1',
                             'fixed_ip_address': '10.0.0.10',
                             'floating_network_id': 'net1'},
                            {'id': 'fip-id2',
                             'floating_ip_address': '192.167.0.10',
                             'router_id': 'router-id',
                             'port_id': 'port_id',
                             'floating_port_id': 'fip-port-id2',
                             'fixed_ip_address': '10.0.0.11',
                             'floating_network_id': 'net2'}]
        self.l3_inst.disassociate_floatingips(self.context, 'port_id',
                                              do_notify=False)

        delete_nat_calls = [mock.call('neutron-router-id',
                                      type='dnat_and_snat',
                                      logical_ip=fip['fixed_ip_address'],
                                      external_ip=fip['floating_ip_address'])
                            for fip in gfs.return_value]
        self.assertEqual(
            len(delete_nat_calls),
            self.l3_inst._nb_ovn.delete_nat_rule_in_lrouter.call_count)
        self.l3_inst._nb_ovn.delete_nat_rule_in_lrouter.assert_has_calls(
            delete_nat_calls, any_order=True)

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient.update_router_port')
    def test_port_update_postcommit(self, update_rp_mock):
        context = 'fake_context'
        port = {'device_owner': 'foo'}
        self.l3_inst._port_update(resources.PORT, events.AFTER_UPDATE, None,
                                  payload=events.DBEventPayload(
                                      context,
                                      states=(port,)))
        update_rp_mock.assert_not_called()

        port = {'device_owner': constants.DEVICE_OWNER_ROUTER_INTF}
        self.l3_inst._port_update(resources.PORT, events.AFTER_UPDATE, None,
                                  payload=events.DBEventPayload(
                                      context,
                                      states=(port,)))

        update_rp_mock.assert_called_once_with(context,
                                               port,
                                               if_exists=True)

    def test_port_update_before_update_router_port_without_ip(self):
        context = 'fake_context'
        port = {'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
                'fixed_ips': [],
                'id': 'port-id'}
        self.assertRaises(
            n_exc.ServicePortInUse,
            self.l3_inst._port_update,
            resources.PORT,
            events.BEFORE_UPDATE,
            None,
            payload=events.DBEventPayload(
                                        context,
                                        states=(port,))
        )

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.update_port_status')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.update_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    def test_update_router_gateway_port_bindings_active(
            self, mock_get_port, mock_updt_port, mock_updt_status):
        fake_host = 'fake-host'
        fake_router = 'fake-router'
        fake_port_id = 'fake-port-id'
        mock_get_port.return_value = [{
            'id': fake_port_id,
            'status': constants.PORT_STATUS_DOWN}]
        mock_updt_port.return_value = {
            'id': fake_port_id,
            'status': constants.PORT_STATUS_DOWN
        }
        self.l3_inst.update_router_gateway_port_bindings(
            fake_router, fake_host)

        # Assert that the port is being bound
        expected_update = {'port': {portbindings.HOST_ID: fake_host}}
        mock_updt_port.assert_called_once_with(
            mock.ANY, fake_port_id, expected_update)

        # Assert that the port status is being set to ACTIVE
        mock_updt_status.assert_called_once_with(
            mock.ANY, fake_port_id, constants.PORT_STATUS_ACTIVE)

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.update_port_status')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    def test_update_router_gateway_port_bindings_down(
            self, mock_get_port, mock_updt_status):
        fake_port_id = 'fake-port-id'
        mock_get_port.return_value = [{
            'id': fake_port_id,
            'status': constants.PORT_STATUS_ACTIVE}]
        self.l3_inst.update_router_gateway_port_bindings(None, None)

        # Assert that the port status is being set to DOWN
        mock_updt_status.assert_called_once_with(
            mock.ANY, fake_port_id, constants.PORT_STATUS_DOWN)

    @mock.patch('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin.'
                '_get_gateway_port_physnet_mapping')
    def test_schedule_unhosted_gateways_no_gateways(self, get_gppm):
        get_gppm.return_value = {}
        self.nb_idl().get_unhosted_gateways.return_value = []
        self.l3_inst.schedule_unhosted_gateways()
        self.nb_idl().update_lrouter_port.assert_not_called()

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.mech_driver.'
                'OVNMechanismDriver.list_availability_zones', lambda *_: [])
    @mock.patch('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin.'
                '_get_gateway_port_physnet_mapping')
    def test_schedule_unhosted_gateways(self, get_gppm):
        unhosted_gws = ['lrp-foo-1', 'lrp-foo-2', 'lrp-foo-3']
        get_gppm.return_value = {k[len(ovn_const.LRP_PREFIX):]: 'physnet1'
                                 for k in unhosted_gws}
        chassis_mappings = {
            'chassis1': ['physnet1'],
            'chassis2': ['physnet1'],
            'chassis3': ['physnet1']}
        chassis = ['chassis1', 'chassis2', 'chassis3']
        self.sb_idl().get_chassis_and_physnets.return_value = (
            chassis_mappings)
        self.sb_idl().get_gateway_chassis_from_cms_options.return_value = (
            chassis)
        self.nb_idl().get_unhosted_gateways.return_value = unhosted_gws
        # 1. port has 2 gateway chassis
        # 2. port has only chassis2
        # 3. port is not bound
        existing_port_bindings = [
            ['chassis1', 'chassis2'],
            ['chassis2'],
            []]
        self.nb_idl().get_gateway_chassis_binding.side_effect = (
            existing_port_bindings)
        # for 1. port schedule untouched, add only 3'rd chassis
        # for 2. port primary scheduler somewhere else
        # for 3. port schedule all
        self.mock_schedule.side_effect = [
            ['chassis1', 'chassis2', 'chassis3'],
            ['chassis1', 'chassis2', 'chassis3'],
            ['chassis3', 'chassis2', 'chassis1']]

        self.l3_inst.schedule_unhosted_gateways()

        self.mock_candidates.assert_has_calls([
            mock.call(mock.ANY,
                      chassis_physnets=chassis_mappings,
                      cms=chassis, availability_zone_hints=[])] * 3)
        self.mock_schedule.assert_has_calls([
            mock.call(self.nb_idl(), self.sb_idl(),
                      'lrp-foo-1', [], ['chassis1', 'chassis2']),
            mock.call(self.nb_idl(), self.sb_idl(),
                      'lrp-foo-2', [], ['chassis2']),
            mock.call(self.nb_idl(), self.sb_idl(),
                      'lrp-foo-3', [], [])])
        # make sure that for second port primary chassis stays untouched
        self.nb_idl().update_lrouter_port.assert_has_calls([
            mock.call('lrp-foo-1',
                      gateway_chassis=['chassis1', 'chassis2', 'chassis3']),
            mock.call('lrp-foo-2',
                      gateway_chassis=['chassis2', 'chassis1', 'chassis3']),
            mock.call('lrp-foo-3',
                      gateway_chassis=['chassis3', 'chassis2', 'chassis1'])])

    @mock.patch('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin.'
                '_get_gateway_port_physnet_mapping')
    def test_schedule_unhosted_gateways_on_event_no_gw_chassis(self, get_gppm):
        unhosted_gws = ['lrp-foo-1', 'lrp-foo-2', 'lrp-foo-3']
        get_gppm.return_value = {k[len(ovn_const.LRP_PREFIX):]: 'physnet1'
                                 for k in unhosted_gws}
        self.nb_idl().get_chassis_gateways.return_value = []
        self.l3_inst.schedule_unhosted_gateways(event_from_chassis='chassis4')
        self.nb_idl().get_unhosted_gateways.assert_not_called()

    @mock.patch('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin.'
                '_get_gateway_port_physnet_mapping')
    def test_schedule_unhosted_gateways_on_event(self, get_gppm):
        unhosted_gws = ['lrp-foo-1', 'lrp-foo-2', 'lrp-foo-3']
        get_gppm.return_value = {k[len(ovn_const.LRP_PREFIX):]: 'physnet1'
                                 for k in unhosted_gws}
        foo_gw = fake_resources.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lrp-foo-1_chassis1',
                   'chassis_name': 'chassis1'})
        self.nb_idl().get_chassis_gateways.return_value = [
            foo_gw]
        self.nb_idl().get_unhosted_gateways.return_value = []
        # Fake that rescheduling is executed on chassis event
        self.l3_inst.schedule_unhosted_gateways(event_from_chassis='chassis1')
        # Validate that only foo-1 port is beign rescheduled.
        self.nb_idl().get_unhosted_gateways.assert_called_once_with(
            {'foo-1': 'physnet1'}, mock.ANY, mock.ANY, mock.ANY)

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_network')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_networks')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_need_to_frag_enabled(
            self, ari, grps, gns, gn):
        config.cfg.CONF.set_override(
            'ovn_emit_need_to_frag', True, group='ovn')
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id',
                'network_id': 'priv-net'}
        ari.return_value = self.fake_router_interface_info
        grps.return_value = [interface_info]
        self.get_router.return_value = self.fake_router_with_ext_gw
        network_attrs = {'id': 'prov-net', 'mtu': 1200}
        prov_net = fake_resources.FakeNetwork.create_one_network(
                attrs=network_attrs).info()
        self.fake_router_port['device_owner'] = (
            constants.DEVICE_OWNER_ROUTER_GW)
        gn.return_value = prov_net
        gns.return_value = [self.fake_network]

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        # Make sure that the "gateway_mtu" option was set to the router port
        fake_router_port_assert = self.fake_router_port_assert
        fake_router_port_assert['gateway_chassis'] = mock.ANY
        fake_router_port_assert['options'] = {
            ovn_const.OVN_ROUTER_PORT_GW_MTU_OPTION:
            str(prov_net['mtu'])}

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **fake_router_port_assert)
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)
        self.l3_inst._nb_ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')

        self.bump_rev_p.assert_called_with(
            mock.ANY, self.fake_router_port,
            ovn_const.TYPE_ROUTER_PORTS)

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_network')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_networks')
    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
                'ovn_client.OVNClient._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_need_to_frag_enabled_then_remove(
            self, ari, grps, gns, gn):
        config.cfg.CONF.set_override(
            'ovn_emit_need_to_frag', True, group='ovn')
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id',
                'network_id': 'priv-net'}
        ari.return_value = self.fake_router_interface_info
        # If we remove the router halfway the return value of
        # _get_routers_ports will be RouterNotFound
        grps.side_effect = l3_exc.RouterNotFound(router_id=router_id)
        self.get_router.return_value = self.fake_router_with_ext_gw
        network_attrs = {'id': 'prov-net', 'mtu': 1200}
        prov_net = fake_resources.FakeNetwork.create_one_network(
                attrs=network_attrs).info()
        self.fake_router_port['device_owner'] = (
            constants.DEVICE_OWNER_ROUTER_GW)
        gn.return_value = prov_net
        gns.return_value = [self.fake_network]

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        # Make sure that the "gateway_mtu" option was set to the router port
        fake_router_port_assert = self.fake_router_port_assert
        fake_router_port_assert['gateway_chassis'] = mock.ANY
        fake_router_port_assert['options'] = {}

        self.l3_inst._nb_ovn.add_lrouter_port.assert_called_once_with(
            **fake_router_port_assert)
        # Since if_exists = True it will safely return
        self.l3_inst._nb_ovn.lrp_set_options(
            name='lrp-router-port-id', if_exists=True,
            options=fake_router_port_assert)
        # If no if_exists is provided, it is defaulted to true, so this
        # operation is safe.
        self.l3_inst._nb_ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with(
                'router-port-id', 'lrp-router-port-id', is_gw_port=True,
                lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER)

    def _test_get_router_availability_zones(self, azs, expected):
        lr = fake_resources.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'id': 'fake-router', 'external_ids': {
                ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: azs}})
        self.l3_inst._nb_ovn.get_lrouter.return_value = lr
        azs_list = self.l3_inst.get_router_availability_zones(lr)
        self.assertEqual(sorted(expected), sorted(azs_list))

    def test_get_router_availability_zones_one(self):
        self._test_get_router_availability_zones('az0', ['az0'])

    def test_get_router_availability_zones_multiple(self):
        self._test_get_router_availability_zones(
            'az0,az1,az2', ['az0', 'az1', 'az2'])

    def test_get_router_availability_zones_none(self):
        self._test_get_router_availability_zones('', [])

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.mech_driver.'
                'OVNMechanismDriver.list_availability_zones')
    def test_validate_availability_zones(self, mock_list_azs):
        mock_list_azs.return_value = {'az0': {'name': 'az0'},
                                      'az1': {'name': 'az1'},
                                      'az2': {'name': 'az2'}}
        self.assertIsNone(
            self.l3_inst.validate_availability_zones(
                self.context, 'router', ['az0', 'az2']))

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.mech_driver.'
                'OVNMechanismDriver.list_availability_zones')
    def test_validate_availability_zones_fail_non_exist(self, mock_list_azs):
        mock_list_azs.return_value = {'az0': {'name': 'az0'},
                                      'az1': {'name': 'az1'},
                                      'az2': {'name': 'az2'}}
        # Fails validation if the az does not exist
        self.assertRaises(
            az_exc.AvailabilityZoneNotFound,
            self.l3_inst.validate_availability_zones, self.context, 'router',
            ['az0', 'non-existent'])

    @mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.mech_driver.'
                'OVNMechanismDriver.list_availability_zones')
    def test_validate_availability_zones_no_azs(self, mock_list_azs):
        # When no AZs are requested validation should just succeed
        self.assertIsNone(
            self.l3_inst.validate_availability_zones(
                self.context, 'router', []))
        mock_list_azs.assert_not_called()

    def test_ovn_l3_router_plugin_without_ovn_mech_driver(self):
        cfg.CONF.set_override('mechanism_drivers', [], group='ml2')
        neutron_manager.NeutronManager._instance = None
        with mock.patch.object(managers.TypeManager, 'initialize'):
            self.assertRaises(ovn_l3_exc.MechanismDriverNotFound,
                              api_router.APIRouter)


class OVNL3ExtrarouteTests(test_l3_gw.ExtGwModeIntTestCase,
                           test_l3.L3NatDBIntTestCase,
                           test_extraroute.ExtraRouteDBTestCaseBase):

    # TODO(lucasagomes): Ideally, this method should be moved to a base
    # class which all tests classes in networking-ovn inherits from but,
    # this base class doesn't seem to exist for now so we need to duplicate
    # it here
    def _start_mock(self, path, return_value, new_callable=None):
        patcher = mock.patch(path, return_value=return_value,
                             new_callable=new_callable)
        patch = patcher.start()
        self.addCleanup(patcher.stop)
        return patch

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestOVNL3Plugin'
        l3_plugin = ('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}
        config.register_opts()
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = test_extraroute.ExtraRouteTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins)
        revision_plugin.RevisionPlugin()
        l3_gw_mgr = test_l3_gw.TestExtensionManager()
        test_extensions.setup_extensions_middleware(l3_gw_mgr)
        self.l3_inst = directory.get_plugin(plugin_constants.L3)
        self._start_mock(
            'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin._nb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fake_resources.FakeOvsdbNbOvnIdl())
        self._start_mock(
            'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fake_resources.FakeOvsdbSbOvnIdl())
        self._start_mock(
            'neutron.scheduler.l3_ovn_scheduler.'
            'OVNGatewayScheduler._schedule_gateway',
            return_value='hv1')
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.get_candidates_for_scheduling',
            return_value=[])
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient._get_v4_network_of_all_router_ports',
            return_value=[])
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.update_floatingip_status',
            return_value=None)
        self._start_mock(
            'neutron.common.ovn.utils.get_revision_number',
            return_value=1)
        self._start_mock(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.ovn_client.'
            'OVNClient.delete_mac_binding_entries_by_mac',
            return_value=1)
        self.setup_notification_driver()

    # Note(dongj): According to bug #1657693, status of an unassociated
    # floating IP is set to DOWN. Revise expected_status to DOWN for related
    # test cases.
    def test_floatingip_update(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).test_floatingip_update(
            expected_status)

    def test_floatingip_update_to_same_port_id_twice(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).\
            test_floatingip_update_to_same_port_id_twice(expected_status)

    def test_floatingip_update_subnet_gateway_disabled(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).\
            test_floatingip_update_subnet_gateway_disabled(expected_status)

    # Test function _subnet_update of L3 OVN plugin.
    def test_update_subnet_gateway_for_external_net(self):
        super(OVNL3ExtrarouteTests, self). \
            test_update_subnet_gateway_for_external_net()
        self.l3_inst._nb_ovn.add_static_route.assert_called_once_with(
            'neutron-fake_device', ip_prefix='0.0.0.0/0', nexthop='120.0.0.2')
        self.l3_inst._nb_ovn.delete_static_route.assert_called_once_with(
            'neutron-fake_device', ip_prefix='0.0.0.0/0', nexthop='120.0.0.1')

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        super(OVNL3ExtrarouteTests, self). \
            test_router_update_gateway_upon_subnet_create_max_ips_ipv6()
        expected_ext_ids = {
                ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                ovn_const.OVN_SUBNET_EXT_ID_KEY: mock.ANY}
        add_static_route_calls = [
            mock.call(mock.ANY, ip_prefix='0.0.0.0/0', nexthop='10.0.0.1',
                external_ids=expected_ext_ids),
            mock.call(mock.ANY, ip_prefix='::/0', nexthop='2001:db8::',
                external_ids=expected_ext_ids)]
        self.l3_inst._nb_ovn.add_static_route.assert_has_calls(
            add_static_route_calls, any_order=True)
