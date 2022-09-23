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
import collections
import copy
from unittest import mock

from ovsdbapp.backend import ovs_idl

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.services.portforwarding import constants as pf_const
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class TestDBImplIdlOvn(base.BaseTestCase):

    def _load_ovsdb_fake_rows(self, table, fake_attrs):
        for fake_attr in fake_attrs:
            fake_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs=fake_attr)
            # Pre-populate ovs idl "._data"
            fake_data = copy.deepcopy(fake_attr)
            try:
                del fake_data["unit_test_id"]
            except KeyError:
                pass
            setattr(fake_row, "_data", fake_data)
            table.rows[fake_row.uuid] = fake_row

    def _find_ovsdb_fake_row(self, table, key, value):
        for fake_row in table.rows.values():
            if getattr(fake_row, key) == value:
                return fake_row
        return None

    def _construct_ovsdb_references(self, fake_associations,
                                    parent_table, child_table,
                                    parent_key, child_key,
                                    reference_column_name):
        for p_name, c_names in fake_associations.items():
            p_row = self._find_ovsdb_fake_row(parent_table, parent_key, p_name)
            c_uuids = []
            for c_name in c_names:
                c_row = self._find_ovsdb_fake_row(child_table, child_key,
                                                  c_name)
                if not c_row:
                    continue
                # Fake IDL processing (uuid -> row)
                c_uuids.append(c_row)
            setattr(p_row, reference_column_name, c_uuids)


class TestNBImplIdlOvn(TestDBImplIdlOvn):

    fake_set = {
        'lswitches': [
            {'name': utils.ovn_name('ls-id-1'),
             'external_ids': {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                              'ls-name-1'}},
            {'name': utils.ovn_name('ls-id-2'),
             'external_ids': {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                              'ls-name-2'}},
            {'name': utils.ovn_name('ls-id-3'),
             'external_ids': {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                              'ls-name-3'}},
            {'name': 'ls-id-4',
             'external_ids': {'not-neutron:network_name': 'ls-name-4'}},
            {'name': utils.ovn_name('ls-id-5'),
             'external_ids': {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                              'ls-name-5'}}],
        'lswitch_ports': [
            {'name': 'lsp-id-11', 'addresses': ['10.0.1.1'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-11'}},
            {'name': 'lsp-id-12', 'addresses': ['10.0.1.2'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-12'}},
            {'name': 'lsp-rp-id-1', 'addresses': ['10.0.1.254'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-rp-name-1'},
             'options': {'router-port':
                         utils.ovn_lrouter_port_name('orp-id-a1')}},
            {'name': 'provnet-ls-id-1', 'addresses': ['unknown'],
             'external_ids': {},
             'options': {'network_name': 'physnet1'}},
            {'name': 'lsp-id-21', 'addresses': ['10.0.2.1'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-21'}},
            {'name': 'lsp-id-22', 'addresses': ['10.0.2.2'],
             'external_ids': {}},
            {'name': 'lsp-id-23', 'addresses': ['10.0.2.3'],
             'external_ids': {'not-neutron:port_name': 'lsp-name-23'}},
            {'name': 'lsp-rp-id-2', 'addresses': ['10.0.2.254'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-rp-name-2'},
             'options': {'router-port':
                         utils.ovn_lrouter_port_name('orp-id-a2')}},
            {'name': 'provnet-ls-id-2', 'addresses': ['unknown'],
             'external_ids': {},
             'options': {'network_name': 'physnet2'}},
            {'name': 'lsp-id-31', 'addresses': ['10.0.3.1'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-31'}},
            {'name': 'lsp-id-32', 'addresses': ['10.0.3.2'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-32'}},
            {'name': 'lsp-rp-id-3', 'addresses': ['10.0.3.254'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-rp-name-3'},
             'options': {'router-port':
                         utils.ovn_lrouter_port_name('orp-id-a3')}},
            {'name': 'lsp-vpn-id-3', 'addresses': ['10.0.3.253'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-vpn-name-3'}},
            {'name': 'lsp-id-41', 'addresses': ['20.0.1.1'],
             'external_ids': {'not-neutron:port_name': 'lsp-name-41'}},
            {'name': 'lsp-rp-id-4', 'addresses': ['20.0.1.254'],
             'external_ids': {},
             'options': {'router-port': 'xrp-id-b1'}},
            {'name': 'lsp-id-51', 'addresses': ['20.0.2.1'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-51'}},
            {'name': 'lsp-id-52', 'addresses': ['20.0.2.2'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-name-52'}},
            {'name': 'lsp-rp-id-5', 'addresses': ['20.0.2.254'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-rp-name-5'},
             'options': {'router-port':
                         utils.ovn_lrouter_port_name('orp-id-b2')}},
            {'name': 'lsp-vpn-id-5', 'addresses': ['20.0.2.253'],
             'external_ids': {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                              'lsp-vpn-name-5'}}],
        'lrouters': [
            {'name': utils.ovn_name('lr-id-a'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-name-a',
                              ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az-a'}},
            {'name': utils.ovn_name('lr-id-b'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-name-b',
                              ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az-b'}},
            {'name': utils.ovn_name('lr-id-c'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-name-c'}},
            {'name': utils.ovn_name('lr-id-d'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-name-d'}},
            {'name': utils.ovn_name('lr-id-e'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-name-e'}}],
        'lrouter_ports': [
            {'name': utils.ovn_lrouter_port_name('orp-id-a1'),
             'external_ids': {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                              'lr-id-a'},
             'networks': ['10.0.1.0/24'],
             'options': {ovn_const.OVN_GATEWAY_CHASSIS_KEY: 'host-1'}},
            {'name': utils.ovn_lrouter_port_name('orp-id-a2'),
             'external_ids': {}, 'networks': ['10.0.2.0/24'],
             'options': {ovn_const.OVN_GATEWAY_CHASSIS_KEY: 'host-1'}},
            {'name': utils.ovn_lrouter_port_name('orp-id-a3'),
             'external_ids': {}, 'networks': ['10.0.3.0/24'],
             'options': {ovn_const.OVN_GATEWAY_CHASSIS_KEY:
                         ovn_const.OVN_GATEWAY_INVALID_CHASSIS}},
            {'name': 'xrp-id-b1',
             'external_ids': {}, 'networks': ['20.0.1.0/24']},
            {'name': utils.ovn_lrouter_port_name('orp-id-b2'),
             'external_ids': {}, 'networks': ['20.0.2.0/24'],
             'options': {ovn_const.OVN_GATEWAY_CHASSIS_KEY: 'host-2'}},
            {'name': utils.ovn_lrouter_port_name('orp-id-b3'),
             'external_ids': {}, 'networks': ['20.0.3.0/24'],
             'options': {}}],
        'static_routes': [{'ip_prefix': '20.0.0.0/16',
                           'nexthop': '10.0.3.253'},
                          {'ip_prefix': '10.0.0.0/16',
                           'nexthop': '20.0.2.253'}],
        'nats': [{'external_ip': '10.0.3.1', 'logical_ip': '20.0.0.0/16',
                  'type': 'snat'},
                 {'external_ip': '20.0.2.1', 'logical_ip': '10.0.0.0/24',
                  'type': 'snat'},
                 {'external_ip': '20.0.2.4', 'logical_ip': '10.0.0.4',
                  'type': 'dnat_and_snat', 'external_mac': [],
                  'logical_port': []},
                 {'external_ip': '20.0.2.5', 'logical_ip': '10.0.0.5',
                  'type': 'dnat_and_snat',
                  'external_mac': ['00:01:02:03:04:05'],
                  'logical_port': ['lsp-id-001']}],
        'acls': [
            {'unit_test_id': 1,
             'action': 'allow-related', 'direction': 'from-lport',
             'external_ids': {'neutron:lport': 'lsp-id-11'},
             'match': 'inport == "lsp-id-11" && ip4'},
            {'unit_test_id': 2,
             'action': 'allow-related', 'direction': 'to-lport',
             'external_ids': {'neutron:lport': 'lsp-id-11'},
             'match': 'outport == "lsp-id-11" && ip4.src == $as_ip4_id_1'},
            {'unit_test_id': 3,
             'action': 'allow-related', 'direction': 'from-lport',
             'external_ids': {'neutron:lport': 'lsp-id-12'},
             'match': 'inport == "lsp-id-12" && ip4'},
            {'unit_test_id': 4,
             'action': 'allow-related', 'direction': 'to-lport',
             'external_ids': {'neutron:lport': 'lsp-id-12'},
             'match': 'outport == "lsp-id-12" && ip4.src == $as_ip4_id_1'},
            {'unit_test_id': 5,
             'action': 'allow-related', 'direction': 'from-lport',
             'external_ids': {'neutron:lport': 'lsp-id-21'},
             'match': 'inport == "lsp-id-21" && ip4'},
            {'unit_test_id': 6,
             'action': 'allow-related', 'direction': 'to-lport',
             'external_ids': {'neutron:lport': 'lsp-id-21'},
             'match': 'outport == "lsp-id-21" && ip4.src == $as_ip4_id_2'},
            {'unit_test_id': 7,
             'action': 'allow-related', 'direction': 'from-lport',
             'external_ids': {'neutron:lport': 'lsp-id-41'},
             'match': 'inport == "lsp-id-41" && ip4'},
            {'unit_test_id': 8,
             'action': 'allow-related', 'direction': 'to-lport',
             'external_ids': {'neutron:lport': 'lsp-id-41'},
             'match': 'outport == "lsp-id-41" && ip4.src == $as_ip4_id_4'},
            {'unit_test_id': 9,
             'action': 'allow-related', 'direction': 'from-lport',
             'external_ids': {'neutron:lport': 'lsp-id-52'},
             'match': 'inport == "lsp-id-52" && ip4'},
            {'unit_test_id': 10,
             'action': 'allow-related', 'direction': 'to-lport',
             'external_ids': {'neutron:lport': 'lsp-id-52'},
             'match': 'outport == "lsp-id-52" && ip4.src == $as_ip4_id_5'}],
        'dhcp_options': [
            {'cidr': '10.0.1.0/24',
             'external_ids': {'subnet_id': 'subnet-id-10-0-1-0'},
             'options': {'mtu': '1442', 'router': '10.0.1.254'}},
            {'cidr': '10.0.2.0/24',
             'external_ids': {'subnet_id': 'subnet-id-10-0-2-0'},
             'options': {'mtu': '1442', 'router': '10.0.2.254'}},
            {'cidr': '10.0.1.0/26',
             'external_ids': {'subnet_id': 'subnet-id-10-0-1-0',
                              'port_id': 'lsp-vpn-id-3'},
             'options': {'mtu': '1442', 'router': '10.0.1.1'}},
            {'cidr': '20.0.1.0/24',
             'external_ids': {'subnet_id': 'subnet-id-20-0-1-0'},
             'options': {'mtu': '1442', 'router': '20.0.1.254'}},
            {'cidr': '20.0.2.0/24',
             'external_ids': {'subnet_id': 'subnet-id-20-0-2-0',
                              'port_id': 'lsp-vpn-id-5'},
             'options': {'mtu': '1442', 'router': '20.0.2.254'}},
            {'cidr': '2001:dba::/64',
             'external_ids': {'subnet_id': 'subnet-id-2001-dba',
                              'port_id': 'lsp-vpn-id-5'},
             'options': {'server_id': '12:34:56:78:9a:bc'}},
            {'cidr': '30.0.1.0/24',
             'external_ids': {'port_id': 'port-id-30-0-1-0'},
             'options': {'mtu': '1442', 'router': '30.0.2.254'}},
            {'cidr': '30.0.2.0/24', 'external_ids': {}, 'options': {}}],
        'address_sets': [
            {'name': '$as_ip4_id_1',
             'addresses': ['10.0.1.1', '10.0.1.2'],
             'external_ids': {ovn_const.OVN_SG_EXT_ID_KEY: 'id_1'}},
            {'name': '$as_ip4_id_2',
             'addresses': ['10.0.2.1'],
             'external_ids': {ovn_const.OVN_SG_EXT_ID_KEY: 'id_2'}},
            {'name': '$as_ip4_id_3',
             'addresses': ['10.0.3.1', '10.0.3.2'],
             'external_ids': {ovn_const.OVN_SG_EXT_ID_KEY: 'id_3'}},
            {'name': '$as_ip4_id_4',
             'addresses': ['20.0.1.1', '20.0.1.2'],
             'external_ids': {}},
            {'name': '$as_ip4_id_5',
             'addresses': ['20.0.2.1', '20.0.2.2'],
             'external_ids': {ovn_const.OVN_SG_EXT_ID_KEY: 'id_5'}}],
        'lbs': [
            {'name': 'lb_1',
             'external_ids': {
                 ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                     pf_const.PORT_FORWARDING_PLUGIN,
                 ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'rtr_name',
                 ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id_1'}},
            {'name': 'lb_2',
             'external_ids': {
                 ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                     pf_const.PORT_FORWARDING_PLUGIN,
                 ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'rtr_name',
                 ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id_2'}},
            {'name': 'lb_3', 'external_ids': {}}],
    }

    fake_associations = {
        'lstolsp': {
            utils.ovn_name('ls-id-1'): [
                'lsp-id-11', 'lsp-id-12', 'lsp-rp-id-1', 'provnet-ls-id-1'],
            utils.ovn_name('ls-id-2'): [
                'lsp-id-21', 'lsp-id-22', 'lsp-id-23', 'lsp-rp-id-2',
                'provnet-ls-id-2'],
            utils.ovn_name('ls-id-3'): [
                'lsp-id-31', 'lsp-id-32', 'lsp-rp-id-3', 'lsp-vpn-id-3'],
            'ls-id-4': [
                'lsp-id-41', 'lsp-rp-id-4'],
            utils.ovn_name('ls-id-5'): [
                'lsp-id-51', 'lsp-id-52', 'lsp-rp-id-5', 'lsp-vpn-id-5']},
        'lrtolrp': {
            utils.ovn_name('lr-id-a'): [
                utils.ovn_lrouter_port_name('orp-id-a1'),
                utils.ovn_lrouter_port_name('orp-id-a2'),
                utils.ovn_lrouter_port_name('orp-id-a3')],
            utils.ovn_name('lr-id-b'): [
                'xrp-id-b1',
                utils.ovn_lrouter_port_name('orp-id-b2')]},
        'lrtosroute': {
            utils.ovn_name('lr-id-a'): ['20.0.0.0/16'],
            utils.ovn_name('lr-id-b'): ['10.0.0.0/16']
        },
        'lrtonat': {
            utils.ovn_name('lr-id-a'): ['10.0.3.1'],
            utils.ovn_name('lr-id-b'): ['20.0.2.1', '20.0.2.4', '20.0.2.5'],
        },
        'lstoacl': {
            utils.ovn_name('ls-id-1'): [1, 2, 3, 4],
            utils.ovn_name('ls-id-2'): [5, 6],
            'ls-id-4': [7, 8],
            utils.ovn_name('ls-id-5'): [9, 10]}
    }

    def setUp(self):
        super(TestNBImplIdlOvn, self).setUp()

        self.lswitch_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.lsp_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.lrouter_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.lrp_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.sroute_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.nat_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.acl_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.dhcp_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.address_set_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self.lb_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()

        self._tables = {}
        self._tables['Logical_Switch'] = self.lswitch_table
        self._tables['Logical_Switch_Port'] = self.lsp_table
        self._tables['Logical_Router'] = self.lrouter_table
        self._tables['Logical_Router_Port'] = self.lrp_table
        self._tables['Logical_Router_Static_Route'] = self.sroute_table
        self._tables['ACL'] = self.acl_table
        self._tables['DHCP_Options'] = self.dhcp_table
        self._tables['Address_Set'] = self.address_set_table
        self._tables['Load_Balancer'] = self.lb_table
        self._tables['NAT'] = self.nat_table

        with mock.patch.object(impl_idl_ovn.OvsdbNbOvnIdl, 'from_worker',
                               return_value=mock.Mock()):
            with mock.patch.object(ovs_idl.Backend, 'autocreate_indices',
                                   create=True):
                impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection = None
                self.nb_ovn_idl = impl_idl_ovn.OvsdbNbOvnIdl(mock.MagicMock())

        self.nb_ovn_idl.idl.tables = self._tables

    def _load_nb_db(self):
        # Load Switches and Switch Ports
        fake_lswitches = TestNBImplIdlOvn.fake_set['lswitches']
        self._load_ovsdb_fake_rows(self.lswitch_table, fake_lswitches)
        fake_lsps = TestNBImplIdlOvn.fake_set['lswitch_ports']
        self._load_ovsdb_fake_rows(self.lsp_table, fake_lsps)
        # Associate switches and ports
        self._construct_ovsdb_references(
            TestNBImplIdlOvn.fake_associations['lstolsp'],
            self.lswitch_table, self.lsp_table,
            'name', 'name', 'ports')
        # Load Routers and Router Ports
        fake_lrouters = TestNBImplIdlOvn.fake_set['lrouters']
        self._load_ovsdb_fake_rows(self.lrouter_table, fake_lrouters)
        fake_lrps = TestNBImplIdlOvn.fake_set['lrouter_ports']
        self._load_ovsdb_fake_rows(self.lrp_table, fake_lrps)
        # Associate routers and router ports
        self._construct_ovsdb_references(
            TestNBImplIdlOvn.fake_associations['lrtolrp'],
            self.lrouter_table, self.lrp_table,
            'name', 'name', 'ports')
        # Load static routes
        fake_sroutes = TestNBImplIdlOvn.fake_set['static_routes']
        self._load_ovsdb_fake_rows(self.sroute_table, fake_sroutes)
        # Associate routers and static routes
        self._construct_ovsdb_references(
            TestNBImplIdlOvn.fake_associations['lrtosroute'],
            self.lrouter_table, self.sroute_table,
            'name', 'ip_prefix', 'static_routes')
        # Load nats
        fake_nats = TestNBImplIdlOvn.fake_set['nats']
        self._load_ovsdb_fake_rows(self.nat_table, fake_nats)
        # Associate routers and nats
        self._construct_ovsdb_references(
            TestNBImplIdlOvn.fake_associations['lrtonat'],
            self.lrouter_table, self.nat_table,
            'name', 'external_ip', 'nat')
        # Load acls
        fake_acls = TestNBImplIdlOvn.fake_set['acls']
        self._load_ovsdb_fake_rows(self.acl_table, fake_acls)
        # Associate switches and acls
        self._construct_ovsdb_references(
            TestNBImplIdlOvn.fake_associations['lstoacl'],
            self.lswitch_table, self.acl_table,
            'name', 'unit_test_id', 'acls')
        # Load dhcp options
        fake_dhcp_options = TestNBImplIdlOvn.fake_set['dhcp_options']
        self._load_ovsdb_fake_rows(self.dhcp_table, fake_dhcp_options)
        # Load address sets
        fake_address_sets = TestNBImplIdlOvn.fake_set['address_sets']
        self._load_ovsdb_fake_rows(self.address_set_table, fake_address_sets)
        # Load load balancers
        fake_lbs = TestNBImplIdlOvn.fake_set['lbs']
        self._load_ovsdb_fake_rows(self.lb_table, fake_lbs)

    def test_get_all_logical_switches_with_ports(self):
        # Test empty
        mapping = self.nb_ovn_idl.get_all_logical_switches_with_ports()
        self.assertCountEqual(mapping, {})
        # Test loaded values
        self._load_nb_db()
        mapping = self.nb_ovn_idl.get_all_logical_switches_with_ports()
        expected = [{'name': utils.ovn_name('ls-id-1'),
                     'ports': ['lsp-id-11', 'lsp-id-12', 'lsp-rp-id-1'],
                     'provnet_ports': ['provnet-ls-id-1']},
                    {'name': utils.ovn_name('ls-id-2'),
                     'ports': ['lsp-id-21', 'lsp-rp-id-2'],
                     'provnet_ports': ['provnet-ls-id-2']},
                    {'name': utils.ovn_name('ls-id-3'),
                     'ports': ['lsp-id-31', 'lsp-id-32', 'lsp-rp-id-3',
                               'lsp-vpn-id-3'],
                     'provnet_ports': []},
                    {'name': utils.ovn_name('ls-id-5'),
                     'ports': ['lsp-id-51', 'lsp-id-52', 'lsp-rp-id-5',
                               'lsp-vpn-id-5'],
                     'provnet_ports': []}]
        self.assertCountEqual(mapping, expected)

    def test_get_all_logical_routers_with_rports(self):
        # Test empty
        mapping = self.nb_ovn_idl.get_all_logical_switches_with_ports()
        self.assertCountEqual(mapping, {})
        # Test loaded values
        self._load_nb_db()
        mapping = self.nb_ovn_idl.get_all_logical_routers_with_rports()
        expected = [{'name': 'lr-id-a',
                     'ports': {'orp-id-a1': ['10.0.1.0/24'],
                               'orp-id-a2': ['10.0.2.0/24'],
                               'orp-id-a3': ['10.0.3.0/24']},
                     'static_routes': [{'destination': '20.0.0.0/16',
                                        'nexthop': '10.0.3.253'}],
                     'snats': [{'external_ip': '10.0.3.1',
                                'logical_ip': '20.0.0.0/16',
                                'type': 'snat'}],
                     'dnat_and_snats': []},
                    {'name': 'lr-id-b',
                     'ports': {'xrp-id-b1': ['20.0.1.0/24'],
                               'orp-id-b2': ['20.0.2.0/24']},
                     'static_routes': [{'destination': '10.0.0.0/16',
                                        'nexthop': '20.0.2.253'}],
                     'snats': [{'external_ip': '20.0.2.1',
                                'logical_ip': '10.0.0.0/24',
                                'type': 'snat'}],
                     'dnat_and_snats': [{'external_ip': '20.0.2.4',
                                         'logical_ip': '10.0.0.4',
                                         'type': 'dnat_and_snat'},
                                        {'external_ip': '20.0.2.5',
                                         'logical_ip': '10.0.0.5',
                                         'type': 'dnat_and_snat',
                                         'external_mac': '00:01:02:03:04:05',
                                         'logical_port': 'lsp-id-001'}]},
                    {'name': 'lr-id-c', 'ports': {}, 'static_routes': [],
                     'snats': [], 'dnat_and_snats': []},
                    {'name': 'lr-id-d', 'ports': {}, 'static_routes': [],
                     'snats': [], 'dnat_and_snats': []},
                    {'name': 'lr-id-e', 'ports': {}, 'static_routes': [],
                     'snats': [], 'dnat_and_snats': []}]
        self.assertCountEqual(mapping, expected)

    def test_get_acls_for_lswitches(self):
        self._load_nb_db()
        # Test neutron switches
        lswitches = ['ls-id-1', 'ls-id-2', 'ls-id-3', 'ls-id-5']
        acl_values, acl_objs, lswitch_ovsdb_dict = \
            self.nb_ovn_idl.get_acls_for_lswitches(lswitches)
        excepted_acl_values = {
            'lsp-id-11': [
                {'action': 'allow-related', 'lport': 'lsp-id-11',
                 'lswitch': 'neutron-ls-id-1',
                 'external_ids': {'neutron:lport': 'lsp-id-11'},
                 'direction': 'from-lport',
                 'match': 'inport == "lsp-id-11" && ip4'},
                {'action': 'allow-related', 'lport': 'lsp-id-11',
                 'lswitch': 'neutron-ls-id-1',
                 'external_ids': {'neutron:lport': 'lsp-id-11'},
                 'direction': 'to-lport',
                 'match': 'outport == "lsp-id-11" && ip4.src == $as_ip4_id_1'}
            ],
            'lsp-id-12': [
                {'action': 'allow-related', 'lport': 'lsp-id-12',
                 'lswitch': 'neutron-ls-id-1',
                 'external_ids': {'neutron:lport': 'lsp-id-12'},
                 'direction': 'from-lport',
                 'match': 'inport == "lsp-id-12" && ip4'},
                {'action': 'allow-related', 'lport': 'lsp-id-12',
                 'lswitch': 'neutron-ls-id-1',
                 'external_ids': {'neutron:lport': 'lsp-id-12'},
                 'direction': 'to-lport',
                 'match': 'outport == "lsp-id-12" && ip4.src == $as_ip4_id_1'}
            ],
            'lsp-id-21': [
                {'action': 'allow-related', 'lport': 'lsp-id-21',
                 'lswitch': 'neutron-ls-id-2',
                 'external_ids': {'neutron:lport': 'lsp-id-21'},
                 'direction': 'from-lport',
                 'match': 'inport == "lsp-id-21" && ip4'},
                {'action': 'allow-related', 'lport': 'lsp-id-21',
                 'lswitch': 'neutron-ls-id-2',
                 'external_ids': {'neutron:lport': 'lsp-id-21'},
                 'direction': 'to-lport',
                 'match': 'outport == "lsp-id-21" && ip4.src == $as_ip4_id_2'}
            ],
            'lsp-id-52': [
                {'action': 'allow-related', 'lport': 'lsp-id-52',
                 'lswitch': 'neutron-ls-id-5',
                 'external_ids': {'neutron:lport': 'lsp-id-52'},
                 'direction': 'from-lport',
                 'match': 'inport == "lsp-id-52" && ip4'},
                {'action': 'allow-related', 'lport': 'lsp-id-52',
                 'lswitch': 'neutron-ls-id-5',
                 'external_ids': {'neutron:lport': 'lsp-id-52'},
                 'direction': 'to-lport',
                 'match': 'outport == "lsp-id-52" && ip4.src == $as_ip4_id_5'}
            ]}
        self.assertCountEqual(acl_values, excepted_acl_values)
        self.assertEqual(len(acl_objs), 8)
        self.assertEqual(len(lswitch_ovsdb_dict), len(lswitches))

        # Test non-neutron switches
        lswitches = ['ls-id-4']
        acl_values, acl_objs, lswitch_ovsdb_dict = \
            self.nb_ovn_idl.get_acls_for_lswitches(lswitches)
        self.assertCountEqual(acl_values, {})
        self.assertEqual(len(acl_objs), 0)
        self.assertEqual(len(lswitch_ovsdb_dict), 0)

    def test_get_all_chassis_gateway_bindings(self):
        self._load_nb_db()
        bindings = self.nb_ovn_idl.get_all_chassis_gateway_bindings()
        expected = {'host-1': [utils.ovn_lrouter_port_name('orp-id-a1'),
                               utils.ovn_lrouter_port_name('orp-id-a2')],
                    'host-2': [utils.ovn_lrouter_port_name('orp-id-b2')],
                    ovn_const.OVN_GATEWAY_INVALID_CHASSIS: [
                        utils.ovn_name('orp-id-a3')]}
        self.assertCountEqual(bindings, expected)

        bindings = self.nb_ovn_idl.get_all_chassis_gateway_bindings([])
        self.assertCountEqual(bindings, expected)

        bindings = self.nb_ovn_idl.get_all_chassis_gateway_bindings(['host-1'])
        expected = {'host-1': [utils.ovn_lrouter_port_name('orp-id-a1'),
                               utils.ovn_lrouter_port_name('orp-id-a2')]}
        self.assertCountEqual(bindings, expected)

    def test_get_gateway_chassis_binding(self):
        self._load_nb_db()
        chassis = self.nb_ovn_idl.get_gateway_chassis_binding(
            utils.ovn_lrouter_port_name('orp-id-a1'))
        self.assertEqual(chassis, ['host-1'])
        chassis = self.nb_ovn_idl.get_gateway_chassis_binding(
            utils.ovn_lrouter_port_name('orp-id-b2'))
        self.assertEqual(chassis, ['host-2'])
        chassis = self.nb_ovn_idl.get_gateway_chassis_binding(
            utils.ovn_lrouter_port_name('orp-id-a3'))
        self.assertEqual(chassis, ['neutron-ovn-invalid-chassis'])
        chassis = self.nb_ovn_idl.get_gateway_chassis_binding(
            utils.ovn_lrouter_port_name('orp-id-b3'))
        self.assertEqual([], chassis)
        chassis = self.nb_ovn_idl.get_gateway_chassis_binding('bad')
        self.assertEqual([], chassis)

    def test_get_unhosted_gateways(self):
        self._load_nb_db()
        # Port physnet-dict
        port_physnet_dict = {
            'orp-id-a1': 'physnet1',  # scheduled
            'orp-id-a2': 'physnet1',  # scheduled
            'orp-id-a3': 'physnet1',  # not scheduled
            'orp-id-b6': 'physnet2'}  # not scheduled
        # Test only that orp-id-a3 is to be scheduled.
        # Rest ports don't have required chassis (physnet2)
        # or are already scheduled.
        chassis_with_azs = {'host-1': ['az-a'], 'host-2': ['az-b']}
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            port_physnet_dict, {'host-1': 'physnet1', 'host-2': 'physnet3'},
            ['host-1', 'host-2'], chassis_with_azs)
        expected = ['lrp-orp-id-a3']
        self.assertCountEqual(unhosted_gateways, expected)
        # Test both host-1, host-2 in valid list
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            port_physnet_dict, {'host-1': 'physnet1', 'host-2': 'physnet2'},
            ['host-1', 'host-2'], chassis_with_azs)
        expected = ['lrp-orp-id-a3', 'lrp-orp-id-b6']
        self.assertCountEqual(unhosted_gateways, expected)
        # Test lrp-orp-id-a1 az_hints not in host-1's azs
        # lrp-orp-id-a2 not set az_hints, should schedule in host-1, host-3
        # lrp-orp-id-a3 not scheduled
        chassis_with_azs = {'host-1': ['az-b'], 'host-2': ['az-b'],
                            'host-3': ['az-a']}
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            port_physnet_dict, {'host-1': 'physnet1', 'host-2': 'physnet3',
                                'host-3': 'physnet1'},
            ['host-1', 'host-2', 'host-3'], chassis_with_azs)
        expected = ['lrp-orp-id-a1', 'lrp-orp-id-a2', 'lrp-orp-id-a3']
        self.assertCountEqual(unhosted_gateways, expected)

    def test_get_unhosted_gateways_deleted_physnet(self):
        self._load_nb_db()
        # The LRP is on host-2 now
        router_row = self._find_ovsdb_fake_row(self.lrp_table,
                                               'name', 'lrp-orp-id-a1')
        setattr(router_row, 'options', {
            ovn_const.OVN_GATEWAY_CHASSIS_KEY: 'host-2'})
        port_physnet_dict = {'orp-id-a1': 'physnet1'}
        chassis_with_azs = {'host-1': ['az-a'], 'host-2': ['az-a']}
        # Lets spoof that physnet1 is deleted from host-2.
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            port_physnet_dict, {'host-1': 'physnet1', 'host-2': 'physnet3'},
            ['host-1', 'host-2'], chassis_with_azs)
        # Make sure that lrp is rescheduled, because host-1 has physet1
        expected = ['lrp-orp-id-a1']
        self.assertCountEqual(unhosted_gateways, expected)
        # Spoof that there is no valid host with required physnet.
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            port_physnet_dict, {'host-1': 'physnet4', 'host-2': 'physnet3'},
            ['host-1', 'host-2'], chassis_with_azs)
        self.assertCountEqual(unhosted_gateways, [])

    def _test_get_unhosted_gateway_max_chassis(self, r):
        gw_chassis_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()
        self._tables['Gateway_Chassis'] = gw_chassis_table
        gw_chassis = collections.namedtuple('gw_chassis',
                                            'chassis_name priority')
        TestNBImplIdlOvn.fake_set['lrouter_ports'][0]['gateway_chassis'] = [
            gw_chassis(chassis_name='host-%s' % x,
                       priority=x) for x in r]
        self._load_nb_db()
        self.port_physnet_dict = {'orp-id-a1': 'physnet1'}

    def test_get_unhosted_gateway_max_chassis_lack_of_chassis(self):
        self._test_get_unhosted_gateway_max_chassis(r=(1, 3, 5))
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            self.port_physnet_dict,
            {'host-1': 'physnet1', 'host-2': 'physnet2',
             'host-3': 'physnet1', 'host-4': 'physnet2',
             'host-5': 'physnet1', 'host-6': 'physnet2'},
            ['host-%s' % x for x in range(1, 7)],
            {'host-%s' % x: ['az-a'] for x in range(1, 7)})
        # We don't have required number of chassis
        expected = []
        self.assertCountEqual(unhosted_gateways, expected)

    def test_get_unhosted_gateway_max_chassis(self):
        # We have required number of chassis, and lrp
        # is hosted everywhere.
        self._test_get_unhosted_gateway_max_chassis(r=range(1, 6))
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            self.port_physnet_dict,
            {'host-1': 'physnet1', 'host-2': 'physnet1',
             'host-3': 'physnet1', 'host-4': 'physnet1',
             'host-5': 'physnet1', 'host-6': 'physnet1'},
            ['host-%s' % x for x in range(1, 7)],
            {'host-%s' % x: ['az-a'] for x in range(1, 7)})
        expected = []
        self.assertCountEqual(unhosted_gateways, expected)

    def test_get_unhosed_gateway_schedule_to_max(self):
        # The LRP is not yet scheduled on all chassis
        # but we can schedule on new chassis now.
        self._test_get_unhosted_gateway_max_chassis(r=range(1, 4))
        unhosted_gateways = self.nb_ovn_idl.get_unhosted_gateways(
            self.port_physnet_dict,
            {'host-1': 'physnet1', 'host-2': 'physnet1',
             'host-3': 'physnet1', 'host-4': 'physnet1',
             'host-5': 'physnet1', 'host-6': 'physnet1'},
            ['host-%s' % x for x in range(1, 7)],
            {'host-%s' % x: ['az-a'] for x in range(1, 7)})
        expected = ['lrp-orp-id-a1']
        self.assertCountEqual(unhosted_gateways, expected)

    def test_get_subnet_dhcp_options(self):
        self._load_nb_db()
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-10-0-2-0')
        expected_row = self._find_ovsdb_fake_row(self.dhcp_table,
                                                 'cidr', '10.0.2.0/24')
        self.assertEqual({
            'subnet': {'cidr': expected_row.cidr,
                       'external_ids': expected_row.external_ids,
                       'options': expected_row.options,
                       'uuid': expected_row.uuid},
            'ports': []}, subnet_options)
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-11-0-2-0')['subnet']
        self.assertEqual({}, subnet_options)
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'port-id-30-0-1-0')['subnet']
        self.assertEqual({}, subnet_options)

    def test_get_subnet_dhcp_options_with_ports(self):
        # Test empty
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-10-0-1-0', with_ports=True)
        self.assertCountEqual({'subnet': None, 'ports': []}, subnet_options)
        # Test loaded values
        self._load_nb_db()
        # Test getting both subnet and port dhcp options
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-10-0-1-0', with_ports=True)
        dhcp_rows = [
            self._find_ovsdb_fake_row(self.dhcp_table, 'cidr', '10.0.1.0/24'),
            self._find_ovsdb_fake_row(self.dhcp_table, 'cidr', '10.0.1.0/26')]
        expected_rows = [{'cidr': dhcp_row.cidr,
                          'external_ids': dhcp_row.external_ids,
                          'options': dhcp_row.options,
                          'uuid': dhcp_row.uuid} for dhcp_row in dhcp_rows]
        self.assertCountEqual(expected_rows, [
            subnet_options['subnet']] + subnet_options['ports'])
        # Test getting only subnet dhcp options
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-10-0-2-0', with_ports=True)
        dhcp_rows = [
            self._find_ovsdb_fake_row(self.dhcp_table, 'cidr', '10.0.2.0/24')]
        expected_rows = [{'cidr': dhcp_row.cidr,
                          'external_ids': dhcp_row.external_ids,
                          'options': dhcp_row.options,
                          'uuid': dhcp_row.uuid} for dhcp_row in dhcp_rows]
        self.assertCountEqual(expected_rows, [
            subnet_options['subnet']] + subnet_options['ports'])
        # Test getting no dhcp options
        subnet_options = self.nb_ovn_idl.get_subnet_dhcp_options(
            'subnet-id-11-0-2-0', with_ports=True)
        self.assertCountEqual({'subnet': None, 'ports': []}, subnet_options)

    def test_get_subnets_dhcp_options(self):
        self._load_nb_db()

        def get_row_dict(row):
            return {'cidr': row.cidr, 'external_ids': row.external_ids,
                    'options': row.options, 'uuid': row.uuid}

        subnets_options = self.nb_ovn_idl.get_subnets_dhcp_options(
            ['subnet-id-10-0-1-0', 'subnet-id-10-0-2-0'])
        expected_rows = [
            get_row_dict(
                self._find_ovsdb_fake_row(self.dhcp_table, 'cidr', cidr))
            for cidr in ('10.0.1.0/24', '10.0.2.0/24')]
        self.assertCountEqual(expected_rows, subnets_options)

        subnets_options = self.nb_ovn_idl.get_subnets_dhcp_options(
            ['subnet-id-11-0-2-0', 'subnet-id-20-0-1-0'])
        expected_row = get_row_dict(
            self._find_ovsdb_fake_row(self.dhcp_table, 'cidr', '20.0.1.0/24'))
        self.assertCountEqual([expected_row], subnets_options)

        subnets_options = self.nb_ovn_idl.get_subnets_dhcp_options(
            ['port-id-30-0-1-0', 'fake-not-exist'])
        self.assertEqual([], subnets_options)

    def test_get_all_dhcp_options(self):
        self._load_nb_db()
        dhcp_options = self.nb_ovn_idl.get_all_dhcp_options()
        self.assertEqual(len(dhcp_options['subnets']), 3)
        self.assertEqual(len(dhcp_options['ports_v4']), 2)

    def test_get_address_sets(self):
        self._load_nb_db()
        address_sets = self.nb_ovn_idl.get_address_sets()
        self.assertEqual(len(address_sets), 4)

    def test_get_router_floatingip_lbs(self):
        lrouter_name = 'rtr_name'
        # Empty
        lbs = self.nb_ovn_idl.get_router_floatingip_lbs(lrouter_name)
        self.assertEqual([], lbs)
        self._load_nb_db()
        lbs = self.nb_ovn_idl.get_router_floatingip_lbs('not_there')
        self.assertEqual([], lbs)
        lb1_row = self._find_ovsdb_fake_row(self.lb_table, 'name', 'lb_1')
        lb2_row = self._find_ovsdb_fake_row(self.lb_table, 'name', 'lb_2')
        lbs = self.nb_ovn_idl.get_router_floatingip_lbs(lrouter_name)
        self.assertEqual(lbs, [lb1_row, lb2_row])

    def test_get_floatingip_in_nat_or_lb(self):
        fip_id = 'fip_id_2'
        # Empty
        lb = self.nb_ovn_idl.get_floatingip_in_nat_or_lb(fip_id)
        self.assertIsNone(lb)
        self._load_nb_db()
        lb = self.nb_ovn_idl.get_floatingip_in_nat_or_lb('not_there')
        self.assertIsNone(lb)
        lb_row = self._find_ovsdb_fake_row(self.lb_table, 'name', 'lb_2')
        lb = self.nb_ovn_idl.get_floatingip_in_nat_or_lb(fip_id)
        self.assertEqual(lb['_uuid'], lb_row.uuid)


class TestSBImplIdlOvnBase(TestDBImplIdlOvn):

    fake_set = {
        'chassis': [
            {
                'hostname': 'fake-smartnic-dpu-chassis.fqdn',
                'other_config': {
                    ovn_const.OVN_CMS_OPTIONS: (
                        'firstoption,'
                        'card-serial-number=fake-serial,'
                        'thirdoption'),
                },
            },
        ],
    }
    fake_associations = {}

    def setUp(self):
        super(TestSBImplIdlOvnBase, self).setUp()

        self.chassis_table = fakes.FakeOvsdbTable.create_one_ovsdb_table()

        self._tables = {}
        self._tables['Chassis'] = self.chassis_table

        with mock.patch.object(impl_idl_ovn.OvsdbSbOvnIdl, 'from_worker',
                               return_value=mock.Mock()):
            with mock.patch.object(ovs_idl.Backend, 'autocreate_indices',
                                   create=True):
                impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection = None
                self.sb_ovn_idl = impl_idl_ovn.OvsdbSbOvnIdl(mock.MagicMock())

        self.sb_ovn_idl.idl.tables = self._tables

    def _load_sb_db(self):
        # Load Chassis
        fake_chassis = TestSBImplIdlOvnBase.fake_set['chassis']
        self._load_ovsdb_fake_rows(self.chassis_table, fake_chassis)


class TestSBImplIdlOvnGetChassisByCardSerialFromCMSOptions(
        TestSBImplIdlOvnBase):

    def test_chassis_not_found(self):
        self._load_sb_db()
        self.assertRaises(
            RuntimeError,
            self.sb_ovn_idl.get_chassis_by_card_serial_from_cms_options,
            'non-existent')

    def test_chassis_found(self):
        self._load_sb_db()
        self.assertEqual(
            'fake-smartnic-dpu-chassis.fqdn',
            self.sb_ovn_idl.get_chassis_by_card_serial_from_cms_options(
                'fake-serial').hostname)
