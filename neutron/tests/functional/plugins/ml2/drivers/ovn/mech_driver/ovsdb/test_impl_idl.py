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
import uuid

from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import constants as const
from ovsdbapp import event as ovsdb_event
from ovsdbapp.tests.functional import base
from ovsdbapp.tests import utils

from neutron.common.ovn import constants as ovn_const
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb \
    import impl_idl_ovn as impl
from neutron.services.portforwarding import constants as pf_const
from neutron.tests.functional import base as n_base
from neutron.tests.functional.resources.ovsdb import events

OWNER = ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY
PF_PLUGIN = pf_const.PORT_FORWARDING_PLUGIN


class BaseOvnIdlTest(n_base.BaseLoggingTestCase,
                     base.FunctionalTestCase):
    schemas = ['OVN_Southbound', 'OVN_Northbound']

    def setUp(self):
        super(BaseOvnIdlTest, self).setUp()
        ovn_conf.register_opts()
        self.api = impl.OvsdbSbOvnIdl(self.connection['OVN_Southbound'])
        self.nbapi = impl.OvsdbNbOvnIdl(self.connection['OVN_Northbound'])
        self.handler = ovsdb_event.RowEventHandler()
        self.api.idl.notify = self.handler.notify


class TestSbApi(BaseOvnIdlTest):

    def setUp(self):
        super(TestSbApi, self).setUp()
        self.data = {
            'chassis': [
                {'other_config': {'ovn-bridge-mappings':
                                  'public:br-ex,private:br-0'}},
                {'other_config': {'ovn-bridge-mappings':
                                  'public:br-ex,public2:br-ex2'}},
                {'other_config': {'ovn-bridge-mappings':
                                  'public:br-ex'}},
            ]
        }
        self.load_test_data()

    def load_test_data(self):
        with self.api.transaction(check_error=True) as txn:
            for chassis in self.data['chassis']:
                chassis['name'] = utils.get_rand_device_name('chassis')
                chassis['hostname'] = '%s.localdomain.com' % chassis['name']
                txn.add(self.api.chassis_add(
                    chassis['name'], ['geneve'], chassis['hostname'],
                    hostname=chassis['hostname'],
                    other_config=chassis['other_config']))

    def test_get_chassis_hostname_and_physnets(self):
        mapping = self.api.get_chassis_hostname_and_physnets()
        self.assertLessEqual(len(self.data['chassis']), len(mapping))
        self.assertGreaterEqual(set(mapping.keys()),
                                {c['hostname'] for c in self.data['chassis']})

    def test_get_all_chassis(self):
        chassis_list = set(self.api.get_all_chassis())
        our_chassis = {c['name'] for c in self.data['chassis']}
        self.assertLessEqual(our_chassis, chassis_list)

    def test_chassis_exists(self):
        self.assertTrue(self.api.chassis_exists(
            self.data['chassis'][0]['hostname']))
        self.assertFalse(self.api.chassis_exists("nochassishere"))

    def test_get_chassis_and_physnets(self):
        mapping = self.api.get_chassis_and_physnets()
        self.assertLessEqual(len(self.data['chassis']), len(mapping))
        self.assertGreaterEqual(set(mapping.keys()),
                                {c['name'] for c in self.data['chassis']})

    def test_multiple_physnets_in_one_bridge(self):
        self.data = {
            'chassis': [
                {'other_config': {'ovn-bridge-mappings': 'p1:br-ex,p2:br-ex'}}
            ]
        }
        self.load_test_data()
        self.assertRaises(ValueError, self.api.get_chassis_and_physnets)

    def _add_switch_port(self, chassis_name,
                         type=ovn_const.LSP_TYPE_LOCALPORT):
        sname, pname = (utils.get_rand_device_name(prefix=p)
                        for p in ('switch', 'port'))
        chassis = self.api.lookup('Chassis', chassis_name)
        row_event = events.WaitForCreatePortBindingEvent(pname)
        self.handler.watch_event(row_event)
        with self.nbapi.transaction(check_error=True) as txn:
            switch = txn.add(self.nbapi.ls_add(sname))
            port = txn.add(self.nbapi.lsp_add(sname, pname, type=type))
        row_event.wait()
        return chassis, switch.result, port.result, row_event.row

    def test_get_metadata_port_network(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        result = self.api.get_metadata_port_network(str(binding.datapath.uuid))
        self.assertEqual(binding, result)
        self.assertEqual(binding.datapath.external_ids['logical-switch'],
                         str(switch.uuid))

    def test_get_metadata_port_network_missing(self):
        val = str(uuid.uuid4())
        self.assertIsNone(self.api.get_metadata_port_network(val))

    def _create_bound_port_with_ip(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        mac = 'de:ad:be:ef:4d:ad'
        ipaddr = '192.0.2.1'
        mac_ip = '%s %s' % (mac, ipaddr)
        pb_update_event = events.WaitForUpdatePortBindingEvent(
            port.name, mac=[mac_ip])
        self.handler.watch_event(pb_update_event)
        self.nbapi.lsp_set_addresses(
            port.name, [mac_ip]).execute(check_error=True)
        self.assertTrue(pb_update_event.wait())
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)

        return binding, ipaddr, switch

    def test_get_network_port_bindings_by_ip(self):
        binding, ipaddr, _ = self._create_bound_port_with_ip()
        result = self.api.get_network_port_bindings_by_ip(
            str(binding.datapath.uuid), ipaddr)
        self.assertIn(binding, result)

    def test_get_network_port_bindings_by_ip_with_unbound_port(self):
        binding, ipaddr, switch = self._create_bound_port_with_ip()
        unbound_port_name = utils.get_rand_device_name(prefix="port")
        mac_ip = "de:ad:be:ef:4d:ab %s" % ipaddr
        with self.nbapi.transaction(check_error=True) as txn:
            txn.add(
                self.nbapi.lsp_add(switch.name, unbound_port_name, type=type))
            txn.add(self.nbapi.lsp_set_addresses(unbound_port_name, [mac_ip]))
        result = self.api.get_network_port_bindings_by_ip(
            str(binding.datapath.uuid), ipaddr)
        self.assertIn(binding, result)
        self.assertEqual(1, len(result))

    def test_get_ports_on_chassis(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual([binding],
                         self.api.get_ports_on_chassis(chassis.name))


class TestNbApi(BaseOvnIdlTest):

    def setUp(self):
        super(TestNbApi, self).setUp()
        self.data = {
            'lbs': [
                {'name': 'pf-floatingip-fip_id1-tcp',
                 'protocol': const.PROTO_TCP,
                 'vips': {"172.24.4.8:2020": ["10.0.0.10:22"],
                          "172.24.4.8:2021": ["10.0.0.11:22"]},
                 'external_ids': {
                     ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                         pf_const.PORT_FORWARDING_PLUGIN,
                     ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id1',
                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                     ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'neutron-rtr1_id'}},
                {'name': 'pf-floatingip-fip_id1-udp',
                 'protocol': const.PROTO_UDP,
                 'vips': {"172.24.4.8:53": ["10.0.0.10:53"]},
                 'external_ids': {
                     ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                         pf_const.PORT_FORWARDING_PLUGIN,
                     ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id1',
                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                     ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'neutron-rtr1_id'}},
                {'name': 'pf-floatingip-fip_id2-tcp',
                 'protocol': const.PROTO_TCP,
                 'vips': {"172.24.4.100:2020": ["10.0.0.10:22"]},
                 'external_ids': {
                     ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                         pf_const.PORT_FORWARDING_PLUGIN,
                     ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id2',
                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '10',
                     ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'neutron-rtr2_id'}},
                {'name': 'octavia_lb1_id',
                 'vips': {"172.24.4.250:80": ["10.0.0.10:8080",
                                              "10.0.0.11:8080"]},
                 'selection_fields': ['ip_dst', 'ip_src', 'tp_dst', 'tp_src'],
                 'external_ids': {
                     'enabled': 'True',
                     'lr_ref': 'neutron-rtr1_id',
                     'ls_refs': str({'neutron-net1_id': 1}),
                     ovn_const.LB_EXT_IDS_VIP_KEY: '172.24.4.250',
                     ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'neutron-port1_id',
                 }},
            ],
        }
        self.load_test_data()

    def load_test_data(self):
        with self.nbapi.transaction(check_error=True) as txn:
            for lb in copy.deepcopy(self.data['lbs']):
                lb_name = lb.pop('name')
                for vip, ips in lb.pop('vips').items():
                    txn.add(self.nbapi.lb_add(
                        lb_name, vip, ips, may_exist=True, **lb))

    def test_lb_list(self):
        lbs = self.nbapi.lb_list().execute(check_error=True)
        self.assertEqual(len(self.data['lbs']), len(lbs))
        exp_values = [(lb['name'], lb['external_ids'])
                      for lb in self.data['lbs']]
        lbs_values = [(lb.name, lb.external_ids) for lb in lbs]
        self.assertCountEqual(exp_values, lbs_values)

    def test_get_router_floatingip_lbs(self):
        f = self.nbapi.get_router_floatingip_lbs
        self.assertEqual([], f('unused_router_name'))
        for exp_router_name in ['neutron-rtr1_id', 'neutron-rtr2_id']:
            exp_values = [
                (lb['name'], lb['external_ids'])
                for lb in self.data['lbs']
                if all([lb['external_ids'].get(OWNER) == PF_PLUGIN,
                        lb['external_ids'].get(
                            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY) ==
                        exp_router_name])]
            lbs_values = [(lb.name, lb.external_ids)
                          for lb in f(exp_router_name)]
            self.assertTrue(exp_values)
            self.assertCountEqual(exp_values, lbs_values)

    def test_get_floatingip_in_nat_or_lb(self):
        f = self.nbapi.get_floatingip_in_nat_or_lb
        self.assertIsNone(f('unused_fip_id'))
        for exp_fip_id in ['fip_id1', 'fip_id2']:
            exp_values = [
                (lb['name'], lb['external_ids'])
                for lb in self.data['lbs']
                if all([lb['external_ids'].get(OWNER) == PF_PLUGIN,
                        lb['external_ids'].get(
                            ovn_const.OVN_FIP_EXT_ID_KEY) == exp_fip_id])]
            # get_floatingip_in_nat_or_lb returns the first entry
            # it finds for the fip_id provided. Make sure that it
            # is present in exp_values.
            lb_match = f(exp_fip_id)
            self.assertIn((lb_match['name'], lb_match['external_ids']),
                          exp_values)


class TestIgnoreConnectionTimeout(BaseOvnIdlTest):
    @classmethod
    def create_connection(cls, schema):
        idl = connection.OvsdbIdl.from_server(cls.schema_map[schema], schema)
        return connection.Connection(idl, 0)

    def test_setUp_will_fail_if_this_is_broken(self):
        pass
