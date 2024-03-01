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
import uuid

import netaddr
from neutron_lib import constants
from oslo_utils import netutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
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
from neutron.tests.functional.common import ovn as ovn_common
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

    def _add_switch(self, chassis_name):
        sname = utils.get_rand_device_name(prefix='switch')
        chassis = self.api.lookup('Chassis', chassis_name)
        with self.nbapi.transaction(check_error=True) as txn:
            switch = txn.add(self.nbapi.ls_add(sname))
        return chassis, switch.result

    def _add_port_to_switch(
            self, switch, type=ovn_const.LSP_TYPE_LOCALPORT,
            device_owner=constants.DEVICE_OWNER_DISTRIBUTED):
        pname = utils.get_rand_device_name(prefix='port')
        row_event = events.WaitForCreatePortBindingEvent(pname)
        self.handler.watch_event(row_event)
        with self.nbapi.transaction(check_error=True) as txn:
            port = txn.add(self.nbapi.lsp_add(
                switch.uuid, pname, type=type,
                external_ids={
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: device_owner}))
        self.assertTrue(row_event.wait())
        return port.result, row_event.row

    def test_get_metadata_port_network(self):
        chassis, switch = self._add_switch(self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        result = self.api.get_metadata_port_network(str(binding.datapath.uuid))
        self.assertEqual(binding, result)
        self.assertEqual(binding.datapath.external_ids['logical-switch'],
                         str(switch.uuid))
        self.assertEqual(
            port.external_ids[ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY],
            constants.DEVICE_OWNER_DISTRIBUTED)

    def test_get_metadata_port_network_other_non_metadata_port(self):
        chassis, switch = self._add_switch(self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        port_lbhm, binding_port_lbhm = self._add_port_to_switch(
            switch, device_owner=ovn_const.OVN_LB_HM_PORT_DISTRIBUTED)
        result = self.api.get_metadata_port_network(str(binding.datapath.uuid))
        self.assertEqual(binding, result)
        self.assertEqual(binding.datapath.external_ids['logical-switch'],
                         str(switch.uuid))
        self.assertEqual(
            binding_port_lbhm.datapath.external_ids['logical-switch'],
            str(switch.uuid))
        self.assertEqual(
            port_lbhm.external_ids[ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY],
            ovn_const.OVN_LB_HM_PORT_DISTRIBUTED)

    def test_get_metadata_port_network_missing(self):
        val = str(uuid.uuid4())
        self.assertIsNone(self.api.get_metadata_port_network(val))

    def _create_bound_port_with_ip(self, mac, ipaddr):
        chassis, switch = self._add_switch(
            self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        mac_ip = '%s %s' % (mac, ipaddr)
        pb_update_event = events.WaitForUpdatePortBindingEvent(
            port.name, mac=[mac_ip])
        self.handler.watch_event(pb_update_event)
        self.nbapi.lsp_set_addresses(
            port.name, [mac_ip]).execute(check_error=True)
        self.assertTrue(pb_update_event.wait())
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)

        return binding, switch

    def test_get_network_port_bindings_by_ip(self):
        mac = 'de:ad:be:ef:4d:ad'
        ipaddr = '192.0.2.1'
        binding, switch = self._create_bound_port_with_ip(mac, ipaddr)
        # binding, ipaddr, switch = self._create_bound_port_with_ip()
        network_id = switch.name.replace('neutron-', '')
        result = self.api.get_network_port_bindings_by_ip(network_id, ipaddr)
        self.assertIn(binding, result)

    def test_get_network_port_bindings_by_ip_ipv6_ll(self):
        ipaddr = 'fe80::99'
        mac = str(netutils.get_mac_addr_by_ipv6(netaddr.IPAddress(ipaddr)))
        binding, switch = self._create_bound_port_with_ip(mac, ipaddr)
        network_id = switch.name.replace('neutron-', '')
        result = self.api.get_network_port_bindings_by_ip(network_id, ipaddr)
        self.assertIn(binding, result)

    def test_get_network_port_bindings_by_ip_with_unbound_port(self):
        mac = 'de:ad:be:ef:4d:ad'
        ipaddr = '192.0.2.1'
        binding, switch = self._create_bound_port_with_ip(mac, ipaddr)
        unbound_port_name = utils.get_rand_device_name(prefix="port")
        mac_ip = "de:ad:be:ef:4d:ab %s" % ipaddr
        with self.nbapi.transaction(check_error=True) as txn:
            txn.add(
                self.nbapi.lsp_add(switch.name, unbound_port_name, type=type))
            txn.add(self.nbapi.lsp_set_addresses(unbound_port_name, [mac_ip]))
        network_id = switch.name.replace('neutron-', '')
        result = self.api.get_network_port_bindings_by_ip(network_id, ipaddr)
        self.assertIn(binding, result)
        self.assertEqual(1, len(result))

    def test_get_ports_on_chassis(self):
        chassis, switch = self._add_switch(
            self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual([binding],
                         self.api.get_ports_on_chassis(chassis.name))

    def _test_get_ports_on_chassis_with_additional_chassis(
            self, ports, chassis, bindings, expected):
        self.api.lsp_bind(
            ports[0].name, chassis[0].name).execute(check_error=True)
        self.api.lsp_bind(
            ports[1].name, chassis[1].name).execute(check_error=True)

        self.api.db_set('Port_Binding', bindings[1].uuid,
            additional_chassis=[chassis[0].uuid]).execute(
                check_error=True, log_errors=True)

        result = self.api.get_ports_on_chassis(
            chassis[0].name, include_additional_chassis=True)

        self.assertEqual(expected, result)

    @ovn_common.skip_if_additional_chassis_not_supported('api')
    def test_get_ports_on_chassis_with_additional_chassis(self):
        chassis, switch = self._add_switch(self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        chassis2, switch2 = self._add_switch(self.data['chassis'][1]['name'])
        port2, binding2 = self._add_port_to_switch(switch2)

        self._test_get_ports_on_chassis_with_additional_chassis(
            ports=[port, port2],
            chassis=[chassis, chassis2],
            bindings=[binding, binding2],
            expected=[binding, binding2])

    def test_get_ports_on_chassis_with_additional_chassis_not_supported(self):
        chassis, switch = self._add_switch(self.data['chassis'][0]['name'])
        port, binding = self._add_port_to_switch(switch)
        chassis2, switch2 = self._add_switch(self.data['chassis'][1]['name'])
        port2, binding2 = self._add_port_to_switch(switch2)

        with mock.patch(
                'neutron.common.ovn.utils.is_additional_chassis_supported',
                return_value=False):
            self._test_get_ports_on_chassis_with_additional_chassis(
                ports=[port, port2],
                chassis=[chassis, chassis2],
                bindings=[binding, binding2],
                expected=[binding])


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

    def test_create_lswitch_port_ha_chassis_group(self):
        ls_name = uuidutils.generate_uuid()
        lsp_name = uuidutils.generate_uuid()
        hcg_name = uuidutils.generate_uuid()
        self.nbapi.ha_chassis_group_add(hcg_name).execute(check_error=True)
        hcg = self.nbapi.lookup('HA_Chassis_Group', hcg_name)
        self.nbapi.ls_add(ls_name).execute(check_error=True)
        self.nbapi.create_lswitch_port(
            lsp_name, ls_name, ha_chassis_group=hcg.uuid).execute(
            check_error=True)
        lsp = self.nbapi.lookup('Logical_Switch_Port', lsp_name)
        self.assertEqual(hcg.uuid, lsp.ha_chassis_group[0].uuid)

    def test_set_lswitch_port_ha_chassis_group(self):
        ls_name = uuidutils.generate_uuid()
        lsp_name = uuidutils.generate_uuid()
        self.nbapi.ls_add(ls_name).execute(check_error=True)
        self.nbapi.create_lswitch_port(lsp_name, ls_name).execute(
            check_error=True)
        lsp = self.nbapi.lookup('Logical_Switch_Port', lsp_name)
        self.assertEqual([], lsp.ha_chassis_group)

        # Create an HA Chassis Group register and assign to the LSP.
        hcg_name = uuidutils.generate_uuid()
        self.nbapi.ha_chassis_group_add(hcg_name).execute(check_error=True)
        hcg = self.nbapi.lookup('HA_Chassis_Group', hcg_name)
        self.nbapi.set_lswitch_port(
            lsp_name, ha_chassis_group=hcg.uuid).execute(check_error=True)
        lsp = self.nbapi.lookup('Logical_Switch_Port', lsp_name)
        self.assertEqual(hcg.uuid, lsp.ha_chassis_group[0].uuid)

        # Unassign the HA Chassis Group from the LSP.
        self.nbapi.set_lswitch_port(
            lsp_name, ha_chassis_group=[]).execute(check_error=True)
        lsp = self.nbapi.lookup('Logical_Switch_Port', lsp_name)
        self.assertEqual([], lsp.ha_chassis_group)

    def test_set_router_mac_aging(self):
        name = "aging_router1"
        with self.nbapi.transaction(check_error=True) as txn:
            r = txn.add(self.nbapi.lr_add(name))
            txn.add(self.nbapi.set_router_mac_age_limit(router=name))
        self.assertEqual(r.result.options[ovn_const.LR_OPTIONS_MAC_AGE_LIMIT],
                         ovn_conf.get_ovn_mac_binding_age_threshold())

    def test_set_router_mac_aging_all(self):
        ovn_conf.cfg.CONF.set_override("mac_binding_age_threshold", 5,
                                       group="ovn")
        names = ["aging_router2", "aging_router3"]
        with self.nbapi.transaction(check_error=True) as txn:
            for name in names:
                txn.add(self.nbapi.lr_add(name))
            txn.add(self.nbapi.set_router_mac_age_limit())
        for name in names:
            r = self.nbapi.lookup("Logical_Router", name)
            self.assertEqual(r.options[ovn_const.LR_OPTIONS_MAC_AGE_LIMIT],
                             ovn_conf.get_ovn_mac_binding_age_threshold())

    def _add_static_route(self, txn, lr_name, lrp_name, **columns):
        r = txn.add(self.nbapi.lr_add(lr_name))
        if lrp_name:
            txn.add(self.nbapi.add_lrouter_port(lrp_name, lr_name))
            columns.update({'output_port': lrp_name})
        txn.add(self.nbapi.add_static_route(lr_name, **columns))

        return r

    def test_add_static_route(self):
        name = 'router_with_static_routes'
        columns = {
            'bfd': [],
            'external_ids': {'fake_eid_key': 'fake_eid_value'},
            'ip_prefix': '0.0.0.0/0',
            'nexthop': '192.0.2.1',
            'options': {'fake_option_key': 'fake_option_value'},
            'output_port': [],
            'policy': ['dst-ip'],
            'route_table': '',
        }
        with self.nbapi.transaction(check_error=True) as txn:
            r = self._add_static_route(txn, name, '', **columns)
        for route in r.result.static_routes:
            for k, v in columns.items():
                self.assertEqual(
                    getattr(route, k),
                    v)

    def _add_static_route_bfd_assert(self, r, lr_name, lrp_name, ip_prefix,
                                     nexthop):
        for route in r.result.static_routes:
            self.assertEqual(
                route.ip_prefix,
                ip_prefix)
            self.assertEqual(
                route.nexthop,
                nexthop)
            self.assertEqual(
                route.output_port[0],
                lrp_name)

            self.assertEqual(
                route.bfd[0].logical_port,
                lrp_name)
            self.assertEqual(
                route.bfd[0].dst_ip,
                nexthop)

    def test_add_static_route_bfd(self):
        lr_name = 'router_with_static_routes_and_bfd'
        lrp_name = 'lrp-' + lr_name
        ip_prefix = '0.0.0.0/0'
        nexthop = '192.0.2.1'
        with self.nbapi.transaction(check_error=True) as txn:
            r = self._add_static_route(txn, lr_name, lrp_name,
                                       ip_prefix=ip_prefix,
                                       nexthop=nexthop,
                                       maintain_bfd=True)

        self._add_static_route_bfd_assert(r, lr_name, lrp_name, ip_prefix,
                                          nexthop)

    def test_add_static_route_bfd_record_exists(self):
        lr_name = 'router_with_static_routes_and_preexisting_bfd_record'
        lrp_name = 'lrp-' + lr_name
        ip_prefix = '0.0.0.0/0'
        nexthop = '192.0.2.1'
        with self.nbapi.transaction(check_error=True) as txn:
            bfd = txn.add(self.nbapi.bfd_add(lrp_name, nexthop))
            r = self._add_static_route(txn, lr_name, lrp_name,
                                       ip_prefix=ip_prefix,
                                       nexthop=nexthop,
                                       maintain_bfd=True)

        for route in r.result.static_routes:
            self.assertEqual(
                bfd.result,
                route.bfd[0],
            )
        self._add_static_route_bfd_assert(r, lr_name, lrp_name, ip_prefix,
                                          nexthop)

    def test_add_static_route_bfd_record_exists_multiple_txn(self):
        lr_name = 'router_with_static_routes_and_preexisting_bfd_record_txn'
        lrp_name = 'lrp-' + lr_name
        ip_prefix = '0.0.0.0/0'
        nexthop = '192.0.2.1'
        with self.nbapi.transaction(check_error=True) as txn:
            bfd = txn.add(self.nbapi.bfd_add(lrp_name, nexthop))
        with self.nbapi.transaction(check_error=True) as txn:
            r = self._add_static_route(txn, lr_name, lrp_name,
                                       ip_prefix=ip_prefix,
                                       nexthop=nexthop,
                                       maintain_bfd=True)

        for route in r.result.static_routes:
            self.assertEqual(
                bfd.result,
                route.bfd[0],
            )
        self._add_static_route_bfd_assert(r, lr_name, lrp_name, ip_prefix,
                                          nexthop)

    def test_delete_lrouter_ext_gw(self):
        lr_name = 'router_with_ext_gw'
        ip_prefix = '0.0.0.0/0'
        nexthop = '192.0.2.1'
        external_ids = {ovn_const.OVN_ROUTER_IS_EXT_GW: 'True'}
        with self.nbapi.transaction(check_error=True) as txn:
            r = self._add_static_route(txn, lr_name, '',
                                       ip_prefix=ip_prefix,
                                       nexthop=nexthop,
                                       external_ids=external_ids)

        uuids = []
        for route in r.result.static_routes:
            lkp = self.nbapi.lookup("Logical_Router_Static_Route", route.uuid)
            uuids.append(lkp.uuid)
        self.assertTrue(len(uuids))

        with self.nbapi.transaction(check_error=True) as txn:
            txn.add(self.nbapi.delete_lrouter_ext_gw(lr_name))

        for route_uuid in uuids:
            self.assertRaises(
                idlutils.RowNotFound,
                self.nbapi.lookup,
                "Logical_Router_Static_Route",
                route_uuid)

    def test_delete_lrouter_ext_gw_bfd(self):
        lr_name = 'router_with_ext_gw_bfd'
        lrp_name = 'lrp-' + lr_name
        ip_prefix = '0.0.0.0/0'
        nexthop = '192.0.2.1'
        external_ids = {ovn_const.OVN_ROUTER_IS_EXT_GW: 'True'}
        with self.nbapi.transaction(check_error=True) as txn:
            r = self._add_static_route(txn, lr_name, lrp_name,
                                       ip_prefix=ip_prefix,
                                       nexthop=nexthop,
                                       external_ids=external_ids,
                                       maintain_bfd=True)

        uuids = []
        bfd_uuids = []
        for route in r.result.static_routes:
            lkp = self.nbapi.lookup("Logical_Router_Static_Route", route.uuid)
            uuids.append(lkp.uuid)
            self.assertTrue(len(lkp.bfd))
            for bfd_rec in lkp.bfd:
                bfd_uuids.append(bfd_rec.uuid)
        self.assertTrue(len(uuids))
        self.assertTrue(len(bfd_uuids))

        with self.nbapi.transaction(check_error=True) as txn:
            txn.add(self.nbapi.delete_lrouter_ext_gw(lr_name))

        for route_uuid in uuids:
            self.assertRaises(
                idlutils.RowNotFound,
                self.nbapi.lookup,
                "Logical_Router_Static_Route",
                route_uuid)

        for bfd_uuid in bfd_uuids:
            self.assertRaises(
                idlutils.RowNotFound,
                self.nbapi.lookup,
                "BFD",
                bfd_uuid)


class TestIgnoreConnectionTimeout(BaseOvnIdlTest):
    @classmethod
    def create_connection(cls, schema):
        idl = connection.OvsdbIdl.from_server(cls.schema_map[schema], schema)
        return connection.Connection(idl, 0)

    def test_setUp_will_fail_if_this_is_broken(self):
        pass
