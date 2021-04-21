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

import uuid

from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import event as ovsdb_event
from ovsdbapp.tests.functional import base
from ovsdbapp.tests import utils

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb \
    import impl_idl_ovn as impl
from neutron.tests.functional import base as n_base
from neutron.tests.functional.resources.ovsdb import events


class TestSbApi(base.FunctionalTestCase,
                n_base.BaseLoggingTestCase):
    schemas = ['OVN_Southbound', 'OVN_Northbound']

    def setUp(self):
        super(TestSbApi, self).setUp()
        self.data = {
            'chassis': [
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex,private:br-0'}},
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex,public2:br-ex'}},
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex'}},
            ]
        }
        self.api = impl.OvsdbSbOvnIdl(self.connection['OVN_Southbound'])
        self.nbapi = impl.OvsdbNbOvnIdl(self.connection['OVN_Northbound'])
        self.load_test_data()
        self.handler = ovsdb_event.RowEventHandler()
        self.api.idl.notify = self.handler.notify

    def load_test_data(self):
        with self.api.transaction(check_error=True) as txn:
            for chassis in self.data['chassis']:
                chassis['name'] = utils.get_rand_device_name('chassis')
                chassis['hostname'] = '%s.localdomain.com' % chassis['name']
                txn.add(self.api.chassis_add(
                    chassis['name'], ['geneve'], chassis['hostname'],
                    hostname=chassis['hostname'],
                    external_ids=chassis['external_ids']))

    def test_get_chassis_hostname_and_physnets(self):
        mapping = self.api.get_chassis_hostname_and_physnets()
        self.assertLessEqual(len(self.data['chassis']), len(mapping))
        self.assertGreaterEqual(set(mapping.keys()),
                                {c['hostname'] for c in self.data['chassis']})

    def test_get_all_chassis(self):
        chassis_list = set(self.api.get_all_chassis())
        our_chassis = {c['name'] for c in self.data['chassis']}
        self.assertLessEqual(our_chassis, chassis_list)

    def test_get_chassis_data_for_ml2_bind_port(self):
        host = self.data['chassis'][0]['hostname']
        dp, iface, phys = self.api.get_chassis_data_for_ml2_bind_port(host)
        self.assertEqual('', dp)
        self.assertEqual('', iface)
        self.assertItemsEqual(phys, ['private', 'public'])

    def test_chassis_exists(self):
        self.assertTrue(self.api.chassis_exists(
            self.data['chassis'][0]['hostname']))
        self.assertFalse(self.api.chassis_exists("nochassishere"))

    def test_get_chassis_and_physnets(self):
        mapping = self.api.get_chassis_and_physnets()
        self.assertLessEqual(len(self.data['chassis']), len(mapping))
        self.assertGreaterEqual(set(mapping.keys()),
                                {c['name'] for c in self.data['chassis']})

    def _add_switch_port(self, chassis_name, type='localport'):
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

    def test_set_get_chassis_metadata_networks(self):
        name = self.data['chassis'][0]['name']
        nets = [str(uuid.uuid4()) for _ in range(3)]
        self.api.set_chassis_metadata_networks(name, nets).execute(
            check_error=True)
        self.assertEqual(nets, self.api.get_chassis_metadata_networks(name))

    def test_get_network_port_bindings_by_ip(self):
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
        result = self.api.get_network_port_bindings_by_ip(
            str(binding.datapath.uuid), ipaddr)
        self.assertIn(binding, result)

    def test_get_ports_on_chassis(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual([binding],
                         self.api.get_ports_on_chassis(chassis.name))

    def test_get_logical_port_chassis_and_datapath(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual(
            (chassis.name, str(binding.datapath.uuid)),
            self.api.get_logical_port_chassis_and_datapath(port.name))


class TestIgnoreConnectionTimeout(base.FunctionalTestCase,
                                  n_base.BaseLoggingTestCase):
    schemas = ['OVN_Southbound', 'OVN_Northbound']

    def setUp(self):
        super(TestIgnoreConnectionTimeout, self).setUp()
        self.api = impl.OvsdbSbOvnIdl(self.connection['OVN_Southbound'])
        self.nbapi = impl.OvsdbNbOvnIdl(self.connection['OVN_Northbound'])
        self.handler = ovsdb_event.RowEventHandler()
        self.api.idl.notify = self.handler.notify

    @classmethod
    def create_connection(cls, schema):
        idl = connection.OvsdbIdl.from_server(cls.schema_map[schema], schema)
        return connection.Connection(idl, 0)

    def test_setUp_will_fail_if_this_is_broken(self):
        pass
