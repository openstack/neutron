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

import mock
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.tests.unit.plugins.ml2.drivers import ext_test
from neutron.tests.unit.plugins.ml2 import test_plugin


class ExtensionDriverTestCase(test_plugin.Ml2PluginV2TestCase):

    _extension_drivers = ['test']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(ExtensionDriverTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._ctxt = context.get_admin_context()

    def _verify_network_create(self, code, exc_reason):
        tenant_id = uuidutils.generate_uuid()
        data = {'network': {'name': 'net1',
                            'tenant_id': tenant_id}}
        req = self.new_create_request('networks', data)
        res = req.get_response(self.api)
        self.assertEqual(code, res.status_int)

        network = self.deserialize(self.fmt, res)
        if exc_reason:
            self.assertEqual(exc_reason,
                             network['NeutronError']['type'])

        return (network, tenant_id)

    def _verify_network_update(self, network, code, exc_reason):
        net_id = network['network']['id']
        new_name = 'a_brand_new_name'
        data = {'network': {'name': new_name}}
        req = self.new_update_request('networks', data, net_id)
        res = req.get_response(self.api)
        self.assertEqual(code, res.status_int)
        error = self.deserialize(self.fmt, res)
        self.assertEqual(exc_reason,
                         error['NeutronError']['type'])

    def test_faulty_process_create(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_create_network',
                               side_effect=TypeError):
            net, tenant_id = self._verify_network_create(500,
                                                    'HTTPInternalServerError')
            # Verify the operation is rolled back
            query_params = "tenant_id=%s" % tenant_id
            nets = self._list('networks', query_params=query_params)
            self.assertFalse(nets['networks'])

    def test_faulty_process_update(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_network',
                               side_effect=TypeError):
            network, tid = self._verify_network_create(201, None)
            self._verify_network_update(network, 500,
                                        'HTTPInternalServerError')

    def test_faulty_extend_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'extend_network_dict',
                               side_effect=[None, None, TypeError]):
            network, tid = self._verify_network_create(201, None)
            self._verify_network_update(network, 400, 'ExtensionDriverError')

    def test_network_attr(self):
        with self.network() as network:
            # Test create network
            ent = network['network'].get('network_extension')
            self.assertIsNotNone(ent)

            # Test list networks
            res = self._list('networks')
            val = res['networks'][0].get('network_extension')
            self.assertEqual('default_network_extension', val)

            # Test network update
            data = {'network':
                    {'network_extension': 'Test_Network_Extension_Update'}}
            res = self._update('networks', network['network']['id'], data)
            val = res['network'].get('network_extension')
            self.assertEqual('Test_Network_Extension_Update', val)

    def test_subnet_attr(self):
        with self.subnet() as subnet:
            # Test create subnet
            ent = subnet['subnet'].get('subnet_extension')
            self.assertIsNotNone(ent)

            # Test list subnets
            res = self._list('subnets')
            val = res['subnets'][0].get('subnet_extension')
            self.assertEqual('default_subnet_extension', val)

            # Test subnet update
            data = {'subnet':
                    {'subnet_extension': 'Test_Subnet_Extension_Update'}}
            res = self._update('subnets', subnet['subnet']['id'], data)
            val = res['subnet'].get('subnet_extension')
            self.assertEqual('Test_Subnet_Extension_Update', val)

    def test_port_attr(self):
        with self.port() as port:
            # Test create port
            ent = port['port'].get('port_extension')
            self.assertIsNotNone(ent)

            # Test list ports
            res = self._list('ports')
            val = res['ports'][0].get('port_extension')
            self.assertEqual('default_port_extension', val)

            # Test port update
            data = {'port': {'port_extension': 'Test_Port_Extension_Update'}}
            res = self._update('ports', port['port']['id'], data)
            val = res['port'].get('port_extension')
            self.assertEqual('Test_Port_Extension_Update', val)

    def test_extend_network_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_network') as ext_update_net,\
                mock.patch.object(ext_test.TestExtensionDriver,
                                  'extend_network_dict') as ext_net_dict,\
                self.network() as network:
            net_id = network['network']['id']
            net_data = {'network': {'id': net_id}}
            self._plugin.update_network(self._ctxt, net_id, net_data)
            self.assertTrue(ext_update_net.called)
            self.assertTrue(ext_net_dict.called)

    def test_extend_subnet_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_subnet') as ext_update_subnet,\
                mock.patch.object(ext_test.TestExtensionDriver,
                                  'extend_subnet_dict') as ext_subnet_dict,\
                self.subnet() as subnet:
            subnet_id = subnet['subnet']['id']
            subnet_data = {'subnet': {'id': subnet_id}}
            self._plugin.update_subnet(self._ctxt, subnet_id, subnet_data)
            self.assertTrue(ext_update_subnet.called)
            self.assertTrue(ext_subnet_dict.called)

    def test_extend_port_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_port') as ext_update_port,\
                mock.patch.object(ext_test.TestExtensionDriver,
                                  'extend_port_dict') as ext_port_dict,\
                self.port() as port:
            port_id = port['port']['id']
            port_data = {'port': {'id': port_id}}
            self._plugin.update_port(self._ctxt, port_id, port_data)
            self.assertTrue(ext_update_port.called)
            self.assertTrue(ext_port_dict.called)


class DBExtensionDriverTestCase(test_plugin.Ml2PluginV2TestCase):
    _extension_drivers = ['testdb']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(DBExtensionDriverTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._ctxt = context.get_admin_context()

    def test_network_attr(self):
        with self.network() as network:
            # Test create with default value.
            net_id = network['network']['id']
            val = network['network']['network_extension']
            self.assertEqual("", val)
            res = self._show('networks', net_id)
            val = res['network']['network_extension']
            self.assertEqual("", val)

            # Test list.
            res = self._list('networks')
            val = res['networks'][0]['network_extension']
            self.assertEqual("", val)

        # Test create with explicit value.
        res = self._create_network(self.fmt,
                                   'test-network', True,
                                   arg_list=('network_extension', ),
                                   network_extension="abc")
        network = self.deserialize(self.fmt, res)
        net_id = network['network']['id']
        val = network['network']['network_extension']
        self.assertEqual("abc", val)
        res = self._show('networks', net_id)
        val = res['network']['network_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'network': {'network_extension': "def"}}
        res = self._update('networks', net_id, data)
        val = res['network']['network_extension']
        self.assertEqual("def", val)
        res = self._show('networks', net_id)
        val = res['network']['network_extension']
        self.assertEqual("def", val)

    def test_subnet_attr(self):
        with self.subnet() as subnet:
            # Test create with default value.
            net_id = subnet['subnet']['id']
            val = subnet['subnet']['subnet_extension']
            self.assertEqual("", val)
            res = self._show('subnets', net_id)
            val = res['subnet']['subnet_extension']
            self.assertEqual("", val)

            # Test list.
            res = self._list('subnets')
            val = res['subnets'][0]['subnet_extension']
            self.assertEqual("", val)

        with self.network() as network:
            # Test create with explicit value.
            data = {'subnet':
                    {'network_id': network['network']['id'],
                     'cidr': '10.1.0.0/24',
                     'ip_version': constants.IP_VERSION_4,
                     'tenant_id': self._tenant_id,
                     'subnet_extension': 'abc'}}
            req = self.new_create_request('subnets', data, self.fmt)
            res = req.get_response(self.api)
            subnet = self.deserialize(self.fmt, res)
            subnet_id = subnet['subnet']['id']
            val = subnet['subnet']['subnet_extension']
            self.assertEqual("abc", val)
            res = self._show('subnets', subnet_id)
            val = res['subnet']['subnet_extension']
            self.assertEqual("abc", val)

            # Test update.
            data = {'subnet': {'subnet_extension': "def"}}
            res = self._update('subnets', subnet_id, data)
            val = res['subnet']['subnet_extension']
            self.assertEqual("def", val)
            res = self._show('subnets', subnet_id)
            val = res['subnet']['subnet_extension']
            self.assertEqual("def", val)

    def test_port_attr(self):
        with self.port() as port:
            # Test create with default value.
            net_id = port['port']['id']
            val = port['port']['port_extension']
            self.assertEqual("", val)
            res = self._show('ports', net_id)
            val = res['port']['port_extension']
            self.assertEqual("", val)

            # Test list.
            res = self._list('ports')
            val = res['ports'][0]['port_extension']
            self.assertEqual("", val)

        with self.network() as network:
            # Test create with explicit value.
            res = self._create_port(self.fmt,
                                    network['network']['id'],
                                    arg_list=('port_extension', ),
                                    port_extension="abc")
            port = self.deserialize(self.fmt, res)
            port_id = port['port']['id']
            val = port['port']['port_extension']
            self.assertEqual("abc", val)
            res = self._show('ports', port_id)
            val = res['port']['port_extension']
            self.assertEqual("abc", val)

            # Test update.
            data = {'port': {'port_extension': "def"}}
            res = self._update('ports', port_id, data)
            val = res['port']['port_extension']
            self.assertEqual("def", val)
            res = self._show('ports', port_id)
            val = res['port']['port_extension']
            self.assertEqual("def", val)
