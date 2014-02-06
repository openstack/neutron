# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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

from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.plugins.ml2 import config
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_extradhcpopts as test_dhcpopts
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class Ml2PluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME
    _mechanism_drivers = ['logger', 'test']

    def setUp(self):
        # We need a L3 service plugin
        l3_plugin = ('neutron.tests.unit.test_l3_plugin.'
                     'TestL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     self._mechanism_drivers,
                                     group='ml2')
        self.physnet = 'physnet1'
        self.vlan_range = '1:100'
        self.phys_vrange = ':'.join([self.physnet, self.vlan_range])
        config.cfg.CONF.set_override('network_vlan_ranges', [self.phys_vrange],
                                     group='ml2_type_vlan')
        self.addCleanup(config.cfg.CONF.reset)
        super(Ml2PluginV2TestCase, self).setUp(PLUGIN_NAME,
                                               service_plugins=service_plugins)
        self.port_create_status = 'DOWN'


class TestMl2BulkToggle(Ml2PluginV2TestCase):

    def test_bulk_disable_with_bulkless_driver(self):
        self.tearDown()
        self._mechanism_drivers = ['logger', 'test', 'bulkless']
        self.setUp()
        self.assertTrue(self._skip_native_bulk)

    def test_bulk_enabled_with_bulk_drivers(self):
        self.tearDown()
        self._mechanism_drivers = ['logger', 'test']
        self.setUp()
        self.assertFalse(self._skip_native_bulk)


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      Ml2PluginV2TestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            Ml2PluginV2TestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        Ml2PluginV2TestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2, Ml2PluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')


class TestMl2PortBinding(Ml2PluginV2TestCase,
                         test_bindings.PortBindingsTestCase):
    # Test case does not set binding:host_id, so ml2 does not attempt
    # to bind port
    VIF_TYPE = portbindings.VIF_TYPE_UNBOUND
    HAS_PORT_FILTER = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self, firewall_driver=None):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        super(TestMl2PortBinding, self).setUp()


class TestMl2PortBindingNoSG(TestMl2PortBinding):
    HAS_PORT_FILTER = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestMl2PortBindingHost(Ml2PluginV2TestCase,
                             test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestMultiSegmentNetworks(Ml2PluginV2TestCase):

    def setUp(self, plugin=None):
        super(TestMultiSegmentNetworks, self).setUp()

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_single_multiprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        net_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_multiprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 2}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

    def test_create_network_with_provider_and_multiprovider_fail(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_duplicate_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)
