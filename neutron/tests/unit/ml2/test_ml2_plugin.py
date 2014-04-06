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

import contextlib
import mock
import testtools
import webob

from neutron.common import exceptions as exc
from neutron import context
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_allowedaddresspairs as test_pair
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
        super(Ml2PluginV2TestCase, self).setUp(PLUGIN_NAME,
                                               service_plugins=service_plugins)
        self.port_create_status = 'DOWN'
        self.driver = ml2_plugin.Ml2Plugin()
        self.context = context.get_admin_context()


class TestMl2BulkToggleWithBulkless(Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'test', 'bulkless']

    def test_bulk_disable_with_bulkless_driver(self):
        self.assertTrue(self._skip_native_bulk)


class TestMl2BulkToggleWithoutBulkless(Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'test']

    def test_bulk_enabled_with_bulk_drivers(self):
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

    def test_update_non_existent_port(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        data = {'port': {'admin_state_up': False}}
        self.assertRaises(exc.PortNotFound, plugin.update_port, ctx,
                          'invalid-uuid', data)

    def test_delete_non_existent_port(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(ml2_plugin.LOG, 'debug') as log_debug:
            plugin.delete_port(ctx, 'invalid-uuid', l3_port_check=False)
            log_debug.assert_has_calls([
                mock.call(_("Deleting port %s"), 'invalid-uuid'),
                mock.call(_("The port '%s' was deleted"), 'invalid-uuid')
            ])

    def test_delete_port_no_notify_in_disassociate_floatingips(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        with contextlib.nested(
            self.port(no_delete=True),
            mock.patch.object(l3plugin, 'disassociate_floatingips'),
            mock.patch.object(l3plugin, 'notify_routers_updated')
        ) as (port, disassociate_floatingips, notify):

            port_id = port['port']['id']
            plugin.delete_port(ctx, port_id)

            # check that no notification was requested while under
            # transaction
            disassociate_floatingips.assert_has_calls([
                mock.call(ctx, port_id, do_notify=False)
            ])

            # check that notifier was still triggered
            notify.assert_has_calls([
                mock.call(ctx, disassociate_floatingips.return_value)
            ])

    def test_disassociate_floatingips_do_notify_returns_nothing(self):
        ctx = context.get_admin_context()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        with self.port() as port:

            port_id = port['port']['id']
            # check that nothing is returned when notifications are handled
            # by the called method
            self.assertIsNone(l3plugin.disassociate_floatingips(ctx, port_id))


class TestMl2PortBinding(Ml2PluginV2TestCase,
                         test_bindings.PortBindingsTestCase):
    # Test case does not set binding:host_id, so ml2 does not attempt
    # to bind port
    VIF_TYPE = portbindings.VIF_TYPE_UNBOUND
    HAS_PORT_FILTER = False
    ENABLE_SG = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self, firewall_driver=None):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        config.cfg.CONF.set_override(
            'enable_security_group', self.ENABLE_SG,
            group='SECURITYGROUP')
        super(TestMl2PortBinding, self).setUp()

    def _check_port_binding_profile(self, port, profile=None):
        self.assertIn('id', port)
        self.assertIn(portbindings.PROFILE, port)
        value = port[portbindings.PROFILE]
        self.assertEqual(profile or {}, value)

    def test_create_port_binding_profile(self):
        self._test_create_port_binding_profile({'a': 1, 'b': 2})

    def test_update_port_binding_profile(self):
        self._test_update_port_binding_profile({'c': 3})

    def test_create_port_binding_profile_too_big(self):
        s = 'x' * 5000
        profile_arg = {portbindings.PROFILE: {'d': s}}
        try:
            with self.port(expected_res_status=400,
                           arg_list=(portbindings.PROFILE,),
                           **profile_arg):
                pass
        except webob.exc.HTTPClientError:
            pass

    def test_remove_port_binding_profile(self):
        profile = {'e': 5}
        profile_arg = {portbindings.PROFILE: profile}
        with self.port(arg_list=(portbindings.PROFILE,),
                       **profile_arg) as port:
            self._check_port_binding_profile(port['port'], profile)
            port_id = port['port']['id']
            profile_arg = {portbindings.PROFILE: None}
            port = self._update('ports', port_id,
                                {'port': profile_arg})['port']
            self._check_port_binding_profile(port)
            port = self._show('ports', port_id)['port']
            self._check_port_binding_profile(port)


class TestMl2PortBindingNoSG(TestMl2PortBinding):
    HAS_PORT_FILTER = False
    ENABLE_SG = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestMl2PortBindingHost(Ml2PluginV2TestCase,
                             test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestMl2PortBindingVnicType(Ml2PluginV2TestCase,
                                 test_bindings.PortBindingsVnicTestCaseMixin):
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

    def test_release_segment_no_type_driver(self):
        segment = {driver_api.NETWORK_TYPE: 'faketype',
                   driver_api.PHYSICAL_NETWORK: 'physnet1',
                   driver_api.ID: 1}
        with mock.patch('neutron.plugins.ml2.managers.LOG') as log:
            self.driver.type_manager.release_segment(session=None,
                                                     segment=segment)
        log.error.assert_called_once_with(
            "Failed to release segment '%s' because "
            "network type is not supported.", segment)

    def test_create_provider_fail(self):
        segment = {pnet.NETWORK_TYPE: None,
                   pnet.PHYSICAL_NETWORK: 'phys_net',
                   pnet.SEGMENTATION_ID: None}
        with testtools.ExpectedException(exc.InvalidInput):
            self.driver._process_provider_create(segment)

    def test_create_network_plugin(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        def raise_mechanism_exc(*args, **kwargs):
            raise ml2_exc.MechanismDriverError(
                method='create_network_postcommit')

        with mock.patch('neutron.plugins.ml2.managers.MechanismManager.'
                        'create_network_precommit', new=raise_mechanism_exc):
            with testtools.ExpectedException(ml2_exc.MechanismDriverError):
                self.driver.create_network(self.context, data)

    def test_extend_dictionary_no_segments(self):
        network = dict(name='net_no_segment', id='5', tenant_id='tenant_one')
        self.driver._extend_network_dict_provider(self.context, network)
        self.assertIsNone(network[pnet.NETWORK_TYPE])
        self.assertIsNone(network[pnet.PHYSICAL_NETWORK])
        self.assertIsNone(network[pnet.SEGMENTATION_ID])


class TestMl2AllowedAddressPairs(Ml2PluginV2TestCase,
                                 test_pair.TestAllowedAddressPairs):
    def setUp(self, plugin=None):
        super(test_pair.TestAllowedAddressPairs, self).setUp(
            plugin=PLUGIN_NAME)


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)
