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
import uuid
import webob

from neutron.common import constants
from neutron.common import exceptions as exc
from neutron.common import utils
from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.extensions import external_net as external_net
from neutron.extensions import l3agentscheduler
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import type_vlan
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests import base
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.ml2.drivers import mechanism_logger as mech_logger
from neutron.tests.unit.ml2.drivers import mechanism_test as mech_test
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_allowedaddresspairs as test_pair
from neutron.tests.unit import test_extension_extradhcpopts as test_dhcpopts
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


config.cfg.CONF.import_opt('network_vlan_ranges',
                           'neutron.plugins.ml2.drivers.type_vlan',
                           group='ml2_type_vlan')


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
        self.vlan_range2 = '200:300'
        self.physnet2 = 'physnet2'
        self.phys_vrange = ':'.join([self.physnet, self.vlan_range])
        self.phys2_vrange = ':'.join([self.physnet2, self.vlan_range2])
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     [self.phys_vrange, self.phys2_vrange],
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


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       Ml2PluginV2TestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2, Ml2PluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual('DOWN', port['port']['status'])
            self.assertEqual('DOWN', self.port_create_status)

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

    def test_l3_cleanup_on_net_delete(self):
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as n:
            with self.subnet(network=n, cidr='200.0.0.0/22'):
                l3plugin.create_floatingip(
                    context.get_admin_context(),
                    {'floatingip': {'floating_network_id': n['network']['id'],
                                    'tenant_id': n['network']['tenant_id']}}
                )
        self._delete('networks', n['network']['id'])
        flips = l3plugin.get_floatingips(context.get_admin_context())
        self.assertFalse(flips)

    def test_delete_port_no_notify_in_disassociate_floatingips(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        with contextlib.nested(
            self.port(do_delete=False),
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

    def test_check_if_compute_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced('compute:None'))

    def test_check_if_lbaas_vip_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced(
            constants.DEVICE_OWNER_LOADBALANCER))

    def test_check_if_dhcp_port_serviced_by_dvr(self):
        self.assertTrue(utils.is_dvr_serviced(constants.DEVICE_OWNER_DHCP))

    def test_check_if_port_not_serviced_by_dvr(self):
        self.assertFalse(utils.is_dvr_serviced(
            constants.DEVICE_OWNER_ROUTER_INTF))

    def test_disassociate_floatingips_do_notify_returns_nothing(self):
        ctx = context.get_admin_context()
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        with self.port() as port:

            port_id = port['port']['id']
            # check that nothing is returned when notifications are handled
            # by the called method
            self.assertIsNone(l3plugin.disassociate_floatingips(ctx, port_id))


class TestMl2DvrPortsV2(TestMl2PortsV2):
    def setUp(self):
        super(TestMl2DvrPortsV2, self).setUp()
        extensions = ['router',
                      constants.L3_AGENT_SCHEDULER_EXT_ALIAS,
                      constants.L3_DISTRIBUTED_EXT_ALIAS]
        self.plugin = manager.NeutronManager.get_plugin()
        self.l3plugin = mock.Mock()
        type(self.l3plugin).supported_extension_aliases = (
            mock.PropertyMock(return_value=extensions))
        self.service_plugins = {'L3_ROUTER_NAT': self.l3plugin}

    def _test_delete_dvr_serviced_port(self, device_owner, floating_ip=False):
        ns_to_delete = {'host': 'myhost', 'agent_id': 'vm_l3_agent',
                        'router_id': 'my_router'}
        fip_set = set()
        if floating_ip:
            fip_set.add(ns_to_delete['router_id'])

        with contextlib.nested(
            mock.patch.object(manager.NeutronManager,
                              'get_service_plugins',
                              return_value=self.service_plugins),
            self.port(do_delete=False,
                      device_owner=device_owner),
            mock.patch.object(self.l3plugin, 'notify_routers_updated'),
            mock.patch.object(self.l3plugin, 'disassociate_floatingips',
                              return_value=fip_set),
            mock.patch.object(self.l3plugin, 'dvr_deletens_if_no_port',
                              return_value=[ns_to_delete]),
            mock.patch.object(self.l3plugin, 'remove_router_from_l3_agent')
        ) as (get_service_plugin, port, notify, disassociate_floatingips,
              dvr_delns_ifno_port, remove_router_from_l3_agent):

            port_id = port['port']['id']
            self.plugin.delete_port(self.context, port_id)

            notify.assert_has_calls([mock.call(self.context, fip_set)])
            dvr_delns_ifno_port.assert_called_once_with(self.context,
                                                        port['port']['id'])
            remove_router_from_l3_agent.assert_has_calls([
                mock.call(self.context, ns_to_delete['agent_id'],
                          ns_to_delete['router_id'])
            ])

    def test_delete_last_vm_port(self):
        self._test_delete_dvr_serviced_port(device_owner='compute:None')

    def test_delete_last_vm_port_with_floatingip(self):
        self._test_delete_dvr_serviced_port(device_owner='compute:None',
                                            floating_ip=True)

    def test_delete_vm_port_namespace_already_deleted(self):
        ns_to_delete = {'host': 'myhost',
                        'agent_id': 'vm_l3_agent',
                        'router_id': 'my_router'}

        with contextlib.nested(
            mock.patch.object(manager.NeutronManager,
                              'get_service_plugins',
                              return_value=self.service_plugins),
            self.port(do_delete=False,
                      device_owner='compute:None'),
            mock.patch.object(self.l3plugin, 'dvr_deletens_if_no_port',
                              return_value=[ns_to_delete]),
            mock.patch.object(self.l3plugin, 'remove_router_from_l3_agent',
                side_effect=l3agentscheduler.RouterNotHostedByL3Agent(
                            router_id=ns_to_delete['router_id'],
                            agent_id=ns_to_delete['agent_id']))
        ) as (get_service_plugin, port, dvr_delns_ifno_port,
              remove_router_from_l3_agent):

            self.plugin.delete_port(self.context, port['port']['id'])
            remove_router_from_l3_agent.assert_called_once_with(self.context,
                ns_to_delete['agent_id'], ns_to_delete['router_id'])

    def test_delete_lbaas_vip_port(self):
        self._test_delete_dvr_serviced_port(
            device_owner=constants.DEVICE_OWNER_LOADBALANCER)


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

    def test_return_on_concurrent_delete_and_binding(self):
        # create a port and delete it so we have an expired mechanism context
        with self.port() as port:
            plugin = manager.NeutronManager.get_plugin()
            binding = ml2_db.get_locked_port_and_binding(self.context.session,
                                                         port['port']['id'])[1]
            binding['host'] = 'test'
            mech_context = driver_context.PortContext(
                plugin, self.context, port['port'],
                plugin.get_network(self.context, port['port']['network_id']),
                binding)
        with contextlib.nested(
            mock.patch('neutron.plugins.ml2.plugin.'
                       'db.get_locked_port_and_binding',
                       return_value=(None, None)),
            mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin._make_port_dict')
        ) as (glpab_mock, mpd_mock):
            plugin._bind_port_if_needed(mech_context)
            # called during deletion to get port
            self.assertTrue(glpab_mock.mock_calls)
            # should have returned before calling _make_port_dict
            self.assertFalse(mpd_mock.mock_calls)

    def test_port_binding_profile_not_changed(self):
        profile = {'e': 5}
        profile_arg = {portbindings.PROFILE: profile}
        with self.port(arg_list=(portbindings.PROFILE,),
                       **profile_arg) as port:
            self._check_port_binding_profile(port['port'], profile)
            port_id = port['port']['id']
            state_arg = {'admin_state_up': True}
            port = self._update('ports', port_id,
                                {'port': state_arg})['port']
            self._check_port_binding_profile(port, profile)
            port = self._show('ports', port_id)['port']
            self._check_port_binding_profile(port, profile)

    def test_process_dvr_port_binding_update_router_id(self):
        host_id = 'host'
        binding = models.DVRPortBinding(
                            port_id='port_id',
                            host=host_id,
                            router_id='old_router_id',
                            vif_type=portbindings.VIF_TYPE_OVS,
                            vnic_type=portbindings.VNIC_NORMAL,
                            cap_port_filter=False,
                            status=constants.PORT_STATUS_DOWN)
        plugin = manager.NeutronManager.get_plugin()
        mock_network = {'id': 'net_id'}
        context = mock.Mock()
        new_router_id = 'new_router'
        attrs = {'device_id': new_router_id, portbindings.HOST_ID: host_id}
        with mock.patch.object(plugin, '_update_port_dict_binding'):
            with mock.patch.object(ml2_db, 'get_network_segments',
                                   return_value=[]):
                mech_context = driver_context.DvrPortContext(
                    self, context, 'port', mock_network, binding)
                plugin._process_dvr_port_binding(mech_context, context, attrs)
                self.assertEqual(new_router_id,
                                 mech_context._binding.router_id)
                self.assertEqual(host_id, mech_context._binding.host)

    def test_update_dvr_port_binding_on_non_existent_port(self):
        plugin = manager.NeutronManager.get_plugin()
        port = {
            'id': 'foo_port_id',
            'binding:host_id': 'foo_host',
        }
        with mock.patch.object(ml2_db, 'ensure_dvr_port_binding') as mock_dvr:
            plugin.update_dvr_port_binding(
                self.context, 'foo_port_id', {'port': port})
        self.assertFalse(mock_dvr.called)


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

    def test_allocate_dynamic_segment(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertTrue(dynamic_segment[driver_api.SEGMENTATION_ID] > 0)
        segment2 = {driver_api.NETWORK_TYPE: 'vlan',
                    driver_api.SEGMENTATION_ID: 1234,
                    driver_api.PHYSICAL_NETWORK: 'physnet3'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment2)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     segmentation_id='1234')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet3',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertEqual(dynamic_segment[driver_api.SEGMENTATION_ID], 1234)

    def test_allocate_dynamic_segment_multiple_physnets(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        dynamic_segmentation_id = dynamic_segment[driver_api.SEGMENTATION_ID]
        self.assertTrue(dynamic_segmentation_id > 0)
        dynamic_segment1 = ml2_db.get_dynamic_segment(self.context.session,
                                                      network_id,
                                                      'physnet1')
        dynamic_segment1_id = dynamic_segment1[driver_api.SEGMENTATION_ID]
        self.assertEqual(dynamic_segmentation_id, dynamic_segment1_id)
        segment2 = {driver_api.NETWORK_TYPE: 'vlan',
                    driver_api.PHYSICAL_NETWORK: 'physnet2'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment2)
        dynamic_segment2 = ml2_db.get_dynamic_segment(self.context.session,
                                                      network_id,
                                                      'physnet2')
        dynamic_segmentation2_id = dynamic_segment2[driver_api.SEGMENTATION_ID]
        self.assertNotEqual(dynamic_segmentation_id, dynamic_segmentation2_id)

    def test_allocate_release_dynamic_segment(self):
        data = {'network': {'name': 'net1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet1'}
        network_id = network['network']['id']
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet1')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet1',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        dynamic_segmentation_id = dynamic_segment[driver_api.SEGMENTATION_ID]
        self.assertTrue(dynamic_segmentation_id > 0)
        self.driver.type_manager.release_dynamic_segment(
            self.context.session, dynamic_segment[driver_api.ID])
        self.assertIsNone(ml2_db.get_dynamic_segment(
            self.context.session, network_id, 'physnet1'))

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
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
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        self.assertEqual('vlan', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(1, network['network'][pnet.SEGMENTATION_ID])
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
        self.assertEqual(400, res.status_int)

    def test_create_network_duplicate_full_segments(self):
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
        self.assertEqual(400, res.status_int)

    def test_create_network_duplicate_partial_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1'},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(201, res.status_int)

    def test_release_network_segments(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']
        segment = {driver_api.NETWORK_TYPE: 'vlan',
                   driver_api.PHYSICAL_NETWORK: 'physnet2'}
        self.driver.type_manager.allocate_dynamic_segment(
            self.context.session, network_id, segment)
        dynamic_segment = ml2_db.get_dynamic_segment(self.context.session,
                                                     network_id,
                                                     'physnet2')
        self.assertEqual('vlan', dynamic_segment[driver_api.NETWORK_TYPE])
        self.assertEqual('physnet2',
                         dynamic_segment[driver_api.PHYSICAL_NETWORK])
        self.assertTrue(dynamic_segment[driver_api.SEGMENTATION_ID] > 0)

        with mock.patch.object(type_vlan.VlanTypeDriver,
                               'release_segment') as rs:
            req = self.new_delete_request('networks', network_id)
            res = req.get_response(self.api)
            self.assertEqual(2, rs.call_count)
        self.assertEqual(ml2_db.get_network_segments(
            self.context.session, network_id), [])
        self.assertIsNone(ml2_db.get_dynamic_segment(
            self.context.session, network_id, 'physnet2'))

    def test_release_segment_no_type_driver(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'shared': False,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']

        segment = {driver_api.NETWORK_TYPE: 'faketype',
                   driver_api.PHYSICAL_NETWORK: 'physnet1',
                   driver_api.ID: 1}
        with mock.patch('neutron.plugins.ml2.managers.LOG') as log:
            with mock.patch('neutron.plugins.ml2.managers.db') as db:
                db.get_network_segments.return_value = (segment,)
                self.driver.type_manager.release_network_segments(
                    self.context.session, network_id)

                log.error.assert_called_once_with(
                    "Failed to release segment '%s' because "
                    "network type is not supported.", segment)

    def test_create_provider_fail(self):
        segment = {pnet.NETWORK_TYPE: None,
                   pnet.PHYSICAL_NETWORK: 'phys_net',
                   pnet.SEGMENTATION_ID: None}
        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.type_manager._process_provider_create(segment)

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
        self.driver.type_manager._extend_network_dict_provider(self.context,
                                                               network)
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


class Ml2PluginV2FaultyDriverTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['test', 'logger'],
                                     group='ml2')
        super(Ml2PluginV2FaultyDriverTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'


class TestFaultyMechansimDriver(Ml2PluginV2FaultyDriverTestCase):

    def test_create_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            tenant_id = str(uuid.uuid4())
            data = {'network': {'name': 'net1',
                                'tenant_id': tenant_id}}
            req = self.new_create_request('networks', data)
            res = req.get_response(self.api)
            self.assertEqual(500, res.status_int)
            error = self.deserialize(self.fmt, res)
            self.assertEqual('MechanismDriverError',
                             error['NeutronError']['type'])
            query_params = "tenant_id=%s" % tenant_id
            nets = self._list('networks', query_params=query_params)
            self.assertFalse(nets['networks'])

    def test_delete_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'delete_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'delete_network_postcommit') as dnp:

                data = {'network': {'name': 'net1',
                                    'tenant_id': 'tenant_one'}}
                network_req = self.new_create_request('networks', data)
                network_res = network_req.get_response(self.api)
                self.assertEqual(201, network_res.status_int)
                network = self.deserialize(self.fmt, network_res)
                net_id = network['network']['id']
                req = self.new_delete_request('networks', net_id)
                res = req.get_response(self.api)
                self.assertEqual(204, res.status_int)
                # Test if other mechanism driver was called
                self.assertTrue(dnp.called)
                self._show('networks', net_id,
                           expected_code=webob.exc.HTTPNotFound.code)

    def test_update_network_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_network_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_network_postcommit') as unp:

                data = {'network': {'name': 'net1',
                                    'tenant_id': 'tenant_one'}}
                network_req = self.new_create_request('networks', data)
                network_res = network_req.get_response(self.api)
                self.assertEqual(201, network_res.status_int)
                network = self.deserialize(self.fmt, network_res)
                net_id = network['network']['id']

                new_name = 'a_brand_new_name'
                data = {'network': {'name': new_name}}
                req = self.new_update_request('networks', data, net_id)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                # Test if other mechanism driver was called
                self.assertTrue(unp.called)
                net = self._show('networks', net_id)
                self.assertEqual(new_name, net['network']['name'])

                self._delete('networks', net_id)

    def test_create_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):

            with self.network() as network:
                net_id = network['network']['id']
                data = {'subnet': {'network_id': net_id,
                                   'cidr': '10.0.20.0/24',
                                   'ip_version': '4',
                                   'name': 'subnet1',
                                   'tenant_id':
                                   network['network']['tenant_id'],
                                   'gateway_ip': '10.0.20.1'}}
                req = self.new_create_request('subnets', data)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                query_params = "network_id=%s" % net_id
                subnets = self._list('subnets', query_params=query_params)
                self.assertFalse(subnets['subnets'])

    def test_delete_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'delete_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'delete_subnet_postcommit') as dsp:

                with self.network() as network:
                    data = {'subnet': {'network_id':
                                       network['network']['id'],
                                       'cidr': '10.0.20.0/24',
                                       'ip_version': '4',
                                       'name': 'subnet1',
                                       'tenant_id':
                                       network['network']['tenant_id'],
                                       'gateway_ip': '10.0.20.1'}}
                    subnet_req = self.new_create_request('subnets', data)
                    subnet_res = subnet_req.get_response(self.api)
                    self.assertEqual(201, subnet_res.status_int)
                    subnet = self.deserialize(self.fmt, subnet_res)
                    subnet_id = subnet['subnet']['id']

                    req = self.new_delete_request('subnets', subnet_id)
                    res = req.get_response(self.api)
                    self.assertEqual(204, res.status_int)
                    # Test if other mechanism driver was called
                    self.assertTrue(dsp.called)
                    self._show('subnets', subnet_id,
                               expected_code=webob.exc.HTTPNotFound.code)

    def test_update_subnet_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_subnet_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_subnet_postcommit') as usp:

                with self.network() as network:
                    data = {'subnet': {'network_id':
                                       network['network']['id'],
                                       'cidr': '10.0.20.0/24',
                                       'ip_version': '4',
                                       'name': 'subnet1',
                                       'tenant_id':
                                       network['network']['tenant_id'],
                                       'gateway_ip': '10.0.20.1'}}
                    subnet_req = self.new_create_request('subnets', data)
                    subnet_res = subnet_req.get_response(self.api)
                    self.assertEqual(201, subnet_res.status_int)
                    subnet = self.deserialize(self.fmt, subnet_res)
                    subnet_id = subnet['subnet']['id']
                    new_name = 'a_brand_new_name'
                    data = {'subnet': {'name': new_name}}
                    req = self.new_update_request('subnets', data, subnet_id)
                    res = req.get_response(self.api)
                    self.assertEqual(500, res.status_int)
                    error = self.deserialize(self.fmt, res)
                    self.assertEqual('MechanismDriverError',
                                     error['NeutronError']['type'])
                    # Test if other mechanism driver was called
                    self.assertTrue(usp.called)
                    subnet = self._show('subnets', subnet_id)
                    self.assertEqual(new_name, subnet['subnet']['name'])

                    self._delete('subnets', subnet['subnet']['id'])

    def test_create_port_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'create_port_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):

            with self.network() as network:
                net_id = network['network']['id']
                data = {'port': {'network_id': net_id,
                                 'tenant_id':
                                 network['network']['tenant_id'],
                                 'name': 'port1',
                                 'admin_state_up': 1,
                                 'fixed_ips': []}}
                req = self.new_create_request('ports', data)
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)
                error = self.deserialize(self.fmt, res)
                self.assertEqual('MechanismDriverError',
                                 error['NeutronError']['type'])
                query_params = "network_id=%s" % net_id
                ports = self._list('ports', query_params=query_params)
                self.assertFalse(ports['ports'])

    def test_update_port_faulty(self):

        with mock.patch.object(mech_test.TestMechanismDriver,
                               'update_port_postcommit',
                               side_effect=ml2_exc.MechanismDriverError):
            with mock.patch.object(mech_logger.LoggerMechanismDriver,
                                   'update_port_postcommit') as upp:

                with self.network() as network:
                    data = {'port': {'network_id': network['network']['id'],
                                     'tenant_id':
                                     network['network']['tenant_id'],
                                     'name': 'port1',
                                     'admin_state_up': 1,
                                     'fixed_ips': []}}
                    port_req = self.new_create_request('ports', data)
                    port_res = port_req.get_response(self.api)
                    self.assertEqual(201, port_res.status_int)
                    port = self.deserialize(self.fmt, port_res)
                    port_id = port['port']['id']

                    new_name = 'a_brand_new_name'
                    data = {'port': {'name': new_name}}
                    req = self.new_update_request('ports', data, port_id)
                    res = req.get_response(self.api)
                    self.assertEqual(500, res.status_int)
                    error = self.deserialize(self.fmt, res)
                    self.assertEqual('MechanismDriverError',
                                     error['NeutronError']['type'])
                    # Test if other mechanism driver was called
                    self.assertTrue(upp.called)
                    port = self._show('ports', port_id)
                    self.assertEqual(new_name, port['port']['name'])

                    self._delete('ports', port['port']['id'])


class TestMl2PluginCreateUpdatePort(base.BaseTestCase):
    def setUp(self):
        super(TestMl2PluginCreateUpdatePort, self).setUp()
        self.context = mock.MagicMock()

    def _ensure_transaction_is_closed(self):
        transaction = self.context.session.begin(subtransactions=True)
        enter = transaction.__enter__.call_count
        exit = transaction.__exit__.call_count
        self.assertEqual(enter, exit)

    def _create_plugin_for_create_update_port(self, new_host_port):
        plugin = ml2_plugin.Ml2Plugin()
        plugin.extension_manager = mock.Mock()
        plugin.type_manager = mock.Mock()
        plugin.mechanism_manager = mock.Mock()
        plugin.notifier = mock.Mock()
        plugin._get_host_port_if_changed = mock.Mock(
            return_value=new_host_port)

        plugin._notify_l3_agent_new_port = mock.Mock()
        plugin._notify_l3_agent_new_port.side_effect = (
            lambda c, p: self._ensure_transaction_is_closed())

        return plugin

    def test_create_port_rpc_outside_transaction(self):
        with contextlib.nested(
            mock.patch.object(ml2_plugin.Ml2Plugin, '__init__'),
            mock.patch.object(base_plugin.NeutronDbPluginV2, 'create_port'),
        ) as (init, super_create_port):
            init.return_value = None

            new_host_port = mock.Mock()
            plugin = self._create_plugin_for_create_update_port(new_host_port)

            plugin.create_port(self.context, mock.MagicMock())

            plugin._notify_l3_agent_new_port.assert_called_once_with(
                self.context, new_host_port)

    def test_update_port_rpc_outside_transaction(self):
        with contextlib.nested(
            mock.patch.object(ml2_plugin.Ml2Plugin, '__init__'),
            mock.patch.object(base_plugin.NeutronDbPluginV2, 'update_port'),
        ) as (init, super_update_port):
            init.return_value = None

            new_host_port = mock.Mock()
            plugin = self._create_plugin_for_create_update_port(new_host_port)

            plugin.update_port(self.context, 'fake_id', mock.MagicMock())

            plugin._notify_l3_agent_new_port.assert_called_once_with(
                self.context, new_host_port)
