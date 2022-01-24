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

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg

from neutron.conf.plugins.ml2.drivers.openvswitch import mech_ovs_conf
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as a_const)
from neutron.plugins.ml2.drivers.openvswitch.mech_driver import (
    mech_openvswitch)
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class OpenvswitchMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    VIF_DETAILS = {'bridge_name': 'br-int',
                   portbindings.OVS_DATAPATH_TYPE: 'system',
                   portbindings.CAP_PORT_FILTER: True,
                   portbindings.OVS_HYBRID_PLUG: True,
                   portbindings.VIF_DETAILS_CONNECTIVITY:
                       portbindings.CONNECTIVITY_L2}
    AGENT_TYPE = constants.AGENT_TYPE_OVS

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'integration_bridge': 'br-int',
                    portbindings.OVS_HYBRID_PLUG: True,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'bridge_mappings': BAD_MAPPINGS,
                   'integration_bridge': 'br-int',
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host',
               'agent_type': AGENT_TYPE,
               }]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host',
                    'agent_type': AGENT_TYPE,
                    }]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1',
                   'agent_type': AGENT_TYPE,
                   },
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2',
                   'agent_type': AGENT_TYPE,
                   }]

    def setUp(self):
        super(OpenvswitchMechanismBaseTestCase, self).setUp()
        cfg.CONF.set_override('firewall_driver', 'iptables_hybrid',
                              'SECURITYGROUP')
        self.driver = mech_openvswitch.OpenvswitchMechanismDriver()
        self.driver.initialize()

    def test__set_bridge_name_notify(self):

        def fake_callback(resource, event, trigger, payload=None):
            trigger('fake-br-name')

        def noop_callback(resource, event, trigger, payload=None):
            pass

        # hardcode callback to override bridge name
        registry.subscribe(fake_callback, a_const.OVS_BRIDGE_NAME,
                           events.BEFORE_READ)
        fake_vif_details = {}
        fake_agent = {'configurations': {'integration_bridge': 'fake-br'}}
        old_fake_agent = {'configurations': {}}
        self.driver._set_bridge_name('foo', fake_vif_details, fake_agent)
        # assert that callback value is used
        self.assertEqual(
            'fake-br-name',
            fake_vif_details.get(portbindings.VIF_DETAILS_BRIDGE_NAME, ''))
        # replace callback with noop
        registry.unsubscribe(fake_callback, a_const.OVS_BRIDGE_NAME,
                           events.BEFORE_READ)
        registry.subscribe(noop_callback, a_const.OVS_BRIDGE_NAME,
                           events.BEFORE_READ)
        fake_vif_details = {}
        self.driver._set_bridge_name('foo', fake_vif_details, fake_agent)
        # assert that agent config value is used
        self.assertEqual(
            'fake-br',
            fake_vif_details.get(portbindings.VIF_DETAILS_BRIDGE_NAME, ''))
        fake_vif_details = {}
        self.driver._set_bridge_name('foo', fake_vif_details, old_fake_agent)
        # assert that if agent does not supply integration_bridge bridge_name
        # is not set in vif:binding-details
        self.assertIsNone(
            fake_vif_details.get(portbindings.VIF_DETAILS_BRIDGE_NAME))


class OpenvswitchMechanismSGDisabledBaseTestCase(
        OpenvswitchMechanismBaseTestCase):
    VIF_DETAILS = {'bridge_name': 'br-int',
                   portbindings.OVS_DATAPATH_TYPE: 'system',
                   portbindings.CAP_PORT_FILTER: False,
                   portbindings.OVS_HYBRID_PLUG: False,
                   portbindings.VIF_DETAILS_CONNECTIVITY:
                       portbindings.CONNECTIVITY_L2}

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'integration_bridge': 'br-int',
                    portbindings.OVS_HYBRID_PLUG: False,
                    'tunnel_types': GOOD_TUNNEL_TYPES}
    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host',
               'agent_type': constants.AGENT_TYPE_OVS,
               }]

    def setUp(self):
        cfg.CONF.set_override('enable_security_group',
                              False,
                              group='SECURITYGROUP')
        super(OpenvswitchMechanismSGDisabledBaseTestCase, self).setUp()


class OpenvswitchMechanismHybridPlugTestCase(OpenvswitchMechanismBaseTestCase):

    def _make_port_ctx(self, agents):
        segments = [{api.ID: 'local_segment_id', api.NETWORK_TYPE: 'local'}]
        return base.FakePortContext(self.AGENT_TYPE, agents, segments,
                                    vnic_type=self.VNIC_TYPE)

    def test_hybrid_plug_true_if_agent_requests(self):
        hybrid = portbindings.OVS_HYBRID_PLUG
        # set server side default to false and ensure that hybrid becomes
        # true if requested by the agent
        self.driver.vif_details[hybrid] = False
        agents = [{'alive': True,
                   'configurations': {hybrid: True},
                   'host': 'host',
                   'agent_type': self.AGENT_TYPE,
                   }]
        context = self._make_port_ctx(agents)
        self.driver.bind_port(context)
        self.assertTrue(context._bound_vif_details[hybrid])

    def test_hybrid_plug_false_if_agent_requests(self):
        hybrid = portbindings.OVS_HYBRID_PLUG
        # set server side default to true and ensure that hybrid becomes
        # false if requested by the agent
        self.driver.vif_details[hybrid] = True
        agents = [{'alive': True,
                   'configurations': {hybrid: False},
                   'host': 'host',
                   'agent_type': self.AGENT_TYPE,
                   }]
        context = self._make_port_ctx(agents)
        self.driver.bind_port(context)
        self.assertFalse(context._bound_vif_details[hybrid])


class OpenvswitchMechanismGenericTestCase(OpenvswitchMechanismBaseTestCase,
                                          base.AgentMechanismGenericTestCase):
    def test_driver_responsible_for_ports_allocation_min_bw(self):
        agents = [
            {'agent_type': constants.AGENT_TYPE_OVS,
             'configurations': {'resource_provider_bandwidths': {'eth0': {}}},
             'id': '1',
             'host': 'host'}
        ]
        segments = []

        # uuid -v5 87ee7d5c-73bb-11e8-9008-c4d987b2a692 host:eth0
        fake_min_bw_rp = '13cc0ed9-e802-5eaa-b4c7-3441855e31f2'
        fake_allocation = {
            'fake_min_bw_resource_request_group': fake_min_bw_rp,
        }
        profile = {'allocation': fake_allocation}

        port_ctx = base.FakePortContext(
            self.AGENT_TYPE,
            agents,
            segments,
            vnic_type=portbindings.VNIC_NORMAL,
            profile=profile)
        with mock.patch.object(self.driver, '_possible_agents_for_port',
                               return_value=agents):
            self.assertTrue(
                self.driver.responsible_for_ports_allocation(port_ctx))

    def test_driver_responsible_for_ports_allocation_min_pps(self):
        agents = [
            {'agent_type': constants.AGENT_TYPE_OVS,
             'configurations': {
                 'resource_provider_packet_processing_with_direction': {
                     'host': {}}},
             'id': '1',
             'host': 'host'}
        ]
        segments = []

        # uuid -v5 87ee7d5c-73bb-11e8-9008-c4d987b2a692 host
        fake_min_pps_rp = '791f63f0-1a1a-5c38-8972-5e43014fd58b'
        fake_allocation = {
            'fake_min_pps_resource_request_group': fake_min_pps_rp,
        }
        profile = {'allocation': fake_allocation}

        port_ctx = base.FakePortContext(
            self.AGENT_TYPE,
            agents,
            segments,
            vnic_type=portbindings.VNIC_NORMAL,
            profile=profile)
        with mock.patch.object(self.driver, '_possible_agents_for_port',
                               return_value=agents):
            self.assertTrue(
                self.driver.responsible_for_ports_allocation(port_ctx))

    def test_driver_responsible_for_ports_allocation_min_pps_and_min_bw(self):
        agents = [{
            'agent_type': constants.AGENT_TYPE_OVS,
            'configurations': {
                'resource_provider_packet_processing_without_direction': {
                    'host': {}
                },
                'resource_provider_bandwidths': {'eth0': {}}
            },
            'id': '1',
            'host': 'host'
        }]
        segments = []

        # uuid -v5 87ee7d5c-73bb-11e8-9008-c4d987b2a692 host
        fake_min_pps_rp = '791f63f0-1a1a-5c38-8972-5e43014fd58b'
        # uuid -v5 87ee7d5c-73bb-11e8-9008-c4d987b2a692 host:eth0
        fake_min_bw_rp = '13cc0ed9-e802-5eaa-b4c7-3441855e31f2'
        fake_allocation = {
            'fake_min_pps_resource_request_group': fake_min_pps_rp,
            'fake_min_bw_resource_request_group': fake_min_bw_rp,
        }
        profile = {'allocation': fake_allocation}

        port_ctx = base.FakePortContext(
            self.AGENT_TYPE,
            agents,
            segments,
            vnic_type=portbindings.VNIC_NORMAL,
            profile=profile)
        with mock.patch.object(self.driver, '_possible_agents_for_port',
                               return_value=agents):
            self.assertTrue(
                self.driver.responsible_for_ports_allocation(port_ctx))


class OpenvswitchMechanismLocalTestCase(OpenvswitchMechanismBaseTestCase,
                                        base.AgentMechanismLocalTestCase):
    pass


class OpenvswitchMechanismFlatTestCase(OpenvswitchMechanismBaseTestCase,
                                       base.AgentMechanismFlatTestCase):
    pass


class OpenvswitchMechanismVlanTestCase(OpenvswitchMechanismBaseTestCase,
                                       base.AgentMechanismVlanTestCase):
    pass


class OpenvswitchMechanismGreTestCase(OpenvswitchMechanismBaseTestCase,
                                      base.AgentMechanismGreTestCase):
    pass


class OpenvswitchMechanismSGDisabledLocalTestCase(
        OpenvswitchMechanismSGDisabledBaseTestCase,
        base.AgentMechanismLocalTestCase):
    pass


class OpenvswitchMechanismFirewallUndefinedTestCase(
        OpenvswitchMechanismBaseTestCase, base.AgentMechanismLocalTestCase):

    def setUp(self):
        # this simple test case just ensures backward compatibility where
        # the server has no firewall driver configured, which should result
        # in hybrid plugging.
        super(OpenvswitchMechanismFirewallUndefinedTestCase, self).setUp()
        cfg.CONF.set_override('firewall_driver', '', 'SECURITYGROUP')
        self.driver = mech_openvswitch.OpenvswitchMechanismDriver()
        self.driver.initialize()


class OpenvswitchMechanismDPDKTestCase(OpenvswitchMechanismBaseTestCase):

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}

    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']

    VHOST_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                     'integration_bridge': 'br-int',
                     'tunnel_types': GOOD_TUNNEL_TYPES,
                     'datapath_type': a_const.OVS_DATAPATH_NETDEV,
                     'ovs_capabilities': {
                         'iface_types': [a_const.OVS_DPDK_VHOST_USER]}}

    VHOST_SERVER_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'integration_bridge': 'br-int',
                    'tunnel_types': GOOD_TUNNEL_TYPES,
                    'datapath_type': a_const.OVS_DATAPATH_NETDEV,
                    'ovs_capabilities': {
                        'iface_types': [a_const.OVS_DPDK_VHOST_USER_CLIENT]}}

    SYSTEM_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                      'integration_bridge': 'br-int',
                      'tunnel_types': GOOD_TUNNEL_TYPES,
                      'datapath_type': a_const.OVS_DATAPATH_SYSTEM,
                      'ovs_capabilities': {'iface_types': []}}

    AGENT = {'alive': True,
             'configurations': VHOST_CONFIGS,
             'host': 'host'}

    AGENT_SERVER = {'alive': True,
                    'configurations': VHOST_SERVER_CONFIGS,
                    'host': 'host'}

    AGENT_SYSTEM = {'alive': True,
                    'configurations': SYSTEM_CONFIGS,
                    'host': 'host'}

    def test_get_vhost_mode(self):
        ifaces = []
        result = self.driver.get_vhost_mode(ifaces)
        self.assertEqual(portbindings.VHOST_USER_MODE_CLIENT, result)

        ifaces = [a_const.OVS_DPDK_VHOST_USER]
        result = self.driver.get_vhost_mode(ifaces)
        self.assertEqual(portbindings.VHOST_USER_MODE_CLIENT, result)

        ifaces = [a_const.OVS_DPDK_VHOST_USER_CLIENT]
        result = self.driver.get_vhost_mode(ifaces)
        self.assertEqual(portbindings.VHOST_USER_MODE_SERVER, result)

    def test_get_vif_type(self):
        normal_port_cxt = base.FakePortContext(None, None, None)
        result = self.driver.get_vif_type(normal_port_cxt, self.AGENT, None)
        self.assertEqual(portbindings.VIF_TYPE_VHOST_USER, result)

        result = self.driver.get_vif_type(normal_port_cxt,
                                          self.AGENT_SERVER, None)
        self.assertEqual(portbindings.VIF_TYPE_VHOST_USER, result)

        result = self.driver.get_vif_type(normal_port_cxt,
                                          self.AGENT_SYSTEM, None)
        self.assertEqual(portbindings.VIF_TYPE_OVS, result)

        direct_port_cxt = base.FakePortContext(
            None, None, None, vnic_type=portbindings.VNIC_DIRECT)
        result = self.driver.get_vif_type(direct_port_cxt,
                                          self.AGENT, None)
        self.assertEqual(portbindings.VIF_TYPE_OVS, result)


class OpenvswitchMechanismSRIOVTestCase(OpenvswitchMechanismBaseTestCase):

    def _make_port_ctx(self, agents, profile=None):
        segments = [{api.ID: 'local_segment_id', api.NETWORK_TYPE: 'local'}]
        return base.FakePortContext(self.AGENT_TYPE, agents, segments,
                                    vnic_type=portbindings.VNIC_DIRECT,
                                    profile=profile)

    @mock.patch('neutron.plugins.ml2.drivers.mech_agent.'
                'SimpleAgentMechanismDriverBase.bind_port')
    def test_bind_port_sriov_legacy(self, mocked_bind_port):
        context = self._make_port_ctx(self.AGENTS)
        self.driver.bind_port(context)
        mocked_bind_port.assert_not_called()

    @mock.patch('neutron.plugins.ml2.drivers.mech_agent.'
                'SimpleAgentMechanismDriverBase.bind_port')
    def test_bind_port_sriov_switchdev(self, mocked_bind_port):
        profile = {'capabilities': ['switchdev']}
        context = self._make_port_ctx(self.AGENTS, profile=profile)
        self.driver.bind_port(context)
        mocked_bind_port.assert_called()


class OpenvswitchMechVnicTypesTestCase(OpenvswitchMechanismBaseTestCase):

    supported_vnics = [portbindings.VNIC_NORMAL,
                       portbindings.VNIC_DIRECT,
                       portbindings.VNIC_SMARTNIC,
                       portbindings.VNIC_VHOST_VDPA,
                       ]

    def setUp(self):
        self.prohibit_list_cfg = {
            'OVS_DRIVER': {
                'vnic_type_prohibit_list': []
            }
        }
        self.default_supported_vnics = self.supported_vnics
        super(OpenvswitchMechVnicTypesTestCase, self).setUp()

    def test_default_vnic_types(self):
        self.assertEqual(self.default_supported_vnics,
                         self.driver.supported_vnic_types)

    def test_vnic_type_prohibit_list_valid_item(self):
        self.prohibit_list_cfg['OVS_DRIVER']['vnic_type_prohibit_list'] = \
            [portbindings.VNIC_DIRECT]

        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_ovs_conf.register_ovs_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        test_driver = mech_openvswitch.OpenvswitchMechanismDriver()

        supported_vnic_types = test_driver.supported_vnic_types
        self.assertNotIn(portbindings.VNIC_DIRECT, supported_vnic_types)
        self.assertEqual(len(self.default_supported_vnics) - 1,
                         len(supported_vnic_types))

    def test_vnic_type_prohibit_list_not_valid_item(self):
        self.prohibit_list_cfg['OVS_DRIVER']['vnic_type_prohibit_list'] = \
            ['foo']

        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_ovs_conf.register_ovs_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        self.assertRaises(ValueError,
                          mech_openvswitch.OpenvswitchMechanismDriver)

    def test_vnic_type_prohibit_list_all_items(self):
        self.prohibit_list_cfg['OVS_DRIVER']['vnic_type_prohibit_list'] = \
            self.supported_vnics
        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_ovs_conf.register_ovs_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        self.assertRaises(ValueError,
                          mech_openvswitch.OpenvswitchMechanismDriver)


class OpenvswitchMechDeviceMappingsTestCase(OpenvswitchMechanismBaseTestCase):

    def test_standard_device_mappings(self):
        mappings = self.driver.get_standard_device_mappings(self.AGENTS[0])
        self.assertEqual(
            len(self.GOOD_CONFIGS['bridge_mappings']),
            len(mappings))
        for ph_orig, br_orig in self.GOOD_CONFIGS['bridge_mappings'].items():
            self.assertIn(ph_orig, mappings)
            self.assertEqual([br_orig], mappings[ph_orig])

    def test_standard_device_mappings_negative(self):
        fake_agent = {'agent_type': constants.AGENT_TYPE_OVS,
                      'configurations': {}}
        self.assertRaises(ValueError, self.driver.get_standard_device_mappings,
                          fake_agent)
