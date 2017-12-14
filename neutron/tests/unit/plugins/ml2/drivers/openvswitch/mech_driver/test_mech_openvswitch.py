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

import mock
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg

from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as a_const)
from neutron.plugins.ml2.drivers.openvswitch.mech_driver import (
    mech_openvswitch)
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class OpenvswitchMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    VIF_DETAILS = {portbindings.OVS_DATAPATH_TYPE: 'system',
                   portbindings.CAP_PORT_FILTER: True,
                   portbindings.OVS_HYBRID_PLUG: True}
    AGENT_TYPE = constants.AGENT_TYPE_OVS

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['gre', 'vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'bridge_mappings': BAD_MAPPINGS,
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host'}]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host'}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1'},
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2'}]

    def setUp(self):
        super(OpenvswitchMechanismBaseTestCase, self).setUp()
        cfg.CONF.set_override('firewall_driver', 'iptables_hybrid',
                              'SECURITYGROUP')
        self.driver = mech_openvswitch.OpenvswitchMechanismDriver()
        self.driver.initialize()

    def test__set_bridge_name_notify(self):

        def fake_callback(resource, event, trigger, payload=None):
            trigger('fake-br-name')

        registry.subscribe(fake_callback, a_const.OVS_BRIDGE_NAME,
                           events.BEFORE_READ)
        fake_vif_details = {}
        self.driver._set_bridge_name('foo', fake_vif_details)
        self.assertEqual(
            'fake-br-name',
            fake_vif_details.get(portbindings.VIF_DETAILS_BRIDGE_NAME, ''))


class OpenvswitchMechanismSGDisabledBaseTestCase(
    OpenvswitchMechanismBaseTestCase):
    VIF_DETAILS = {portbindings.OVS_DATAPATH_TYPE: 'system',
                   portbindings.CAP_PORT_FILTER: False,
                   portbindings.OVS_HYBRID_PLUG: False}

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

    def test_backward_compat_with_unreporting_agent(self):
        hybrid = portbindings.OVS_HYBRID_PLUG
        # agent didn't report so it should be hybrid based on server config
        context = self._make_port_ctx(self.AGENTS)
        self.driver.bind_port(context)
        self.assertTrue(context._bound_vif_details[hybrid])
        self.driver.vif_details[hybrid] = False
        context = self._make_port_ctx(self.AGENTS)
        self.driver.bind_port(context)
        self.assertFalse(context._bound_vif_details[hybrid])

    def test_hybrid_plug_true_if_agent_requests(self):
        hybrid = portbindings.OVS_HYBRID_PLUG
        # set server side default to false and ensure that hybrid becomes
        # true if requested by the agent
        self.driver.vif_details[hybrid] = False
        agents = [{'alive': True,
                   'configurations': {hybrid: True},
                   'host': 'host'}]
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
                   'host': 'host'}]
        context = self._make_port_ctx(agents)
        self.driver.bind_port(context)
        self.assertFalse(context._bound_vif_details[hybrid])


class OpenvswitchMechanismGenericTestCase(OpenvswitchMechanismBaseTestCase,
                                          base.AgentMechanismGenericTestCase):
    pass


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

    VIF_DETAILS = {portbindings.OVS_DATAPATH_TYPE: 'system',
                   portbindings.CAP_PORT_FILTER: True,
                   portbindings.OVS_HYBRID_PLUG: True}

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
                    'tunnel_types': GOOD_TUNNEL_TYPES,
                    'datapath_type': a_const.OVS_DATAPATH_NETDEV,
                    'ovs_capabilities': {
                        'iface_types': [a_const.OVS_DPDK_VHOST_USER]}}

    VHOST_SERVER_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES,
                    'datapath_type': a_const.OVS_DATAPATH_NETDEV,
                    'ovs_capabilities': {
                        'iface_types': [a_const.OVS_DPDK_VHOST_USER_CLIENT]}}

    SYSTEM_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
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
        result = self.driver.get_vif_type(None, self.AGENT, None)
        self.assertEqual(portbindings.VIF_TYPE_VHOST_USER, result)

        result = self.driver.get_vif_type(None, self.AGENT_SERVER, None)
        self.assertEqual(portbindings.VIF_TYPE_VHOST_USER, result)

        result = self.driver.get_vif_type(None, self.AGENT_SYSTEM, None)
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
