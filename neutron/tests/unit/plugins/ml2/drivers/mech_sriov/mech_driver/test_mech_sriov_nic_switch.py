# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
import testtools

from neutron.conf.plugins.ml2.drivers.mech_sriov import mech_sriov_conf
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver import mech_driver
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class TestFakePortContext(base.FakePortContext):
    def __init__(self, agent_type, agents, segments,
                 vnic_type=portbindings.VNIC_NORMAL,
                 profile=None):
        super(TestFakePortContext, self).__init__(agent_type,
                                                  agents,
                                                  segments,
                                                  vnic_type=vnic_type,
                                                  profile=profile)

    def set_binding(self, segment_id, vif_type, vif_details, state):
        self._bound_segment_id = segment_id
        self._bound_vif_type = vif_type
        self._bound_vif_details = vif_details
        self._bound_state = state


class SriovNicSwitchMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_HW_VEB
    CAP_PORT_FILTER = False
    AGENT_TYPE = constants.AGENT_TYPE_NIC_SWITCH
    VLAN_SEGMENTS = base.AgentMechanismVlanTestCase.VLAN_SEGMENTS

    GOOD_MAPPINGS = {'fake_physical_network': ['fake_device']}
    GOOD_CONFIGS = {'device_mappings': GOOD_MAPPINGS}

    BAD_MAPPINGS = {'wrong_physical_network': ['wrong_device']}
    BAD_CONFIGS = {'device_mappings': BAD_MAPPINGS}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'agent_type': AGENT_TYPE,
               }]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'agent_type': AGENT_TYPE,
                    }]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'agent_type': AGENT_TYPE,
                   },
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'agent_type': AGENT_TYPE,
                   }]

    def setUp(self):
        super(SriovNicSwitchMechanismBaseTestCase, self).setUp()
        self.driver = mech_driver.SriovNicSwitchMechanismDriver()
        self.driver.initialize()


class SriovSwitchMechGenericTestCase(SriovNicSwitchMechanismBaseTestCase,
                                     base.AgentMechanismGenericTestCase):
    def test_check_segment(self):
        """Validate the check_segment call."""
        agent = {'agent_type': self.AGENT_TYPE,
                 'configurations': {'device_mappings': ['physnet1']}}
        segment = {api.NETWORK_TYPE: constants.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: 'physnet1'}
        self.assertTrue(self.driver.check_segment_for_agent(segment, agent))
        # Validate a network type not currently supported
        segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertFalse(self.driver.check_segment_for_agent(segment, agent))

    def test_check_segment_allows_supported_network_types(self):
        for network_type in self.driver.get_allowed_network_types(agent=None):
            agent = {'agent_type': self.AGENT_TYPE,
                     'configurations': {'device_mappings': ['physnet1']}}
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: 'physnet1'}
            self.assertTrue(self.driver.check_segment_for_agent(segment,
                                                                agent))

    def test_driver_responsible_for_ports_allocation(self):
        agents = [
            {'agent_type': constants.AGENT_TYPE_NIC_SWITCH,
             'configurations': {'resource_provider_bandwidths': {'eth0': {}}},
             'host': 'host',
             'id': '1'}
        ]
        segments = []
        # uuid -v5 87f1895c-73bb-11e8-9008-c4d987b2a692 host:eth0
        profile = {'allocation':
            {'fake_request_group_uuid':
                '5762cf50-781b-5f01-8ebc-0cce8c9e74cd'}}

        port_ctx = base.FakePortContext(
            self.AGENT_TYPE,
            agents,
            segments,
            vnic_type=portbindings.VNIC_DIRECT,
            profile=profile)
        with mock.patch.object(self.driver, '_possible_agents_for_port',
                               return_value=agents):
            self.assertTrue(
                self.driver.responsible_for_ports_allocation(port_ctx))


class SriovMechVlanTestCase(SriovNicSwitchMechanismBaseTestCase,
                            base.AgentMechanismBaseTestCase):
    VLAN_SEGMENTS = [{api.ID: 'unknown_segment_id',
                      api.NETWORK_TYPE: 'no_such_type'},
                     {api.ID: 'vlan_segment_id',
                      api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'fake_physical_network',
                      api.SEGMENTATION_ID: 1234}]

    def test_type_vlan(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.VLAN_SEGMENTS,
                                  portbindings.VNIC_DIRECT)
        self.driver.bind_port(context)
        self._check_bound(context, self.VLAN_SEGMENTS[1])

    def test_type_vlan_bad(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                  self.AGENTS_BAD,
                                  self.VLAN_SEGMENTS,
                                  portbindings.VNIC_DIRECT)
        self.driver.bind_port(context)
        self._check_unbound(context)


class SriovSwitchMechVnicTypeTestCase(SriovNicSwitchMechanismBaseTestCase):
    def _check_vif_type_for_vnic_type(self, vnic_type,
                                      expected_vif_type):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      vnic_type)
        self.driver.bind_port(context)
        self.assertEqual(expected_vif_type, context._bound_vif_type)
        vlan = int(context._bound_vif_details[portbindings.VIF_DETAILS_VLAN])
        self.assertEqual(1234, vlan)

    def test_vnic_type_direct(self):
        self._check_vif_type_for_vnic_type(portbindings.VNIC_DIRECT,
                                           portbindings.VIF_TYPE_HW_VEB)

    def test_vnic_type_macvtap(self):
        self._check_vif_type_for_vnic_type(portbindings.VNIC_MACVTAP,
                                           portbindings.VIF_TYPE_HW_VEB)

    def test_vnic_type_direct_physical(self):
        self._check_vif_type_for_vnic_type(portbindings.VNIC_DIRECT_PHYSICAL,
                                           portbindings.VIF_TYPE_HOSTDEV_PHY)

    @mock.patch.object(mech_driver.SriovNicSwitchMechanismDriver,
                       'try_to_bind_segment_for_agent')
    def test_vnic_type_direct_with_switchdev_cap(self, mocked_bind_segment):
        profile = {'capabilities': ['switchdev']}
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT,
                                      profile)
        self.driver.bind_port(context)
        mocked_bind_segment.assert_not_called()


class SriovSwitchMechVifDetailsTestCase(SriovNicSwitchMechanismBaseTestCase):
    VLAN_SEGMENTS = [{api.ID: 'vlan_segment_id',
                      api.NETWORK_TYPE: 'vlan',
                      api.PHYSICAL_NETWORK: 'fake_physical_network',
                      api.SEGMENTATION_ID: 1234}]

    def test_vif_details_contains_vlan_id(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT)

        self.driver.bind_port(context)
        vif_details = context._bound_vif_details
        self.assertIsNotNone(vif_details)
        vlan_id = int(vif_details.get(portbindings.VIF_DETAILS_VLAN))
        self.assertEqual(1234, vlan_id)

    def test_get_vif_details_for_flat_network(self):
        segment = {api.NETWORK_TYPE: constants.TYPE_FLAT}
        vif_details = self.driver._get_vif_details(segment)
        vlan_id = vif_details[portbindings.VIF_DETAILS_VLAN]
        self.assertEqual('0', vlan_id)

    def test_get_vif_details_unsupported_net(self):
        segment = {api.NETWORK_TYPE: 'foo'}
        with testtools.ExpectedException(exc.SriovUnsupportedNetworkType):
            self.driver._get_vif_details(segment)

    def test_get_vif_details_with_agent(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT)

        self.driver.bind_port(context)
        self.assertEqual(constants.PORT_STATUS_DOWN, context._bound_state)

    def test_get_vif_details_with_agent_direct_physical(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT_PHYSICAL)

        self.driver.bind_port(context)
        self.assertEqual(constants.PORT_STATUS_ACTIVE, context._bound_state)


class SriovSwitchMechVnicTypesTestCase(SriovNicSwitchMechanismBaseTestCase):

    def setUp(self):
        self.override_vnic_types = [portbindings.VNIC_DIRECT,
                                    portbindings.VNIC_MACVTAP]
        self.default_supported_vnics = list(
            mech_driver.SRIOV_SUPPORTED_VNIC_TYPES)
        mech_driver.SRIOV_SUPPORTED_VNIC_TYPES = self.override_vnic_types
        self.driver_with_vnic_types = (
            mech_driver.SriovNicSwitchMechanismDriver())
        self.prohibit_list_cfg = {
            'SRIOV_DRIVER': {
                'vnic_type_prohibit_list': []
            }
        }
        super(SriovSwitchMechVnicTypesTestCase, self).setUp()

    def test_default_vnic_types(self):
        mech_driver.SRIOV_SUPPORTED_VNIC_TYPES = self.default_supported_vnics
        mech_sriov = mech_driver.SriovNicSwitchMechanismDriver()
        self.assertEqual(self.default_supported_vnics,
                         mech_sriov.supported_vnic_types)

    def test_override_default_vnic_types(self):
        self.assertEqual(
            self.override_vnic_types,
            self.driver_with_vnic_types.supported_vnic_types)

    def test_vnic_type_prohibit_list_valid_item(self):
        self.prohibit_list_cfg['SRIOV_DRIVER']['vnic_type_prohibit_list'] = \
            [portbindings.VNIC_MACVTAP]

        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_sriov_conf.register_sriov_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        mech_driver.SRIOV_SUPPORTED_VNIC_TYPES = self.default_supported_vnics
        test_driver = mech_driver.SriovNicSwitchMechanismDriver()

        supported_vnic_types = test_driver.supported_vnic_types
        self.assertNotIn(portbindings.VNIC_MACVTAP, supported_vnic_types)
        self.assertEqual(len(self.default_supported_vnics) - 1,
                         len(supported_vnic_types))

    def test_vnic_type_prohibit_list_not_valid_item(self):
        self.prohibit_list_cfg['SRIOV_DRIVER']['vnic_type_prohibit_list'] = \
            ['foo']
        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_sriov_conf.register_sriov_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        self.assertRaises(ValueError,
                          mech_driver.SriovNicSwitchMechanismDriver)

    def test_vnic_type_prohibit_list_all_items(self):
        self.prohibit_list_cfg['SRIOV_DRIVER']['vnic_type_prohibit_list'] = \
            [portbindings.VNIC_DIRECT,
             portbindings.VNIC_MACVTAP,
             portbindings.VNIC_DIRECT_PHYSICAL,
             portbindings.VNIC_ACCELERATOR_DIRECT,
             ]

        fake_conf = cfg.CONF
        fake_conf_fixture = base.MechDriverConfFixture(
            fake_conf, self.prohibit_list_cfg,
            mech_sriov_conf.register_sriov_mech_driver_opts)
        self.useFixture(fake_conf_fixture)

        self.assertRaises(ValueError,
                          mech_driver.SriovNicSwitchMechanismDriver)


class SriovSwitchDeviceMappingsTestCase(SriovNicSwitchMechanismBaseTestCase):

    def test_standard_device_mappings(self):
        mappings = self.driver.get_standard_device_mappings(self.AGENTS[0])
        self.assertDictEqual(self.GOOD_CONFIGS['device_mappings'], mappings)

    def test_standard_device_mappings_negative(self):
        fake_agent = {'agent_type': constants.AGENT_TYPE_NIC_SWITCH,
                      'configurations': {}}
        self.assertRaises(ValueError, self.driver.get_standard_device_mappings,
                          fake_agent)
