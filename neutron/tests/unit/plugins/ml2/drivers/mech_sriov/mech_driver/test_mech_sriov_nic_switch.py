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

import mock
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
import testtools

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
               'configurations': GOOD_CONFIGS}]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS},
                  {'alive': True,
                   'configurations': BAD_CONFIGS}]

    def setUp(self):
        super(SriovNicSwitchMechanismBaseTestCase, self).setUp()
        self.driver = mech_driver.SriovNicSwitchMechanismDriver()
        self.driver.initialize()


class SriovSwitchMechGenericTestCase(SriovNicSwitchMechanismBaseTestCase,
                                     base.AgentMechanismGenericTestCase):
    def test_check_segment(self):
        """Validate the check_segment call."""
        segment = {'api.NETWORK_TYPE': ""}
        segment[api.NETWORK_TYPE] = constants.TYPE_VLAN
        self.assertTrue(self.driver.check_segment_for_agent(segment))
        # Validate a network type not currently supported
        segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertFalse(self.driver.check_segment_for_agent(segment))

    def test_check_segment_allows_supported_network_types(self):
        for network_type in self.driver.get_allowed_network_types(agent=None):
            segment = {api.NETWORK_TYPE: network_type}
            self.assertTrue(self.driver.check_segment_for_agent(segment))


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
