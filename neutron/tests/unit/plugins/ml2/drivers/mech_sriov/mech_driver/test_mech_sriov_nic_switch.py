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
from oslo_config import cfg
import testtools

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import config  # noqa
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver import mech_driver
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base

MELLANOX_CONNECTX3_PCI_INFO = '15b3:1004'
DEFAULT_PCI_INFO = ['15b3:1004', '8086:10ca']


class TestFakePortContext(base.FakePortContext):
        def __init__(self, agent_type, agents, segments,
                     vnic_type=portbindings.VNIC_NORMAL,
                     profile={'pci_vendor_info':
                              MELLANOX_CONNECTX3_PCI_INFO}):
            super(TestFakePortContext, self).__init__(agent_type,
                                                      agents,
                                                      segments,
                                                      vnic_type)
            self._bound_profile = profile

        @property
        def current(self):
            return {'id': base.PORT_ID,
                    'binding:vnic_type': self._bound_vnic_type,
                    'binding:profile': self._bound_profile}

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

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_device'}
    GOOD_CONFIGS = {'device_mappings': GOOD_MAPPINGS}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_device'}
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
        cfg.CONF.set_override('supported_pci_vendor_devs',
                              DEFAULT_PCI_INFO,
                              'ml2_sriov')
        cfg.CONF.set_override('agent_required', True, 'ml2_sriov')
        super(SriovNicSwitchMechanismBaseTestCase, self).setUp()
        self.driver = mech_driver.SriovNicSwitchMechanismDriver()
        self.driver.initialize()


class SriovSwitchMechGenericTestCase(SriovNicSwitchMechanismBaseTestCase,
                                     base.AgentMechanismGenericTestCase):
    def test_check_segment(self):
        """Validate the check_segment call."""
        segment = {'api.NETWORK_TYPE': ""}
        segment[api.NETWORK_TYPE] = p_const.TYPE_VLAN
        self.assertTrue(self.driver.check_segment(segment))
        # Validate a network type not currently supported
        segment[api.NETWORK_TYPE] = p_const.TYPE_GRE
        self.assertFalse(self.driver.check_segment(segment))

    def test_check_segment_allows_supported_network_types(self):
        for network_type in self.driver.supported_network_types:
            segment = {api.NETWORK_TYPE: network_type}
            self.assertTrue(self.driver.check_segment(segment))


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


class SriovSwitchMechProfileTestCase(SriovNicSwitchMechanismBaseTestCase):
    def _check_vif_for_pci_info(self, pci_vendor_info, expected_vif_type):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT,
                                      {'pci_vendor_info': pci_vendor_info})
        self.driver.bind_port(context)
        self.assertEqual(expected_vif_type, context._bound_vif_type)

    def test_profile_supported_pci_info(self):
        self._check_vif_for_pci_info(MELLANOX_CONNECTX3_PCI_INFO,
                                     portbindings.VIF_TYPE_HW_VEB)

    def test_profile_unsupported_pci_info(self):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.'
                        'mech_driver.mech_driver.LOG') as log_mock:
            self._check_vif_for_pci_info('xxxx:yyyy', None)
            log_mock.debug.assert_called_with('Refusing to bind due to '
                                              'unsupported pci_vendor device')


class SriovSwitchMechProfileFailTestCase(SriovNicSwitchMechanismBaseTestCase):
    def _check_for_pci_vendor_info(self, pci_vendor_info):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT,
                                      pci_vendor_info)
        self.driver._check_supported_pci_vendor_device(context)

    def test_profile_missing_profile(self):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.'
                        'mech_driver.mech_driver.LOG') as log_mock:
            self._check_for_pci_vendor_info({})
            log_mock.debug.assert_called_with("Missing profile in port"
                                              " binding")

    def test_profile_missing_pci_vendor_info(self):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.'
                        'mech_driver.mech_driver.LOG') as log_mock:
            self._check_for_pci_vendor_info({'aa': 'bb'})
            log_mock.debug.assert_called_with("Missing pci vendor"
                                              " info in profile")


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
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT}
        vif_details = self.driver._get_vif_details(segment)
        vlan_id = vif_details[portbindings.VIF_DETAILS_VLAN]
        self.assertEqual('0', vlan_id)

    def test_get_vif_details_unsupported_net(self):
        segment = {api.NETWORK_TYPE: 'foo'}
        with testtools.ExpectedException(exc.SriovUnsupportedNetworkType):
            self.driver._get_vif_details(segment)

    def test_get_vif_details_without_agent(self):
        cfg.CONF.set_override('agent_required', False, 'ml2_sriov')
        self.driver = mech_driver.SriovNicSwitchMechanismDriver()
        self.driver.initialize()
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT)

        self.driver.bind_port(context)
        self.assertEqual(constants.PORT_STATUS_ACTIVE, context._bound_state)

    def test_get_vif_details_with_agent(self):
        context = TestFakePortContext(self.AGENT_TYPE,
                                      self.AGENTS,
                                      self.VLAN_SEGMENTS,
                                      portbindings.VNIC_DIRECT)

        self.driver.bind_port(context)
        self.assertEqual(constants.PORT_STATUS_DOWN, context._bound_state)


class SriovSwitchMechConfigTestCase(SriovNicSwitchMechanismBaseTestCase):
    def _set_config(self, pci_devs=['aa:bb']):
        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'sriovnicswitch'], 'ml2')
        cfg.CONF.set_override('supported_pci_vendor_devs', pci_devs,
                              'ml2_sriov')

    def test_pci_vendor_config_single_entry(self):
        self._set_config()
        self.driver.initialize()
        self.assertEqual(['aa:bb'], self.driver.pci_vendor_info)

    def test_pci_vendor_config_multiple_entry(self):
        self._set_config(['x:y', 'a:b'])
        self.driver.initialize()
        self.assertEqual(['x:y', 'a:b'], self.driver.pci_vendor_info)

    def test_pci_vendor_config_default_entry(self):
        self.driver.initialize()
        self.assertEqual(DEFAULT_PCI_INFO,
                         self.driver.pci_vendor_info)

    def test_pci_vendor_config_wrong_entry(self):
        self._set_config(['wrong_entry'])
        self.assertRaises(cfg.Error, self.driver.initialize)

    def test_initialize_missing_product_id(self):
        self._set_config(['vendor_id:'])
        self.assertRaises(cfg.Error, self.driver.initialize)

    def test_initialize_missing_vendor_id(self):
        self._set_config([':product_id'])
        self.assertRaises(cfg.Error, self.driver.initialize)

    def test_initialize_multiple_colons(self):
        self._set_config(['foo:bar:baz'])
        self.assertRaises(cfg.Error, self.driver.initialize)

    def test_initialize_empty_string(self):
        self._set_config([''])
        self.assertRaises(cfg.Error, self.driver.initialize)
