# Copyright (c) 2015 IBM Corp.
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

from neutron_lib import constants

from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.macvtap.mech_driver import mech_macvtap
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base


class MacvtapMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_MACVTAP
    CAP_PORT_FILTER = False
    AGENT_TYPE = constants.AGENT_TYPE_MACVTAP

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_if'}
    GOOD_CONFIGS = {'interface_mappings': GOOD_MAPPINGS}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_if'}
    BAD_CONFIGS = {'interface_mappings': BAD_MAPPINGS}

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
        super(MacvtapMechanismBaseTestCase, self).setUp()
        self.driver = mech_macvtap.MacvtapMechanismDriver()
        self.driver.initialize()


class MacvtapMechanismGenericTestCase(MacvtapMechanismBaseTestCase,
                                      base.AgentMechanismGenericTestCase):
    pass


class MacvtapMechanismFlatTestCase(MacvtapMechanismBaseTestCase,
                                   base.AgentMechanismFlatTestCase):
    def test_type_flat_vif_details(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.FLAT_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        vif_details = context._bound_vif_details

        self.assertIsNone(vif_details.get(portbindings.VIF_DETAILS_VLAN))
        self.assertEqual("bridge", vif_details.get(
                                        portbindings.VIF_DETAILS_MACVTAP_MODE))
        self.assertEqual("fake_if", vif_details.get(
                                portbindings.VIF_DETAILS_PHYSICAL_INTERFACE))
        self.assertEqual("fake_if", vif_details.get(
                                    portbindings.VIF_DETAILS_MACVTAP_SOURCE))


class MacvtapMechanismVlanTestCase(MacvtapMechanismBaseTestCase,
                                   base.AgentMechanismVlanTestCase):
    def test_type_vlan_vif_details(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                  self.AGENTS,
                                  self.VLAN_SEGMENTS,
                                  vnic_type=self.VNIC_TYPE)
        self.driver.bind_port(context)
        vif_details = context._bound_vif_details

        self.assertEqual(1234, vif_details.get(portbindings.VIF_DETAILS_VLAN))
        self.assertEqual("bridge", vif_details.get(
                                       portbindings.VIF_DETAILS_MACVTAP_MODE))
        self.assertEqual("fake_if", vif_details.get(
                                portbindings.VIF_DETAILS_PHYSICAL_INTERFACE))
        self.assertEqual("fake_if.1234", vif_details.get(
                                     portbindings.VIF_DETAILS_MACVTAP_SOURCE))
