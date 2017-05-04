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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api

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

    AGENT = {'alive': True,
             'configurations': GOOD_CONFIGS,
             'host': 'host'}
    AGENTS = [AGENT]

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


class MacvtapMechanismMigrationTestCase(object):
    # MIGRATION_SEGMENT must be overridden for the specific type being tested
    MIGRATION_SEGMENT = None

    MIGRATION_SEGMENTS = [MIGRATION_SEGMENT]

    def test__is_live_migration_true(self):
        original = {"binding:profile": {"migrating_to": "host"}}
        self._test__is_live_migration(True, original)

    def test__is_live_migration_false(self):
        self._test__is_live_migration(False, {})

    def test__is_live_migration_false_None_original(self):
        self._test__is_live_migration(False, None)

    def _test__is_live_migration(self, expected, original):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS,
                                       self.MIGRATION_SEGMENTS,
                                       vnic_type=self.VNIC_TYPE,
                                       original=original)

        self.assertEqual(expected, self.driver._is_live_migration(context))

    def _test_try_to_bind_segment_for_agent_migration(self, expected,
                                                      original):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS,
                                       self.MIGRATION_SEGMENTS,
                                       vnic_type=self.VNIC_TYPE,
                                       original=original)
        result = self.driver.try_to_bind_segment_for_agent(
            context, self.MIGRATION_SEGMENT, self.AGENT)
        self.assertEqual(expected, result)

    def test_try_to_bind_segment_for_agent_migration_abort(self):
        original = {"binding:profile": {"migrating_to": "host"},
                    "binding:vif_details": {"macvtap_source": "bad_source"},
                    "binding:host_id": "source_host"}
        self._test_try_to_bind_segment_for_agent_migration(False, original)

    def test_try_to_bind_segment_for_agent_migration_ok(self):
        macvtap_src = "fake_if"
        seg_id = self.MIGRATION_SEGMENT.get(api.SEGMENTATION_ID)
        if seg_id:
            # In the vlan case, macvtap source name ends with .vlan_id
            macvtap_src += "." + str(seg_id)
        original = {"binding:profile": {"migrating_to": "host"},
                    "binding:vif_details": {"macvtap_source": macvtap_src},
                    "binding:host_id": "source_host"}
        self._test_try_to_bind_segment_for_agent_migration(True, original)


class MacvtapMechanismFlatTestCase(MacvtapMechanismBaseTestCase,
                                   base.AgentMechanismFlatTestCase,
                                   MacvtapMechanismMigrationTestCase):
    MIGRATION_SEGMENT = {api.ID: 'flat_segment_id',
                         api.NETWORK_TYPE: 'flat',
                         api.PHYSICAL_NETWORK: 'fake_physical_network'}

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
                                   base.AgentMechanismVlanTestCase,
                                   MacvtapMechanismMigrationTestCase):
    MIGRATION_SEGMENT = {api.ID: 'vlan_segment_id',
                         api.NETWORK_TYPE: 'vlan',
                         api.PHYSICAL_NETWORK: 'fake_physical_network',
                         api.SEGMENTATION_ID: 1234}

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
