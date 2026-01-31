# Copyright 2025 Red Hat, Inc.
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

from oslo_utils import uuidutils

from neutron.agent.ovn.extensions.bgp import commands
from neutron.services.bgp import constants
from neutron.tests.functional.services import bgp


def _get_unique_name(prefix="test"):
    return f"{prefix}_{uuidutils.generate_uuid()[:8]}"


class SetChassisBgpBridgesCommandTestCase(bgp.BaseBgpSbIdlTestCase):
    def _get_chassis_bgp_bridges(self, chassis_name):
        chassis = self.sb_api.lookup('Chassis_Private', chassis_name)
        bridges_str = chassis.external_ids.get(
            constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY, '')
        if bridges_str:
            return bridges_str.split(',')
        return []

    def test_set_bridges_on_chassis_without_existing_bridges(self):
        chassis = self.add_fake_chassis(_get_unique_name("chassis"), '1.1.1.1')
        bridge_name = _get_unique_name("bridge")

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertFalse(bridges)

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, [bridge_name]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([bridge_name], bridges)

    def test_set_bridges_replaces_existing_bridges(self):
        existing_bridge = _get_unique_name("existing_bridge")
        chassis = self.add_fake_chassis(
            _get_unique_name("chassis"), '1.1.1.2',
            external_ids={
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY: existing_bridge
            })
        new_bridge = _get_unique_name("new_bridge")

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([existing_bridge], bridges)

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, [new_bridge]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([new_bridge], bridges)

    def test_set_bridges_is_idempotent(self):
        bridge_name = _get_unique_name("bridge")
        chassis = self.add_fake_chassis(
            _get_unique_name("chassis"), '1.1.1.3',
            external_ids={
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY: bridge_name
            })

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([bridge_name], bridges)

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, [bridge_name]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([bridge_name], bridges)

    def test_set_bridges_replaces_multiple_existing(self):
        existing_bridge1 = _get_unique_name("existing_bridge1")
        existing_bridge2 = _get_unique_name("existing_bridge2")
        existing_bridges_str = f"{existing_bridge1},{existing_bridge2}"
        chassis = self.add_fake_chassis(
            _get_unique_name("chassis"), '1.1.1.4',
            external_ids={
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY: existing_bridges_str
            })
        new_bridge = _get_unique_name("new_bridge")

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertCountEqual([existing_bridge1, existing_bridge2], bridges)

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, [new_bridge]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([new_bridge], bridges)

    def test_set_multiple_bridges_at_once(self):
        chassis = self.add_fake_chassis(_get_unique_name("chassis"), '1.1.1.5')
        bridge1 = _get_unique_name("bridge1")
        bridge2 = _get_unique_name("bridge2")
        bridge3 = _get_unique_name("bridge3")

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name,
            [bridge1, bridge2, bridge3]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertCountEqual([bridge1, bridge2, bridge3], bridges)

    def test_set_bridges_preserves_other_external_ids(self):
        other_key = 'other-external-id'
        other_value = 'some-value'
        chassis = self.add_fake_chassis(
            _get_unique_name("chassis"), '1.1.1.6',
            external_ids={other_key: other_value})
        bridge_name = _get_unique_name("bridge")

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, [bridge_name]).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([bridge_name], bridges)

        chassis = self.sb_api.lookup('Chassis_Private', chassis.name)
        self.assertEqual(other_value, chassis.external_ids.get(other_key))

    def test_set_empty_bridges_clears_existing(self):
        existing_bridge = _get_unique_name("existing_bridge")
        chassis = self.add_fake_chassis(
            _get_unique_name("chassis"), '1.1.1.7',
            external_ids={
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY: existing_bridge
            })

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertEqual([existing_bridge], bridges)

        commands.SetChassisBgpBridgesCommand(
            self.sb_api, chassis.name, []).execute(check_error=True)

        bridges = self._get_chassis_bgp_bridges(chassis.name)
        self.assertFalse(bridges)
