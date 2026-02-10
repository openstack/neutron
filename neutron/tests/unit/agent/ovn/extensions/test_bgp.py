# Copyright 2026 Red Hat, LLC
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

from neutron.agent.ovn.extensions import bgp as bgp_ext
from neutron.tests import base


class TestBGPAgentExtensionWatchPortCreatedEvent(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.extension = bgp_ext.BGPAgentExtension()
        self.extension.agent_api = mock.Mock()
        self.event_handler = (
            self.extension.agent_api.ovs_idl.idl.notify_handler)

        self.bgp_bridge = mock.Mock()
        self.bgp_bridge.name = 'br-bgp'

    def test_port_already_exists_configures_flows(self):
        self.bgp_bridge.ovs_bridge.get_iface_ofports_by_type.return_value = [5]
        self.bgp_bridge.check_requirements_for_flows_met.return_value = True

        self.extension.watch_port_created_event(self.bgp_bridge, 'patch')

        self.bgp_bridge.configure_flows.assert_called_once()

    def test_port_already_exists_requirements_not_met_no_configure_flows(self):
        self.bgp_bridge.ovs_bridge.get_iface_ofports_by_type.return_value = [5]
        self.bgp_bridge.check_requirements_for_flows_met.return_value = False

        self.extension.watch_port_created_event(self.bgp_bridge, 'patch')

        self.bgp_bridge.configure_flows.assert_not_called()

    def test_port_missing_watches_event(self):
        self.bgp_bridge.ovs_bridge.get_iface_ofports_by_type.return_value = []

        self.extension.watch_port_created_event(self.bgp_bridge, 'patch')

        self.event_handler.watch_event.assert_called_once()
        self.bgp_bridge.configure_flows.assert_not_called()

    def test_port_created_in_meantime_unwatches_and_configures_flows(self):
        self.bgp_bridge.ovs_bridge.get_iface_ofports_by_type.side_effect = [
            [],
            [7],
        ]
        self.bgp_bridge.check_requirements_for_flows_met.return_value = True

        self.extension.watch_port_created_event(self.bgp_bridge, 'patch')

        self.event_handler.watch_event.assert_called_once()
        self.event_handler.unwatch_event.assert_called_once()
        self.bgp_bridge.configure_flows.assert_called_once()

    def test_port_created_in_meantime_requirements_not_met_no_configure_flows(
            self):
        self.bgp_bridge.ovs_bridge.get_iface_ofports_by_type.side_effect = [
            [],
            [3],
        ]
        self.bgp_bridge.check_requirements_for_flows_met.return_value = False

        self.extension.watch_port_created_event(self.bgp_bridge, 'patch')

        self.event_handler.watch_event.assert_called_once()
        self.event_handler.unwatch_event.assert_called_once()
        self.bgp_bridge.configure_flows.assert_not_called()
