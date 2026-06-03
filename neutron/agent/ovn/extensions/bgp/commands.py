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

import re

from ovsdbapp.backend.ovs_idl import command as ovs_cmd

from neutron.agent.ovn.extensions.bgp import exceptions
from neutron.services.bgp import constants
from neutron.services.bgp import helpers

RE_IC_SWITCH_NAME = re.compile(r'bgp-lsp-(?P<ic_switch_name>.*)-localnet')


class SetChassisBgpBridgesCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, chassis_name, bridge_name_list):
        super().__init__(api)
        self.chassis_name = chassis_name
        self.bridge_name_list = bridge_name_list

    def run_idl(self, txn):
        chassis = self.api.lookup('Chassis_Private', self.chassis_name)
        external_ids = chassis.external_ids
        external_ids[constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY] = ','.join(
            sorted(self.bridge_name_list))

        self.set_column(chassis, 'external_ids', external_ids)


class GetInterconnectLrpMacCommand(ovs_cmd.ReadOnlyCommand):
    """Return the LRP MAC for the router port on the same switch as a localnet.

    Given the name of a localnet LSP on an interconnect switch, find the
    sibling LSP of type ``router``, resolve its peer Logical_Router_Port,
    and return ``lrp.mac``.
    """

    def __init__(self, api, localnet_lsp_name):
        super().__init__(api)
        if not localnet_lsp_name:
            raise exceptions.InterconnectLrpMacNotFound(
                "Localnet LSP name is not set")
        match = RE_IC_SWITCH_NAME.match(localnet_lsp_name)
        if not match:
            raise exceptions.InterconnectLrpMacNotFound(
                f"Localnet LSP {localnet_lsp_name} does not fit the "
                "naming convention pattern 'bgp-lsp-<ic_switch_name>-localnet'"
            )
        ic_switch_name = match.group('ic_switch_name')
        self.lrp_name = helpers.get_lrp_name(
            constants.MAIN_ROUTER_NAME, ic_switch_name)

    def run_idl(self, txn):
        lrp = self.api.lookup("Logical_Router_Port", self.lrp_name)
        self.result = lrp.mac


class GetPatchPortsFromBridgeCommand(ovs_cmd.ReadOnlyCommand):
    def __init__(self, api, bridge_name):
        super().__init__(api)
        self.bridge_name = bridge_name

    def run_idl(self, txn):
        self.result = []
        bridge = self.api.lookup('Bridge', self.bridge_name)
        for port in bridge.ports:
            if port.name == self.bridge_name:
                continue
            for iface in port.interfaces:
                if iface.type == 'patch' and iface.ofport:
                    self.result.append(iface)
