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


from oslo_log import log

from neutron.agent.common import ovs_lib
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants

LOG = log.getLogger(__name__)


class Bridge:
    def __init__(self, bgp_agent_api, name):
        self.bgp_agent_api = bgp_agent_api
        self.name = name
        self.ovs_bridge = ovs_lib.OVSBridge(name)

    @property
    def ovs_idl(self):
        return self.bgp_agent_api.agent_api.ovs_idl

    @property
    def sb_idl(self):
        return self.bgp_agent_api.agent_api.sb_idl


class BGPChassisBridge(Bridge):
    """BGP Bridge

    The BGP bridge is the provider bridge that connects a chassis to a BGP
    physical interface connected to a BGP peer, typically a leaf switch.
    """
    def __init__(self, bgp_agent_api, name):
        super().__init__(bgp_agent_api, name)
        self.lrp_mac = self._get_lrp_mac()
        self._requirements = [
            ('patch port ofport is not set', self.patch_port_ofport),
            ('LRP MAC is not set', self.lrp_mac),
        ]

    def __str__(self):
        return f"BGPChassisBridge(name={self.name})"

    __repr__ = __str__

    def _check_requirements_for_flows_met(self):
        for msg, requirement in self._requirements:
            if not requirement:
                LOG.debug(
                    "Bridge %s: %s, skipping installing flows",
                    self.name, msg)
                return False
        return True

    @property
    def patch_port_ofport(self):
        patch_ports_ofports = self.ovs_bridge.get_iface_ofports_by_type(
            'patch')
        if len(patch_ports_ofports) > 1:
            LOG.warning("The patch port for bridge %s has multiple ofports: "
                        "%s, using the first one",
                        self.name, patch_ports_ofports)
        try:
            return patch_ports_ofports[0]
        except IndexError:
            LOG.debug("The patch port for bridge %s does not exist yet",
                      self.name)
            return None

    def _get_lrp_mac(self):
        ext_ids = {constants.LRP_NETWORK_NAME_EXT_ID_KEY: self.name}
        port_bindings = self.sb_idl.db_find_rows(
            'Port_Binding',
            ('type', '=', ovn_const.PB_TYPE_L3GATEWAY),
            ('external_ids', '=', ext_ids)).execute(
                check_error=True)
        if port_bindings:
            pb = port_bindings[0]
            try:
                return ovn_utils.get_mac_and_ips_from_port_binding(pb)[0]
            except ValueError:
                LOG.error("Failed to get MAC address from port binding %s",
                            pb.uuid)

        LOG.debug("LRP MAC does not exist yet for %s", self.name)

    def configure_flows(self):
        # TODO(jlibosva) Implement flows configuration
        pass
