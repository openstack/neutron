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

import tempfile

import netaddr
from neutron_lib import constants
from oslo_log import log

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.agent.ovn.extensions.bgp import commands
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants as bgp_const

LOG = log.getLogger(__name__)


class Bridge:
    def __init__(self, bgp_agent_api, name):
        self.bgp_agent_api = bgp_agent_api
        self.name = name
        self.ovs_bridge = ovs_lib.OVSBridge(name)
        self._requirements = []

    @property
    def ovs_idl(self):
        return self.bgp_agent_api.agent_api.ovs_idl

    @property
    def sb_idl(self):
        return self.bgp_agent_api.agent_api.sb_idl

    def get_port_ofport(self, port_name):
        if port_name:
            return self.ovs_bridge.get_port_ofport(port_name)

    def check_requirements_for_flows_met(self):
        for msg, requirement in self._requirements:
            if not getattr(self, requirement):
                LOG.debug(
                    "Bridge %s: %s, skipping installing flows",
                    self.name, msg)
                return False
        return True

    def _apply_flows_as_bundle(self, flows):
        """Apply multiple OpenFlow rules as a bundle using temporary file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.flows',
                                         prefix='bgp_', delete=True) as f:
            f.write("delete\n")
            for flow in flows:
                f.write(f"{flow}\n")
            f.flush()

            LOG.debug("Applying %d BGP flows as bundle to bridge %s",
                      len(flows), self.name)

            self.ovs_bridge.run_ofctl(
                "add-flows", ["--bundle", f.name])


class BGPChassisBridge(Bridge):
    """BGP Bridge

    The BGP bridge is the provider bridge that connects a chassis to a BGP
    physical interface connected to a BGP peer, typically a leaf switch.
    """

    def __init__(self, bgp_agent_api, name):
        super().__init__(bgp_agent_api, name)
        self._requirements = [
            ('bridge does not exist', 'exists'),
            ('NIC ofport is not set', 'nic_ofport'),
            ('patch port ofport is not set', 'patch_port_ofport'),
            ('LRP MAC is not set', 'lrp_mac'),
        ]

    def __str__(self):
        return f"BGPChassisBridge(name={self.name})"

    __repr__ = __str__

    @property
    def patch_port_ofport(self):
        patch_ports_ofports = self.ovs_bridge.get_iface_ofports_by_types(
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

    @property
    def nic_ofport(self):
        # REVISIT(jlibosva): we can consider supporting OVS bonds too
        nics_ofports = self.ovs_bridge.get_iface_ofports_by_types(
            *bgp_const.BGP_BRIDGE_NIC_TYPES)
        if len(nics_ofports) != 1:
            LOG.warning("Expected 1 NIC for bridge %s, got %s",
                        self.name, len(nics_ofports))
            return None
        return nics_ofports[0]

    @property
    def lrp_mac(self):
        ext_ids = {bgp_const.LRP_NETWORK_NAME_EXT_ID_KEY: self.name}
        port_bindings = self.sb_idl.db_find_rows(
            'Port_Binding',
            ('type', '=', ovn_const.PB_TYPE_L3GATEWAY),
            ('external_ids', '=', ext_ids),
            ('chassis', '=', self.bgp_agent_api.chassis_id),
        ).execute(check_error=True)
        if len(port_bindings) > 1:
            LOG.warning("Expected 1 LRP MAC for bridge %s and chassis %s "
                        "and got %s",
                        self.name, self.bgp_agent_api.chassis_name,
                        len(port_bindings))
            return None
        if port_bindings:
            pb = port_bindings[0]
            try:
                return ovn_utils.get_mac_and_ips_from_port_binding(pb)[0]
            except ValueError:
                LOG.error("Failed to get MAC address from port binding %s",
                          pb.logical_port)

        LOG.debug("LRP MAC does not exist yet for %s", self.name)

    @property
    def exists(self):
        return self.ovs_bridge.bridge_exists(self.name)

    @property
    def ips(self):
        return [netaddr.IPNetwork(ip['cidr'])
                for ip in ip_lib.get_devices_with_ip(
                    namespace=None, name=self.name)]

    def _get_flows_for_icmpv6(self):
        """Ingress flows for ICMPv6.

        We don't know if ND or RA related packets are from the host or the
        per chassis BGP router, so we flood the traffic to both.
        """
        flows = [(f"priority=100,in_port={self.nic_ofport},icmp6,"
                  f"icmp_type={icmp_type} "
                  f"actions=NORMAL,mod_dl_dst:{self.lrp_mac},"
                  f"output:{self.patch_port_ofport}")
                 for icmp_type in [133, 134, 135, 136]]

        return flows

    def _get_flows_for_host_ips(self):
        LOG.debug("Adding flows to direct traffic to the host from the NIC "
                  "port %s on bridge %s", self.nic_ofport, self.name)
        # Allow IPv6 link-local traffic
        flows = [f"priority=100,ipv6,in_port={self.nic_ofport},"
                 f"ipv6_dst=fe80::/64 actions=NORMAL,"
                 f"mod_dl_dst:{self.lrp_mac},output:{self.patch_port_ofport}"]

        # Direct traffic meant for the host IPs
        for host_ip in self.bgp_agent_api.hostdev_ips + self.ips:
            if host_ip.version == constants.IP_VERSION_4:
                flows.append(f"priority=100,ip,in_port={self.nic_ofport},"
                             f"nw_dst={host_ip.ip} actions=NORMAL")
            elif host_ip.version == constants.IP_VERSION_6:
                flows.append(f"priority=100,ipv6,in_port={self.nic_ofport},"
                             f"ipv6_dst={host_ip.ip} actions=NORMAL")

        return flows

    def configure_flows(self):
        # The resulting openflows rules that will be written to a temporary
        # file and applied to the bridge.
        if not self.check_requirements_for_flows_met():
            LOG.error("Some of the requirements to install flows on bridge "
                      "%s are missing, skipping", self.name)
            return

        LOG.debug("Configuring BGP bridge flows for %s", self.name)
        # Allow ARP and ICMPv6
        flows = [
            "priority=100,arp actions=NORMAL",

            # Put the destination MAC of the LRP on the per-chassis router for
            # any remaining traffic going from the NIC.
            (f"priority=80,in_port={self.nic_ofport},"
             f"actions=mod_dl_dst:{self.lrp_mac},"
             f"output:{self.patch_port_ofport}"),

            # Any traffic coming from the patch port should go out.
            (f"priority=100,in_port={self.patch_port_ofport},"
             f"actions=NORMAL"),

            # Allow all other traffic
            "priority=0, actions=NORMAL",
        ]

        flows.extend(self._get_flows_for_host_ips())
        flows.extend(self._get_flows_for_icmpv6())

        try:
            self._apply_flows_as_bundle(flows)
        except Exception as e:
            LOG.error("Failed to configure BGP flows on bridge %s: %s: %s",
                      self.name, e, flows)


class BGPInterconnectBridge(Bridge):
    """Provider interconnect bridge (Neutron localnet <-> BGP localnet).

    The interconnect bridge has two patch ports to br-int, both created by
    OVN-controller for localnet LSPs:

    * **provider patch** — carries traffic for the Neutron provider network.
      Its OVS Port row contains ``neutron:provnet-physical-network`` in
      ``external_ids``.
    * **BGP patch** — carries traffic for the BGP interconnect network.
      Its OVS Port row does *not* contain that key.
    """

    def __init__(self, bgp_agent_api, name):
        super().__init__(bgp_agent_api, name)
        self._requirements = [
            ('provider patch port is not set', 'provider_patch_port'),
            ('BGP patch port is not set', 'bgp_patch_port'),
        ]
        self._provider_patch_port = None
        self._bgp_patch_port = None

    def __str__(self):
        return f'BGPInterconnectBridge(name={self.name})'

    __repr__ = __str__

    @staticmethod
    def _is_provider_port(port_external_ids):
        return ovn_const.OVN_PHYSNET_EXT_ID_KEY in port_external_ids

    def _get_port_external_ids(self, iface_row):
        ports = self.ovs_bridge.get_ports_attributes(
            'Port', columns=['interfaces', 'external_ids'])
        for port in ports:
            if iface_row.uuid in port['interfaces']:
                return port['external_ids']
        return {}

    def add_patch_port(self, iface_row):
        port_name = iface_row.name
        ext_ids = self._get_port_external_ids(iface_row)
        if self._is_provider_port(ext_ids):
            self._provider_patch_port = port_name
            LOG.info("Provider patch port %s set on %s", port_name, self.name)
        else:
            self._bgp_patch_port = port_name
            LOG.info("BGP patch port %s set on %s", port_name, self.name)

    def scan_existing_patch_ports(self):
        for iface in commands.GetPatchPortsFromBridgeCommand(
                self.ovs_idl, self.name).execute(check_error=True):
            self.add_patch_port(iface)
        if self.check_requirements_for_flows_met():
            self.configure_flows()

    def remove_patch_port(self, port_row):
        port_name = port_row.name
        if self._provider_patch_port == port_name:
            LOG.info("Provider patch port %s removed from %s",
                     port_name, self.name)
            self._provider_patch_port = None
        elif self._bgp_patch_port == port_name:
            LOG.info("BGP patch port %s removed from %s",
                     port_name, self.name)
            self._bgp_patch_port = None

    def has_patch_port(self, port_name):
        return port_name in (self._provider_patch_port, self._bgp_patch_port)

    @property
    def provider_patch_port(self):
        return self._provider_patch_port

    @property
    def provider_patch_ofport(self):
        return self.get_port_ofport(self._provider_patch_port)

    @property
    def bgp_patch_port(self):
        return self._bgp_patch_port

    @property
    def bgp_patch_ofport(self):
        return self.get_port_ofport(self._bgp_patch_port)

    def configure_flows(self):
        if not self.check_requirements_for_flows_met():
            LOG.error("Some of the requirements to install flows on "
                      "bridge %s are missing, skipping", self.name)
            return
        LOG.info("All requirements met for interconnect bridge %s, "
                 "flow configuration pending implementation", self.name)
