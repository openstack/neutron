# Copyright 2012 Red Hat, Inc.
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

from oslo_config import cfg

from neutron.agent.common import config
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import constants


DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use.")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use.")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge.")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge.")),
    cfg.IPOpt('local_ip', version=4,
              help=_("Local IP address of tunnel endpoint.")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("List of <physical_network>:<bridge>. "
                       "Deprecated for ofagent.")),
    cfg.BoolOpt('use_veth_interconnection', default=False,
                help=_("Use veths instead of patch ports to interconnect the "
                       "integration bridge to physical bridges.")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.BoolOpt('minimize_polling',
                default=True,
                help=_("Minimize polling by monitoring ovsdb for interface "
                       "changes.")),
    cfg.IntOpt('ovsdb_monitor_respawn_interval',
               default=constants.DEFAULT_OVSDBMON_RESPAWN,
               help=_("The number of seconds to wait before respawning the "
                      "ovsdb monitor after losing communication with it.")),
    cfg.ListOpt('tunnel_types', default=DEFAULT_TUNNEL_TYPES,
                help=_("Network types supported by the agent "
                       "(gre and/or vxlan).")),
    cfg.IntOpt('vxlan_udp_port', default=p_const.VXLAN_UDP_PORT,
               help=_("The UDP port to use for VXLAN tunnels.")),
    cfg.IntOpt('veth_mtu',
               help=_("MTU size of veth interfaces")),
    cfg.BoolOpt('l2_population', default=False,
                help=_("Use ML2 l2population mechanism driver to learn "
                       "remote MAC and IPs and improve tunnel scalability.")),
    cfg.BoolOpt('arp_responder', default=False,
                help=_("Enable local ARP responder if it is supported. "
                       "Requires OVS 2.1 and ML2 l2population driver. "
                       "Allows the switch (when supporting an overlay) "
                       "to respond to an ARP request locally without "
                       "performing a costly ARP broadcast into the overlay.")),
    cfg.BoolOpt('prevent_arp_spoofing', default=False,
                help=_("Enable suppression of ARP responses that don't match "
                       "an IP address that belongs to the port from which "
                       "they originate. Note: This prevents the VMs attached "
                       "to this agent from spoofing, it doesn't protect them "
                       "from other devices which have the capability to spoof "
                       "(e.g. bare metal or VMs attached to agents without "
                       "this flag set to True). Spoofing rules will not be "
                       "added to any ports that have port security disabled. "
                       "For LinuxBridge, this requires ebtables. For OVS, it "
                       "requires a version that supports matching ARP "
                       "headers.")),
    cfg.BoolOpt('dont_fragment', default=True,
                help=_("Set or un-set the don't fragment (DF) bit on "
                       "outgoing IP packet carrying GRE/VXLAN tunnel.")),
    cfg.BoolOpt('enable_distributed_routing', default=False,
                help=_("Make the l2 agent run in DVR mode.")),
    cfg.IntOpt('quitting_rpc_timeout', default=10,
               help=_("Set new timeout in seconds for new rpc calls after "
                      "agent receives SIGTERM. If value is set to 0, rpc "
                      "timeout won't be changed"))
]


cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
