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

from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron._i18n import _
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants


DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_TUNNEL_TYPES = []

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use. "
                      "Do not change this parameter unless you have a good "
                      "reason to. This is the name of the OVS integration "
                      "bridge. There is one per hypervisor. The integration "
                      "bridge acts as a virtual 'patch bay'. All VM VIFs are "
                      "attached to this bridge and then 'patched' according "
                      "to their network connectivity.")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use.")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge.")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge.")),
    cfg.IPOpt('local_ip',
              help=_("IP address of local overlay (tunnel) network endpoint. "
                     "Use either an IPv4 or IPv6 address that resides on one "
                     "of the host network interfaces. The IP version of this "
                     "value must match the value of the 'overlay_ip_version' "
                     "option in the ML2 plug-in configuration file on the "
                     "neutron server node(s).")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("Comma-separated list of <physical_network>:<bridge> "
                       "tuples mapping physical network names to the agent's "
                       "node-specific Open vSwitch bridge names to be used "
                       "for flat and VLAN networks. The length of bridge "
                       "names should be no more than 11. Each bridge must "
                       "exist, and should have a physical network interface "
                       "configured as a port. All physical networks "
                       "configured on the server should have mappings to "
                       "appropriate bridges on each agent. "
                       "Note: If you remove a bridge from this "
                       "mapping, make sure to disconnect it from the "
                       "integration bridge as it won't be managed by the "
                       "agent anymore.")),
    cfg.BoolOpt('use_veth_interconnection', default=False,
                help=_("Use veths instead of patch ports to interconnect the "
                       "integration bridge to physical networks. "
                       "Support kernel without Open vSwitch patch port "
                       "support so long as it is set to True.")),
    cfg.StrOpt('of_interface', default='native',
               deprecated_for_removal=True,
               choices=['ovs-ofctl', 'native'],
               help=_("OpenFlow interface to use.")),
    cfg.StrOpt('datapath_type', default=constants.OVS_DATAPATH_SYSTEM,
               choices=[constants.OVS_DATAPATH_SYSTEM,
                        constants.OVS_DATAPATH_NETDEV],
               help=_("OVS datapath to use. 'system' is the default value and "
                      "corresponds to the kernel datapath. To enable the "
                      "userspace datapath set this value to 'netdev'.")),
    cfg.StrOpt('vhostuser_socket_dir', default=constants.VHOST_USER_SOCKET_DIR,
               help=_("OVS vhost-user socket directory.")),
    cfg.IPOpt('of_listen_address', default='127.0.0.1',
              help=_("Address to listen on for OpenFlow connections. "
                     "Used only for 'native' driver.")),
    cfg.PortOpt('of_listen_port', default=6633,
                help=_("Port to listen on for OpenFlow connections. "
                       "Used only for 'native' driver.")),
    cfg.IntOpt('of_connect_timeout', default=300,
               help=_("Timeout in seconds to wait for "
                      "the local switch connecting the controller. "
                      "Used only for 'native' driver.")),
    cfg.IntOpt('of_request_timeout', default=300,
               help=_("Timeout in seconds to wait for a single "
                      "OpenFlow request. "
                      "Used only for 'native' driver.")),
    cfg.IntOpt('of_inactivity_probe', default=10,
               help=_("The inactivity_probe interval in seconds for the local "
                      "switch connection to the controller. "
                      "A value of 0 disables inactivity probes. "
                      "Used only for 'native' driver.")),
]

agent_opts = [
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
    cfg.PortOpt('vxlan_udp_port', default=n_const.VXLAN_UDP_PORT,
                help=_("The UDP port to use for VXLAN tunnels.")),
    cfg.IntOpt('veth_mtu', default=9000,
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
    cfg.BoolOpt('dont_fragment', default=True,
                help=_("Set or un-set the don't fragment (DF) bit on "
                       "outgoing IP packet carrying GRE/VXLAN tunnel.")),
    cfg.BoolOpt('enable_distributed_routing', default=False,
                help=_("Make the l2 agent run in DVR mode.")),
    cfg.BoolOpt('drop_flows_on_start', default=False,
                help=_("Reset flow table on start. Setting this to True will "
                       "cause brief traffic interruption.")),
    cfg.BoolOpt('tunnel_csum', default=False,
                help=_("Set or un-set the tunnel header checksum  on "
                       "outgoing IP packet carrying GRE/VXLAN tunnel.")),
    cfg.StrOpt('agent_type', default=n_const.AGENT_TYPE_OVS,
               deprecated_for_removal=True,
               help=_("Selects the Agent Type reported"))
]


def register_ovs_agent_opts(cfg=cfg.CONF):
    cfg.register_opts(ovs_opts, "OVS")
    cfg.register_opts(agent_opts, "AGENT")
