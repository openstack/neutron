# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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

DEFAULT_VLAN_RANGES = []
DEFAULT_INTERFACE_MAPPINGS = []
DEFAULT_VXLAN_GROUP = '224.0.0.1'


vlan_opts = [
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("Network type for tenant networks "
                      "(local, vlan, or none)")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                       "or <physical_network>")),
]

vxlan_opts = [
    cfg.BoolOpt('enable_vxlan', default=True,
                help=_("Enable VXLAN on the agent. Can be enabled when "
                       "agent is managed by ml2 plugin using linuxbridge "
                       "mechanism driver")),
    cfg.IntOpt('ttl',
               help=_("TTL for vxlan interface protocol packets.")),
    cfg.IntOpt('tos',
               help=_("TOS for vxlan interface protocol packets.")),
    cfg.StrOpt('vxlan_group', default=DEFAULT_VXLAN_GROUP,
               help=_("Multicast group for vxlan interface.")),
    cfg.IPOpt('local_ip', version=4,
              help=_("Local IP address of the VXLAN endpoints.")),
    cfg.BoolOpt('l2_population', default=False,
                help=_("Extension to use alongside ml2 plugin's l2population "
                       "mechanism driver. It enables the plugin to populate "
                       "VXLAN forwarding table.")),
]

bridge_opts = [
    cfg.ListOpt('physical_interface_mappings',
                default=DEFAULT_INTERFACE_MAPPINGS,
                help=_("List of <physical_network>:<physical_interface>")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.BoolOpt('rpc_support_old_agents', default=False,
                help=_("Enable server RPC compatibility with old agents")),
    # TODO(kevinbenton): The following opt is duplicated between the OVS agent
    # and the Linuxbridge agent to make it easy to back-port. These shared opts
    # should be moved into a common agent config options location as part of
    # the deduplication work.
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
                       "headers."))
]


cfg.CONF.register_opts(vlan_opts, "VLANS")
cfg.CONF.register_opts(vxlan_opts, "VXLAN")
cfg.CONF.register_opts(bridge_opts, "LINUX_BRIDGE")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
