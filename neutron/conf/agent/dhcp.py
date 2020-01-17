# Copyright 2015 OpenStack Foundation
#
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


from oslo_config import cfg

from neutron._i18n import _


DHCP_AGENT_OPTS = [
    cfg.IntOpt('resync_interval', default=5,
               help=_("The DHCP agent will resync its state with Neutron to "
                      "recover from any transient notification or RPC errors. "
                      "The interval is maximum number of seconds between "
                      "attempts. The resync can be done more often based on "
                      "the events triggered.")),
    cfg.IntOpt('resync_throttle', default=1,
               help=_("Throttle the number of resync state events between the "
                      "local DHCP state and Neutron to only once per "
                      "'resync_throttle' seconds. The value of throttle "
                      "introduces a minimum interval between resync state "
                      "events. Otherwise the resync may end up in a "
                      "busy-loop. The value must be less than "
                      "resync_interval.")),
    cfg.StrOpt('dhcp_driver',
               default='neutron.agent.linux.dhcp.Dnsmasq',
               help=_("The driver used to manage the DHCP server.")),
    cfg.BoolOpt('enable_isolated_metadata', default=False,
                help=_("The DHCP server can assist with providing metadata "
                       "support on isolated networks. Setting this value to "
                       "True will cause the DHCP server to append specific "
                       "host routes to the DHCP request. The metadata service "
                       "will only be activated when the subnet does not "
                       "contain any router port. The guest instance must be "
                       "configured to request host routes via DHCP (Option "
                       "121). This option doesn't have any effect when "
                       "force_metadata is set to True.")),
    cfg.BoolOpt('force_metadata', default=False,
                help=_("In some cases the Neutron router is not present to "
                       "provide the metadata IP but the DHCP server can be "
                       "used to provide this info. Setting this value will "
                       "force the DHCP server to append specific host routes "
                       "to the DHCP request. If this option is set, then the "
                       "metadata service will be activated for all the "
                       "networks.")),
    cfg.BoolOpt('enable_metadata_network', default=False,
                help=_("Allows for serving metadata requests coming from a "
                       "dedicated metadata access network whose CIDR is "
                       "169.254.169.254/16 (or larger prefix), and is "
                       "connected to a Neutron router from which the VMs send "
                       "metadata:1 request. In this case DHCP Option 121 will "
                       "not be injected in VMs, as they will be able to reach "
                       "169.254.169.254 through a router. This option "
                       "requires enable_isolated_metadata = True.")),
    cfg.IntOpt('num_sync_threads', default=4,
               help=_('Number of threads to use during sync process. '
                      'Should not exceed connection pool size configured on '
                      'server.')),
    cfg.IntOpt('bulk_reload_interval', default=0, min=0,
               help=_('Time to sleep between reloading the DHCP allocations. '
                      'This will only be invoked if the value is not 0. '
                      'If a network has N updates in X seconds then '
                      'we will reload once with the port changes in the X '
                      'seconds and not N times.')),
]

DHCP_OPTS = [
    cfg.StrOpt('dhcp_confs',
               default='$state_path/dhcp',
               help=_('Location to store DHCP server config files.')),
]

DNSMASQ_OPTS = [
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help=_('Override the default dnsmasq settings '
                      'with this file.')),
    cfg.ListOpt('dnsmasq_dns_servers',
                default=[],
                help=_('Comma-separated list of the DNS servers which will be '
                       'used as forwarders.')),
    cfg.StrOpt('dnsmasq_base_log_dir',
               help=_("Base log dir for dnsmasq logging. "
                      "The log contains DHCP and DNS log information and "
                      "is useful for debugging issues with either DHCP or "
                      "DNS. If this section is null, disable dnsmasq log.")),
    cfg.BoolOpt('dnsmasq_local_resolv', default=False,
                help=_("Enables the dnsmasq service to provide name "
                       "resolution for instances via DNS resolvers on the "
                       "host running the DHCP agent. Effectively removes the "
                       "'--no-resolv' option from the dnsmasq process "
                       "arguments. Adding custom DNS resolvers to the "
                       "'dnsmasq_dns_servers' option disables this feature.")),
    cfg.IntOpt(
        'dnsmasq_lease_max',
        default=(2 ** 24),
        help=_('Limit number of leases to prevent a denial-of-service.')),
    cfg.BoolOpt('dhcp_broadcast_reply', default=False,
                help=_("Use broadcast in DHCP replies.")),
    cfg.IntOpt('dhcp_renewal_time', default=0,
               help=_("DHCP renewal time T1 (in seconds). If set to 0, it "
                      "will default to half of the lease time.")),
    cfg.IntOpt('dhcp_rebinding_time', default=0,
               help=_("DHCP rebinding time T2 (in seconds). If set to 0, it "
                      "will default to 7/8 of the lease time.")),
    cfg.BoolOpt('dnsmasq_enable_addr6_list', default=False,
                help=_("Enable dhcp-host entry with list of addresses when "
                       "port has multiple IPv6 addresses in the same subnet."))
]


def register_agent_dhcp_opts(cfg=cfg.CONF):
    cfg.register_opts(DHCP_AGENT_OPTS)
    cfg.register_opts(DHCP_OPTS)
    cfg.register_opts(DNSMASQ_OPTS)
