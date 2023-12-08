# Copyright 2011 VMware, Inc.
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

from neutron_lib import constants
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_service import wsgi
from oslo_utils import netutils

from neutron._i18n import _


core_opts = [
    cfg.HostAddressOpt('bind_host', default='0.0.0.0',
                       help=_("The host IP to bind to.")),
    cfg.PortOpt('bind_port', default=9696,
                help=_("The port to bind to")),
    cfg.StrOpt('api_extensions_path', default="",
               help=_("The path for API extensions. "
                      "Note that this can be a colon-separated list of paths. "
                      "For example: api_extensions_path = "
                      "extensions:/path/to/more/exts:/even/more/exts. "
                      "The __path__ of neutron.extensions is appended to "
                      "this, so if your extensions are in there you do not "
                      "need to specify them here.")),
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.StrOpt('core_plugin',
               help=_("The core plugin Neutron will use")),
    cfg.ListOpt('service_plugins', default=[],
                help=_("The service plugins Neutron will use")),
    cfg.StrOpt('base_mac', default="fa:16:3e:00:00:00",
               help=_("The base MAC address Neutron will use for VIFs. "
                      "The first 3 octets will remain unchanged. If the 4th "
                      "octet is not 00, it will also be used. The others "
                      "will be randomly generated.")),
    cfg.BoolOpt('allow_bulk', default=True,
                help=_("Allow the usage of the bulk API")),
    cfg.StrOpt('pagination_max_limit', default="-1",
               help=_("The maximum number of items returned in a single "
                      "response, value of 'infinite' or negative integer "
                      "means no limit")),
    cfg.ListOpt('default_availability_zones', default=[],
                help=_("Default value of availability zone hints. The "
                       "availability zone aware schedulers use this when "
                       "the resources availability_zone_hints is empty. "
                       "Multiple availability zones can be specified by a "
                       "comma separated string. This value can be empty. "
                       "In this case, even if availability_zone_hints for "
                       "a resource is empty, availability zone is "
                       "considered for high availability while scheduling "
                       "the resource.")),
    cfg.IntOpt('max_dns_nameservers', default=5,
               help=_("Maximum number of DNS nameservers per subnet")),
    cfg.IntOpt('max_subnet_host_routes', default=20,
               help=_("Maximum number of host routes per subnet")),
    cfg.BoolOpt('ipv6_pd_enabled', default=False,
                help=_("Warning: This feature is experimental with low test "
                       "coverage, and the Dibbler client which is used for "
                       "this feature is no longer maintained! "
                       "Enables IPv6 Prefix Delegation for automatic subnet "
                       "CIDR allocation. "
                       "Set to True to enable IPv6 Prefix Delegation for "
                       "subnet allocation in a PD-capable environment. Users "
                       "making subnet creation requests for IPv6 subnets "
                       "without providing a CIDR or subnetpool ID will be "
                       "given a CIDR via the Prefix Delegation mechanism. "
                       "Note that enabling PD will override the behavior of "
                       "the default IPv6 subnetpool."),
                deprecated_for_removal=True,
                deprecated_since='2023.2',
                deprecated_reason=("The Dibbler client used for this feature "
                                   "is no longer maintained. See LP#1916428"),
                ),
    cfg.IntOpt('dhcp_lease_duration', default=86400,
               help=_("DHCP lease duration (in seconds). Use -1 to tell "
                      "dnsmasq to use infinite lease times.")),
    cfg.StrOpt('dns_domain',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
    cfg.StrOpt('external_dns_driver',
               help=_('Driver for external DNS integration.')),
    cfg.BoolOpt('dhcp_agent_notification', default=True,
                help=_("Allow sending resource operation"
                       " notification to DHCP agent")),
    cfg.HostAddressOpt('host', default=net.get_hostname(),
                       sample_default='example.domain',
                       help=_("Hostname to be used by the Neutron server, "
                              "agents and services running on this machine. "
                              "All the agents and services running on this "
                              "machine must use the same host value.")),
    cfg.StrOpt("network_link_prefix",
               help=_("This string is prepended to the normal URL that is "
                      "returned in links to the OpenStack Network API. If it "
                      "is empty (the default), the URLs are returned "
                      "unchanged.")),
    cfg.BoolOpt('notify_nova_on_port_status_changes', default=True,
                help=_("Send notification to Nova when port status changes")),
    cfg.BoolOpt('notify_nova_on_port_data_changes', default=True,
                help=_("Send notification to Nova when port data (fixed_ips/"
                       "floatingip) changes so Nova can update its cache.")),
    cfg.IntOpt('send_events_interval', default=2,
               help=_('Number of seconds between sending events to Nova if '
                      'there are any events to send.')),
    cfg.StrOpt('setproctitle', default='on',
               help=_("Set process name to match child worker role. "
                      "Available options are: 'off' - retains the previous "
                      "behavior; 'on' - renames processes to "
                      "'neutron-server: role (original string)'; "
                      "'brief' - renames the same as 'on', but without the "
                      "original string, such as 'neutron-server: role'.")),
    cfg.StrOpt('ipam_driver', default='internal',
               help=_("Neutron IPAM (IP address management) driver to use. "
                      "By default, the reference implementation of the "
                      "Neutron IPAM driver is used.")),
    cfg.BoolOpt('vlan_transparent', default=False,
                help=_('If True, then allow plugins that support it to '
                       'create VLAN transparent networks.')),
    cfg.BoolOpt('filter_validation', default=True,
                help=_('If True, then allow plugins to decide '
                       'whether to perform validations on filter parameters. '
                       'Filter validation is enabled if this config '
                       'is turned on and it is supported by all plugins')),
    cfg.IntOpt('global_physnet_mtu', default=constants.DEFAULT_NETWORK_MTU,
               help=_('MTU of the underlying physical network. Neutron uses '
                      'this value to calculate MTU for all virtual network '
                      'components. For flat and VLAN networks, neutron uses '
                      'this value without modification. For overlay networks '
                      'such as VXLAN, neutron automatically subtracts the '
                      'overlay protocol overhead from this value. Defaults '
                      'to 1500, the standard value for Ethernet.')),
    cfg.IntOpt('http_retries', default=3, min=0,
               help=_("Number of times client connections (Nova, Ironic) "
                      "should be retried on a failed HTTP call. 0 (zero) "
                      "means connection is attempted only once (not retried). "
                      "Setting to any positive integer means that on failure "
                      "the connection is retried that many times. "
                      "For example, setting to 3 means total attempts to "
                      "connect will be 4.")),
    cfg.BoolOpt('enable_traditional_dhcp', default=True,
                help=_('If False, neutron-server will disable the following '
                       'DHCP-agent related functions: '
                       '1. DHCP provisioning block '
                       '2. DHCP scheduler API extension '
                       '3. Network scheduling mechanism '
                       '4. DHCP RPC/notification')),
    cfg.StrOpt('my_ip', default=netutils.get_my_ipv4(),
               help=_('IPv4 address of this host. If no address is provided '
                      'and one cannot be determined, 127.0.0.1 will be '
                      'used.')),
    cfg.StrOpt('my_ipv6', default=netutils.get_my_ipv6(),
               help=_('IPv6 address of this host. If no address is provided '
                      'and one cannot be determined, ::1 will be '
                      'used.')),
    cfg.BoolOpt('enable_signals', default=True,
                help=_('If False, neutron-server will not listen for signals '
                       'like SIGINT or SIGTERM. This is useful when running '
                       'behind a WSGI server like apache/mod_wsgi.')),
]

core_cli_opts = [
    cfg.StrOpt('state_path',
               default='/var/lib/neutron',
               help=_("Where to store Neutron state files. "
                      "This directory must be writable by the agent.")),
]


def register_core_common_config_opts(cfg=cfg.CONF):
    cfg.register_opts(core_opts)
    cfg.register_cli_opts(core_cli_opts)
    wsgi.register_opts(cfg)


NOVA_CONF_SECTION = 'nova'

nova_opts = [
    cfg.StrOpt('region_name',
               help=_('Name of Nova region to use. Useful if Keystone manages'
                      ' more than one region.')),
    cfg.StrOpt('endpoint_type',
               default='public',
               choices=['public', 'admin', 'internal'],
               help=_('Type of the Nova endpoint to use.  This endpoint will'
                      ' be looked up in the Keystone catalog and should be'
                      ' one of public, internal or admin.')),
]


def register_nova_opts(cfg=cfg.CONF):
    cfg.register_opts(nova_opts, group=NOVA_CONF_SECTION)


PLACEMENT_CONF_SECTION = 'placement'

placement_opts = [
    cfg.StrOpt('region_name',
               help=_('Name of placement region to use. Useful if Keystone '
                      'manages more than one region.')),
    cfg.StrOpt('endpoint_type',
               default='public',
               choices=['public', 'admin', 'internal'],
               help=_('Type of the placement endpoint to use.  This endpoint '
                      'will be looked up in the Keystone catalog and should '
                      'be one of public, internal or admin.')),
]


def register_placement_opts(cfg=cfg.CONF):
    cfg.register_opts(placement_opts, group=PLACEMENT_CONF_SECTION)


IRONIC_CONF_SECTION = 'ironic'

ironic_opts = [
    cfg.BoolOpt('enable_notifications', default=False,
                help=_("Send notification events to Ironic. (For example on "
                       "relevant port status changes.)")),
]


def register_ironic_opts(cfg=cfg.CONF):
    cfg.register_opts(ironic_opts, group=IRONIC_CONF_SECTION)


CLI_SCRIPT_SECTION = 'cli_script'

cli_script_options = [
    cfg.BoolOpt('dry_run', default=False,
                help=_('Dry-run execution of the CLI script. No change will '
                       'be performed on the system.')),
]


def register_cli_script_opts(cfg=cfg.CONF):
    cfg.register_opts(cli_script_options, group=CLI_SCRIPT_SECTION)
