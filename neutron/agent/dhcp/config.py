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

DHCP_AGENT_OPTS = [
    cfg.IntOpt('resync_interval', default=5,
               help=_("Interval to resync.")),
    cfg.StrOpt('dhcp_driver',
               default='neutron.agent.linux.dhcp.Dnsmasq',
               help=_("The driver used to manage the DHCP server.")),
    cfg.BoolOpt('enable_isolated_metadata', default=False,
                help=_("Support Metadata requests on isolated networks.")),
    cfg.BoolOpt('enable_metadata_network', default=False,
                help=_("Allows for serving metadata requests from a "
                       "dedicated network. Requires "
                       "enable_isolated_metadata = True")),
    cfg.IntOpt('num_sync_threads', default=4,
               help=_('Number of threads to use during sync process.'))
]

DHCP_OPTS = [
    cfg.StrOpt('dhcp_confs',
               default='$state_path/dhcp',
               help=_('Location to store DHCP server config files')),
    cfg.StrOpt('dhcp_domain',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
]

DNSMASQ_OPTS = [
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help=_('Override the default dnsmasq settings with this file')),
    cfg.ListOpt('dnsmasq_dns_servers',
                help=_('Comma-separated list of the DNS servers which will be '
                       'used as forwarders.'),
                deprecated_name='dnsmasq_dns_server'),
    cfg.BoolOpt('dhcp_delete_namespaces', default=False,
                help=_("Delete namespace after removing a dhcp server.")),
    cfg.IntOpt(
        'dnsmasq_lease_max',
        default=(2 ** 24),
        help=_('Limit number of leases to prevent a denial-of-service.')),
    cfg.BoolOpt('dhcp_broadcast_reply', default=False,
                help=_("Use broadcast in DHCP replies")),
]
