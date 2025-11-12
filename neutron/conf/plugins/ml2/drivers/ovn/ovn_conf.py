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
from oslo_config import types
from oslo_log import log as logging
from ovsdbapp.backend.ovs_idl import vlog

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.conf.agent import ovs_conf

LOG = logging.getLogger(__name__)

EXTRA_LOG_LEVEL_DEFAULTS = [
]

VLOG_LEVELS = {'CRITICAL': vlog.CRITICAL, 'ERROR': vlog.ERROR, 'WARNING':
               vlog.WARN, 'INFO': vlog.INFO, 'DEBUG': vlog.DEBUG}

OVN_NB_GLOBAL = "ovn_nb_global"

ovn_opts = [
    cfg.ListOpt('ovn_nb_connection',
                default=['tcp:127.0.0.1:6641'],
                item_type=types.String(regex=r'^(tcp|ssl|unix):.+'),
                help=_('The connection string for the OVN_Northbound OVSDB.\n'
                       'Use tcp:IP:PORT for TCP connection.\n'
                       'Use ssl:IP:PORT for SSL connection. The '
                       'ovn_nb_private_key, ovn_nb_certificate and '
                       'ovn_nb_ca_cert are mandatory.\n'
                       'Use unix:FILE for unix domain socket connection.\n'
                       'Multiple connections can be specified by a comma '
                       'separated string. See also: '
                       'https://github.com/openvswitch/ovs/blob'
                       '/ab4d3bfbef37c31331db5a9dbe7c22eb8d5e5e5f'
                       '/python/ovs/db/idl.py#L215-L216')),
    cfg.StrOpt('ovn_nb_private_key',
               default='',
               help=_('The PEM file with private key for SSL connection to '
                      'OVN-NB-DB')),
    cfg.StrOpt('ovn_nb_certificate',
               default='',
               help=_('The PEM file with certificate that certifies the '
                      'private key specified in ovn_nb_private_key')),
    cfg.StrOpt('ovn_nb_ca_cert',
               default='',
               help=_('The PEM file with CA certificate that OVN should use to'
                      ' verify certificates presented to it by SSL peers')),
    cfg.ListOpt('ovn_sb_connection',
                default=['tcp:127.0.0.1:6642'],
                item_type=types.String(regex=r'^(tcp|ssl|unix):.+'),
                help=_('The connection string for the OVN_Southbound OVSDB.\n'
                       'Use tcp:IP:PORT for TCP connection.\n'
                       'Use ssl:IP:PORT for SSL connection. The '
                       'ovn_sb_private_key, ovn_sb_certificate and '
                       'ovn_sb_ca_cert are mandatory.\n'
                       'Use unix:FILE for unix domain socket connection.\n'
                       'Multiple connections can be specified by a comma '
                       'separated string. See also: '
                       'https://github.com/openvswitch/ovs/blob'
                       '/ab4d3bfbef37c31331db5a9dbe7c22eb8d5e5e5f'
                       '/python/ovs/db/idl.py#L215-L216')),
    cfg.StrOpt('ovn_sb_private_key',
               default='',
               help=_('The PEM file with private key for SSL connection to '
                      'OVN-SB-DB')),
    cfg.StrOpt('ovn_sb_certificate',
               default='',
               help=_('The PEM file with certificate that certifies the '
                      'private key specified in ovn_sb_private_key')),
    cfg.StrOpt('ovn_sb_ca_cert',
               default='',
               help=_('The PEM file with CA certificate that OVN should use to'
                      ' verify certificates presented to it by SSL peers')),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=180,
               help=_('Timeout, in seconds, for the OVSDB '
                      'connection transaction')),
    cfg.IntOpt('ovsdb_retry_max_interval',
               default=180,
               help=_('Max interval, in seconds ,between '
                      'each retry to get the OVN NB and SB IDLs')),
    cfg.IntOpt('ovsdb_probe_interval',
               min=0,
               default=60000,
               help=_('The probe interval for the OVSDB session, in '
                      'milliseconds. If this is zero, it disables the '
                      'connection keepalive feature. If non-zero the value '
                      'will be forced to at least 1000 milliseconds. Defaults '
                      'to 60 seconds.')),
    cfg.StrOpt('neutron_sync_mode',
               default=ovn_const.OVN_DB_SYNC_MODE_LOG,
               choices=[(ovn_const.OVN_DB_SYNC_MODE_OFF,
                         "Synchronization is off."),
                        (ovn_const.OVN_DB_SYNC_MODE_LOG,
                         "During neutron-server startup, check to see if OVN "
                         "is in sync with the Neutron database. "
                         "Log warnings for any inconsistencies found so that "
                         "an admin can investigate."),
                        (ovn_const.OVN_DB_SYNC_MODE_REPAIR,
                         "During neutron-server startup, automatically create "
                         "resources found in Neutron but not in OVN. "
                         "Also remove resources from OVN that are no longer "
                         "found in Neutron."),
                        (ovn_const.OVN_DB_SYNC_MODE_MIGRATE,
                         "This mode is to OVS to OVN migration. "
                         "It will sync the DB just like repair mode but it "
                         "will additionally fix the Neutron DB resource from "
                         "OVS to OVN.")],
               help=_('The synchronization mode of OVN_Northbound OVSDB '
                      'with Neutron DB.')),
    cfg.StrOpt("ovn_l3_scheduler",
               default=ovn_const.OVN_L3_SCHEDULER_LEASTLOADED,
               choices=[(ovn_const.OVN_L3_SCHEDULER_LEASTLOADED,
                         "Select chassis with fewest gateway ports."),
                        (ovn_const.OVN_L3_SCHEDULER_CHANCE,
                         "Select chassis randomly.")],
               help=_('The OVN L3 Scheduler type used to schedule router '
                      'gateway ports on hypervisors/chassis.')),
    cfg.BoolOpt('enable_distributed_floating_ip',
                default=False,
                help=_('Enable distributed floating IP support.\n'
                       'If True, the NAT action for floating IPs will be done '
                       'locally and not in the centralized gateway. This '
                       'saves the path to the external network. This requires '
                       'the user to configure the physical network map '
                       '(i.e. ovn-bridge-mappings) on each compute node.')),
    cfg.StrOpt("vhost_sock_dir",
               default="/var/run/openvswitch",
               help=_("The directory in which vhost virtio sockets "
                      "are created by all the vswitch daemons")),
    cfg.IntOpt('dhcp_default_lease_time',
               default=(12 * 60 * 60),
               help=_('Default lease time (in seconds) to use with '
                      'OVN\'s native DHCP service.')),
    cfg.StrOpt("ovsdb_log_level",
               default="INFO",
               choices=list(VLOG_LEVELS.keys()),
               help=_("The log level used for OVSDB")),
    cfg.BoolOpt('ovn_metadata_enabled',
                default=False,
                help=_('Whether to use metadata service.')),
    cfg.ListOpt('dns_servers',
                default=[],
                help=_("Comma-separated list of the DNS servers which will be "
                       "used as forwarders if a subnet's dns_nameservers "
                       "field is empty. If both subnet's dns_nameservers and "
                       "this option are empty, then the DNS resolvers on the "
                       "host running the neutron server will be used.")),
    cfg.BoolOpt('dns_records_ovn_owned',
                default=False,
                help=_("Whether to consider DNS records local to OVN or not. "
                       "For OVN version 24.03 and above if this option is set "
                       "to True, DNS records will be treated local to the OVN "
                       "controller and it will respond to the queries for the "
                       "records and record types known to it, else it will "
                       "forward them to the configured DNS server(s).")),
    cfg.DictOpt('ovn_dhcp4_global_options',
                default={},
                help=_("Dictionary of global DHCPv4 options which will be "
                       "automatically set on each subnet upon creation and "
                       "on all existing subnets when Neutron starts.\n"
                       "An empty value for a DHCP option will cause that "
                       "option to be unset globally. Multiple values should "
                       "be separated by semi-colon.\n"
                       "EXAMPLES:\n"
                       "- ntp_server:1.2.3.4,wpad:1.2.3.5;1.2.3.6 - Set "
                       "ntp_server and wpad\n"
                       "- ntp_server:,wpad:1.2.3.5 - Unset ntp_server and "
                       "set wpad\n"
                       "See the ovn-nb(5) man page for available options.")),
    cfg.DictOpt('ovn_dhcp6_global_options',
                default={},
                help=_("Dictionary of global DHCPv6 options which will be "
                       "automatically set on each subnet upon creation and "
                       "on all existing subnets when Neutron starts.\n"
                       "An empty value for a DHCPv6 option will cause that "
                       "option to be unset globally. Multiple values should "
                       "be separated by semi-colon.\n"
                       "See the ovn-nb(5) man page for available options.")),
    cfg.BoolOpt('disable_ovn_dhcp_for_baremetal_ports',
                default=False,
                help=_('Disable OVN\'s built-in DHCP for baremetal ports '
                       '(VNIC type "baremetal"). This allows operators to '
                       'plug their own DHCP server of choice for PXE booting '
                       'baremetal nodes. OVN 23.06.0 and newer also supports '
                       'baremetal ``PXE`` based provisioning over IPv6. '
                       'If an older version of OVN is used for baremetal '
                       'provisioning over IPv6 this option should be set '
                       'to "True" and neutron-dhcp-agent should be used '
                       'instead. Defaults to "False".')),
    cfg.BoolOpt('localnet_learn_fdb',
                default=False,
                help=_('If enabled it will allow localnet ports to learn MAC '
                       'addresses and store them in FDB SB table. This avoids '
                       'flooding for traffic towards unknown IPs when port '
                       'security is disabled. It requires OVN 22.09 or '
                       'newer.')),
    cfg.IntOpt('fdb_age_threshold',
               min=0,
               default=0,
               help=_('The number of seconds to keep FDB entries in the OVN '
                      'DB. The value defaults to 0, which means disabled. '
                      'This is supported by OVN >= 23.09.')),
    cfg.IntOpt('mac_binding_age_threshold',
               min=0,
               default=0,
               help=_('The number of seconds to keep MAC_Binding entries in '
                      'the OVN DB. 0 to disable aging.')),
    cfg.BoolOpt('broadcast_arps_to_all_routers',
                default=True,
                help=_('If enabled (default) OVN will flood ARP requests to '
                       'all attached ports on a network. If set to False, '
                       'ARP requests are only sent to routers on that network '
                       'if the target MAC address matches. ARP requests that '
                       'do not match a router will only be forwarded to '
                       'non-router ports. Supported by OVN >= 23.06.')),
    cfg.BoolOpt('ovn_router_indirect_snat',
                default=False,
                help=_('Whether to configure SNAT for all nested subnets '
                       'connected to the router through any other routers, '
                       'similar to the default ML2/OVS behavior. Defaults to '
                       '"False".')),
    cfg.StrOpt('live_migration_activation_strategy',
               default="rarp",
               choices=[("rarp",
                         "Expect the hypervisor to send a Reverse ARP request "
                         "through the migrated port after migration is "
                         "complete."),
                        ("",
                         "A migrated port is immediately activated on "
                         "the destination host.")],
               help=_('Activation strategy to use for live migration.')),
    cfg.BoolOpt('stateless_nat_enabled',
                default=False,
                help=_('If enabled, the floating IP NAT rules will be '
                       'stateless, instead of using the conntrack OVN '
                       'actions. This strategy is faster in some '
                       'environments, like for example DPDK deployments.')),
]

nb_global_opts = [
    cfg.BoolOpt('ignore_lsp_down',
                default=False,
                help=_('If set to False, ARP/ND reply flows for logical '
                       'switch ports will be installed only if the port is '
                       'UP, i.e. claimed by a Chassis. If set to True, these '
                       'flows are installed regardless of the status of the '
                       'port, which can result in a situation that an ARP '
                       'request to an IP is resolved even before the relevant '
                       'VM/container is running. For environments where this '
                       'is not an issue, setting it to True can reduce '
                       'the load and latency of the control plane. '
                       'The default value is False.')),
    cfg.IntOpt('fdb_removal_limit',
               min=0,
               default=0,
               help=_('FDB aging bulk removal limit. This limits how many '
                      'rows can expire in a single transaction. Default '
                      'is 0, which is unlimited. When the limit is reached, '
                      'the next batch removal is delayed by 5 seconds. '
                      'This is supported by OVN >= 23.09.')),
    cfg.IntOpt('mac_binding_removal_limit',
               min=0,
               default=0,
               help=_('MAC binding aging bulk removal limit. This limits how '
                      'many entries can expire in a single transaction. '
                      'The default is 0 which is unlimited. When the limit '
                      'is reached, the next batch removal is delayed by '
                      '5 seconds.')),
]


def register_opts():
    cfg.CONF.register_opts(ovn_opts, group='ovn')
    ovs_conf.register_ovs_agent_opts()
    cfg.CONF.register_opts(nb_global_opts, group=OVN_NB_GLOBAL)


def list_opts():
    return [
        ('ovn', ovn_opts),
        ('ovs', ovs_conf.OPTS),
        (OVN_NB_GLOBAL, nb_global_opts),
    ]


def get_ovn_nb_connection():
    return ','.join(cfg.CONF.ovn.ovn_nb_connection)


def get_ovn_nb_private_key():
    return cfg.CONF.ovn.ovn_nb_private_key


def get_ovn_nb_certificate():
    return cfg.CONF.ovn.ovn_nb_certificate


def get_ovn_nb_ca_cert():
    return cfg.CONF.ovn.ovn_nb_ca_cert


def get_ovn_sb_connection():
    return ','.join(cfg.CONF.ovn.ovn_sb_connection)


def get_ovn_sb_private_key():
    return cfg.CONF.ovn.ovn_sb_private_key


def get_ovn_sb_certificate():
    return cfg.CONF.ovn.ovn_sb_certificate


def get_ovn_sb_ca_cert():
    return cfg.CONF.ovn.ovn_sb_ca_cert


def get_ovn_ovsdb_timeout():
    return cfg.CONF.ovn.ovsdb_connection_timeout


def get_ovn_ovsdb_retry_max_interval():
    return cfg.CONF.ovn.ovsdb_retry_max_interval


def get_ovn_ovsdb_probe_interval():
    return cfg.CONF.ovn.ovsdb_probe_interval


def get_ovn_neutron_sync_mode():
    return cfg.CONF.ovn.neutron_sync_mode


def get_ovn_l3_scheduler():
    return cfg.CONF.ovn.ovn_l3_scheduler


def is_ovn_distributed_floating_ip():
    return cfg.CONF.ovn.enable_distributed_floating_ip


def get_ovn_lm_activation_strategy():
    return cfg.CONF.ovn.live_migration_activation_strategy


def get_ovn_vhost_sock_dir():
    return cfg.CONF.ovn.vhost_sock_dir


def get_ovn_dhcp_default_lease_time():
    return cfg.CONF.ovn.dhcp_default_lease_time


def get_ovn_ovsdb_log_level():
    return VLOG_LEVELS[cfg.CONF.ovn.ovsdb_log_level]


def is_ovn_metadata_enabled():
    return cfg.CONF.ovn.ovn_metadata_enabled


def get_dns_servers():
    return cfg.CONF.ovn.dns_servers


def is_dns_records_ovn_owned():
    return cfg.CONF.ovn.dns_records_ovn_owned


def get_global_dhcpv4_opts():
    return cfg.CONF.ovn.ovn_dhcp4_global_options


def get_global_dhcpv6_opts():
    return cfg.CONF.ovn.ovn_dhcp6_global_options


def is_ovn_dhcp_disabled_for_baremetal():
    return cfg.CONF.ovn.disable_ovn_dhcp_for_baremetal_ports


def is_learn_fdb_enabled():
    return cfg.CONF.ovn.localnet_learn_fdb


def get_fdb_age_threshold():
    return str(cfg.CONF.ovn.fdb_age_threshold)


def get_fdb_removal_limit():
    return str(cfg.CONF.ovn_nb_global.fdb_removal_limit)


def get_ovn_mac_binding_age_threshold():
    # This value is always stored as a string in the OVN DB
    return str(cfg.CONF.ovn.mac_binding_age_threshold)


def get_ovn_mac_binding_removal_limit():
    return str(cfg.CONF.ovn_nb_global.mac_binding_removal_limit)


def is_broadcast_arps_to_all_routers_enabled():
    return cfg.CONF.ovn.broadcast_arps_to_all_routers


def is_ovn_router_indirect_snat_enabled():
    return cfg.CONF.ovn.ovn_router_indirect_snat


def is_stateless_nat_enabled():
    return cfg.CONF.ovn.stateless_nat_enabled
