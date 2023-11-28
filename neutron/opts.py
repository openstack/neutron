#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy
import itertools
import operator

from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

import neutron.agent.agent_extensions_manager
import neutron.agent.securitygroups_rpc
import neutron.conf.agent.agent_extensions_manager
import neutron.conf.agent.common
import neutron.conf.agent.database.agents_db
import neutron.conf.agent.database.agentschedulers_db
import neutron.conf.agent.dhcp
import neutron.conf.agent.l3.config
import neutron.conf.agent.l3.ha
import neutron.conf.agent.linux
import neutron.conf.agent.metadata.config as meta_conf
import neutron.conf.agent.ovs_conf
import neutron.conf.agent.ovsdb_api
import neutron.conf.common
import neutron.conf.db.dvr_mac_db
import neutron.conf.db.extraroute_db
import neutron.conf.db.l3_agentschedulers_db
import neutron.conf.db.l3_dvr_db
import neutron.conf.db.l3_extra_gws_db
import neutron.conf.db.l3_gwmode_db
import neutron.conf.db.l3_hamode_db
import neutron.conf.experimental
import neutron.conf.extensions.allowedaddresspairs
import neutron.conf.extensions.conntrack_helper
import neutron.conf.plugins.ml2.config
import neutron.conf.plugins.ml2.drivers.agent
import neutron.conf.plugins.ml2.drivers.driver_type
import neutron.conf.plugins.ml2.drivers.linuxbridge
import neutron.conf.plugins.ml2.drivers.macvtap
import neutron.conf.plugins.ml2.drivers.mech_sriov.agent_common
import neutron.conf.plugins.ml2.drivers.mech_sriov.mech_sriov_conf
import neutron.conf.plugins.ml2.drivers.openvswitch.mech_ovs_conf
import neutron.conf.plugins.ml2.drivers.ovs_conf
import neutron.conf.quota
import neutron.conf.service
import neutron.conf.services.extdns_designate_driver
import neutron.conf.services.logging
import neutron.conf.services.metering_agent
import neutron.conf.wsgi
import neutron.db.migration.cli
import neutron.extensions.l3
import neutron.extensions.securitygroup
import neutron.plugins.ml2.drivers.mech_sriov.agent.common.config
import neutron.wsgi


AUTH_GROUPS_OPTS = {
    'nova': {
        'deprecations': {
            'nova.cafile': [
                cfg.DeprecatedOpt('ca_certificates_file', group='nova')
            ],
            'nova.insecure': [
                cfg.DeprecatedOpt('api_insecure', group='nova')
            ],
            'nova.timeout': [
                cfg.DeprecatedOpt('url_timeout', group='nova')
            ]
        }
    },
    'ironic': {},
    'placement': {},
    'designate': {}
}

CONF = cfg.CONF


def list_auth_opts(group):
    group_conf = AUTH_GROUPS_OPTS.get(group)
    kwargs = {'conf': CONF, 'group': group}
    deprecations = group_conf.get('deprecations')
    if deprecations:
        kwargs['deprecated_opts'] = deprecations
    opts = ks_loading.register_session_conf_options(
        **kwargs
    )
    opt_list = copy.deepcopy(opts)
    opt_list.insert(0, ks_loading.get_auth_common_conf_options()[0])
    # NOTE(mhickey): There are a lot of auth plugins, we just generate
    # the config options for a few common ones
    plugins = ['password', 'v2password', 'v3password']
    for name in plugins:
        for plugin_option in ks_loading.get_auth_plugin_conf_options(name):
            if all(option.name != plugin_option.name for option in opt_list):
                opt_list.append(plugin_option)
    opt_list.sort(key=operator.attrgetter('name'))
    return [(group, opt_list)]


def list_ironic_auth_opts():
    return list_auth_opts('ironic')


def list_nova_auth_opts():
    return list_auth_opts('nova')


def list_placement_auth_opts():
    return list_auth_opts('placement')


def list_designate_auth_opts():
    return list_auth_opts('designate')


def list_agent_opts():
    return [
        ('agent',
         itertools.chain(
             neutron.conf.agent.common.ROOT_HELPER_OPTS,
             neutron.conf.agent.common.AGENT_STATE_OPTS,
             neutron.conf.agent.common.IPTABLES_OPTS,
             neutron.conf.agent.common.PROCESS_MONITOR_OPTS,
             neutron.conf.agent.common.AVAILABILITY_ZONE_OPTS)
         ),
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.common.INTERFACE_DRIVER_OPTS,
             neutron.conf.agent.metadata.config.SHARED_OPTS)
         )
    ]


def list_extension_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.extensions.allowedaddresspairs
             .allowed_address_pair_opts,
             neutron.conf.extensions.conntrack_helper.conntrack_helper_opts)
         ),
        ('quotas',
         itertools.chain(
             neutron.conf.quota.l3_quota_opts,
             neutron.conf.quota.security_group_quota_opts)
         )
    ]


def list_db_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.database.agents_db.AGENT_OPTS,
             neutron.conf.db.extraroute_db.EXTRA_ROUTE_OPTS,
             neutron.conf.db.l3_gwmode_db.L3GWMODE_OPTS,
             neutron.conf.agent.database.agentschedulers_db
             .AGENTS_SCHEDULER_OPTS,
             neutron.conf.db.dvr_mac_db.DVR_MAC_ADDRESS_OPTS,
             neutron.conf.db.l3_dvr_db.ROUTER_DISTRIBUTED_OPTS,
             neutron.conf.db.l3_agentschedulers_db.L3_AGENTS_SCHEDULER_OPTS,
             neutron.conf.db.l3_hamode_db.L3_HA_OPTS,
             neutron.conf.db.l3_extra_gws_db.L3_EXTRA_GWS_OPTS)
         ),
        ('database',
         neutron.db.migration.cli.get_engine_config())
    ]


def list_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.common.core_cli_opts,
             neutron.conf.common.core_opts,
             neutron.conf.wsgi.socket_opts,
             neutron.conf.service.SERVICE_OPTS,
             neutron.conf.service.RPC_EXTRA_OPTS)
         ),
        (neutron.conf.common.NOVA_CONF_SECTION,
         itertools.chain(
             neutron.conf.common.nova_opts)
         ),
        (neutron.conf.common.IRONIC_CONF_SECTION,
         itertools.chain(
             neutron.conf.common.ironic_opts)
         ),
        (neutron.conf.common.PLACEMENT_CONF_SECTION,
         itertools.chain(
             neutron.conf.common.placement_opts)
         ),
        ('designate',
         neutron.conf.services.extdns_designate_driver.designate_opts
         ),
        ('quotas', neutron.conf.quota.core_quota_opts)
    ]


def list_base_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.common.INTERFACE_OPTS,
             neutron.conf.agent.common.INTERFACE_DRIVER_OPTS,
             neutron.conf.service.RPC_EXTRA_OPTS)
         ),
        ('agent', neutron.conf.agent.common.AGENT_STATE_OPTS),
        ('ovs',
         itertools.chain(
             neutron.conf.agent.ovsdb_api.API_OPTS,
             neutron.conf.agent.ovs_conf.OPTS)
         ),
    ]


def list_az_agent_opts():
    return [
        ('agent', neutron.conf.agent.common.AVAILABILITY_ZONE_OPTS),
    ]


def list_dhcp_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.dhcp.DHCP_AGENT_OPTS,
             neutron.conf.agent.dhcp.DHCP_OPTS,
             neutron.conf.agent.dhcp.DNSMASQ_OPTS)
         ),
        (meta_conf.RATE_LIMITING_GROUP,
         meta_conf.METADATA_RATE_LIMITING_OPTS)
    ]


def list_linux_bridge_opts():
    return [
        ('DEFAULT',
         neutron.conf.service.RPC_EXTRA_OPTS),
        ('linux_bridge',
         neutron.conf.plugins.ml2.drivers.linuxbridge.bridge_opts),
        ('vxlan',
         neutron.conf.plugins.ml2.drivers.linuxbridge.vxlan_opts),
        ('agent',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.agent.agent_opts,
             neutron.conf.agent.agent_extensions_manager.
             AGENT_EXT_MANAGER_OPTS)
         ),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts),
        ('network_log',
         neutron.conf.services.logging.log_driver_opts)
    ]


def list_l3_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.l3.config.OPTS,
             neutron.conf.service.SERVICE_OPTS,
             neutron.conf.agent.l3.ha.OPTS,
             neutron.conf.agent.common.PD_DRIVER_OPTS,
             neutron.conf.agent.common.RA_OPTS)
         ),
        ('agent',
         neutron.conf.agent.agent_extensions_manager.AGENT_EXT_MANAGER_OPTS),
        ('network_log',
         neutron.conf.services.logging.log_driver_opts),
        (meta_conf.RATE_LIMITING_GROUP,
         meta_conf.METADATA_RATE_LIMITING_OPTS)
    ]


def list_macvtap_opts():
    return [
        ('macvtap',
         neutron.conf.plugins.ml2.drivers.macvtap.macvtap_opts),
        ('agent',
         neutron.conf.plugins.ml2.drivers.agent.agent_opts),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts)
    ]


def list_metadata_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             meta_conf.SHARED_OPTS,
             meta_conf.METADATA_PROXY_HANDLER_OPTS,
             meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS,
             neutron.conf.service.RPC_EXTRA_OPTS)
         ),
        ('agent', neutron.conf.agent.common.AGENT_STATE_OPTS)
    ]


def list_metering_agent_opts():
    return [
        ('DEFAULT', neutron.conf.services.metering_agent.metering_agent_opts),
    ]


def list_ml2_conf_opts():
    return [
        ('ml2',
         neutron.conf.plugins.ml2.config.ml2_opts),
        ('ml2_type_flat',
         neutron.conf.plugins.ml2.drivers.driver_type.flat_opts),
        ('ml2_type_vlan',
         neutron.conf.plugins.ml2.drivers.driver_type.vlan_opts),
        ('ml2_type_gre',
         neutron.conf.plugins.ml2.drivers.driver_type.gre_opts),
        ('ml2_type_vxlan',
         neutron.conf.plugins.ml2.drivers.driver_type.vxlan_opts),
        ('ml2_type_geneve',
         neutron.conf.plugins.ml2.drivers.driver_type.geneve_opts),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts),
        ('ovs_driver',
         neutron.conf.plugins.ml2.drivers.openvswitch.mech_ovs_conf.
         ovs_driver_opts),
        ('sriov_driver',
         neutron.conf.plugins.ml2.drivers.mech_sriov.mech_sriov_conf.
         sriov_driver_opts)
    ]


def list_ovs_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.service.RPC_EXTRA_OPTS)
         ),
        ('ovs',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.ovs_conf.ovs_opts,
             neutron.conf.agent.ovsdb_api.API_OPTS)
         ),
        ('agent',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.ovs_conf.agent_opts,
             neutron.conf.agent.agent_extensions_manager.
             AGENT_EXT_MANAGER_OPTS)
         ),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts),
        ('network_log',
         neutron.conf.services.logging.log_driver_opts),
        ('dhcp',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.ovs_conf.dhcp_opts,
             neutron.conf.agent.common.DHCP_PROTOCOL_OPTS)),
        ('metadata',
         itertools.chain(
             meta_conf.METADATA_PROXY_HANDLER_OPTS))
    ]


def list_sriov_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.service.RPC_EXTRA_OPTS)
         ),
        ('sriov_nic',
         neutron.conf.plugins.ml2.drivers.mech_sriov.agent_common.
         sriov_nic_opts),
        ('agent',
         neutron.conf.agent.agent_extensions_manager.AGENT_EXT_MANAGER_OPTS)
    ]


def list_experimental_opts():
    return [
        (neutron.conf.experimental.EXPERIMENTAL_CFG_GROUP,
         itertools.chain(neutron.conf.experimental.experimental_opts)
         ),
    ]
