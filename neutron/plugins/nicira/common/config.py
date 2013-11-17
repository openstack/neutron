# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

from oslo.config import cfg


class AgentModes:
    AGENT = 'agent'
    # TODO(armando-migliaccio): support to be added, maybe we could add a
    # mixed mode to support no-downtime migrations?
    AGENTLESS = 'agentless'


class MetadataModes:
    DIRECT = 'access_network'
    INDIRECT = 'dhcp_host_route'


nvp_opts = [
    cfg.IntOpt('max_lp_per_bridged_ls', default=5000,
               help=_("Maximum number of ports of a logical switch on a "
                      "bridged transport zone (default 5000)")),
    cfg.IntOpt('max_lp_per_overlay_ls', default=256,
               help=_("Maximum number of ports of a logical switch on an "
                      "overlay transport zone (default 256)")),
    cfg.IntOpt('concurrent_connections', default=10,
               help=_("Maximum concurrent connections to each NVP "
                      "controller.")),
    cfg.IntOpt('nvp_gen_timeout', default=-1,
               help=_("Number of seconds a generation id should be valid for "
                      "(default -1 meaning do not time out)")),
    cfg.StrOpt('metadata_mode', default=MetadataModes.DIRECT,
               help=_("If set to access_network this enables a dedicated "
                      "connection to the metadata proxy for metadata server "
                      "access via Neutron router. If set to dhcp_host_route "
                      "this enables host route injection via the dhcp agent. "
                      "This option is only useful if running on a host that "
                      "does not support namespaces otherwise access_network "
                      "should be used.")),
    cfg.StrOpt('default_transport_type', default='stt',
               help=_("The default network tranport type to use (stt, gre, "
                      "bridge, ipsec_gre, or ipsec_stt)")),
    cfg.StrOpt('agent_mode', default=AgentModes.AGENT,
               help=_("The mode used to implement DHCP/metadata services."))
]

sync_opts = [
    cfg.IntOpt('state_sync_interval', default=120,
               help=_("Interval in seconds between runs of the state "
                      "synchronization task. Set it to 0 to disable it")),
    cfg.IntOpt('max_random_sync_delay', default=0,
               help=_("Maximum value for the additional random "
                      "delay in seconds between runs of the state "
                      "synchronization task")),
    cfg.IntOpt('min_sync_req_delay', default=10,
               help=_('Minimum delay, in seconds, between two state '
                      'synchronization queries to NVP. It must not '
                      'exceed state_sync_interval')),
    cfg.IntOpt('min_chunk_size', default=500,
               help=_('Minimum number of resources to be retrieved from NVP '
                      'during state synchronization')),
    cfg.BoolOpt('always_read_status', default=False,
                help=_('Always read operational status from backend on show '
                       'operations. Enabling this option might slow down '
                       'the system.'))
]

connection_opts = [
    cfg.StrOpt('nvp_user',
               default='admin',
               help=_('User name for NVP controllers in this cluster')),
    cfg.StrOpt('nvp_password',
               default='admin',
               secret=True,
               help=_('Password for NVP controllers in this cluster')),
    cfg.IntOpt('req_timeout',
               default=30,
               help=_('Total time limit for a cluster request')),
    cfg.IntOpt('http_timeout',
               default=10,
               help=_('Time before aborting a request')),
    cfg.IntOpt('retries',
               default=2,
               help=_('Number of time a request should be retried')),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Number of times a redirect should be followed')),
    cfg.ListOpt('nvp_controllers',
                help=_("Lists the NVP controllers in this cluster")),
]

cluster_opts = [
    cfg.StrOpt('default_tz_uuid',
               help=_("This is uuid of the default NVP Transport zone that "
                      "will be used for creating tunneled isolated "
                      "\"Neutron\" networks. It needs to be created in NVP "
                      "before starting Neutron with the nvp plugin.")),
    cfg.StrOpt('default_l3_gw_service_uuid',
               help=_("Unique identifier of the NVP L3 Gateway service "
                      "which will be used for implementing routers and "
                      "floating IPs")),
    cfg.StrOpt('default_l2_gw_service_uuid',
               help=_("Unique identifier of the NVP L2 Gateway service "
                      "which will be used by default for network gateways")),
    cfg.StrOpt('default_interface_name', default='breth0',
               help=_("Name of the interface on a L2 Gateway transport node"
                      "which should be used by default when setting up a "
                      "network connection")),
]

DEFAULT_STATUS_CHECK_INTERVAL = 2000

vcns_opts = [
    cfg.StrOpt('user',
               default='admin',
               help=_('User name for vsm')),
    cfg.StrOpt('password',
               default='default',
               secret=True,
               help=_('Password for vsm')),
    cfg.StrOpt('manager_uri',
               help=_('uri for vsm')),
    cfg.StrOpt('datacenter_moid',
               help=_('Optional parameter identifying the ID of datacenter '
                      'to deploy NSX Edges')),
    cfg.StrOpt('deployment_container_id',
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('resource_pool_id',
               help=_('Optional parameter identifying the ID of resource to '
                      'deploy NSX Edges')),
    cfg.StrOpt('datastore_id',
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('external_network',
               help=_('Network ID for physical network connectivity')),
    cfg.IntOpt('task_status_check_interval',
               default=DEFAULT_STATUS_CHECK_INTERVAL,
               help=_("Task status check interval"))
]

# Register the configuration options
cfg.CONF.register_opts(connection_opts)
cfg.CONF.register_opts(cluster_opts)
cfg.CONF.register_opts(nvp_opts, "NVP")
cfg.CONF.register_opts(sync_opts, "NVP_SYNC")
cfg.CONF.register_opts(vcns_opts, group="vcns")
