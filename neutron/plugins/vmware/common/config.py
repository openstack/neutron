# Copyright 2012 VMware, Inc.
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

from neutron.plugins.vmware.common import exceptions as nsx_exc


class AgentModes(object):
    AGENT = 'agent'
    AGENTLESS = 'agentless'
    COMBINED = 'combined'


class MetadataModes(object):
    DIRECT = 'access_network'
    INDIRECT = 'dhcp_host_route'


class ReplicationModes(object):
    SERVICE = 'service'
    SOURCE = 'source'


base_opts = [
    cfg.IntOpt('max_lp_per_bridged_ls', default=5000,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on a "
                      "bridged transport zone (default 5000)")),
    cfg.IntOpt('max_lp_per_overlay_ls', default=256,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on an "
                      "overlay transport zone (default 256)")),
    cfg.IntOpt('concurrent_connections', default=10,
               deprecated_group='NVP',
               help=_("Maximum concurrent connections to each NSX "
                      "controller.")),
    cfg.IntOpt('nsx_gen_timeout', default=-1,
               deprecated_name='nvp_gen_timeout',
               deprecated_group='NVP',
               help=_("Number of seconds a generation id should be valid for "
                      "(default -1 meaning do not time out)")),
    cfg.StrOpt('metadata_mode', default=MetadataModes.DIRECT,
               deprecated_group='NVP',
               help=_("If set to access_network this enables a dedicated "
                      "connection to the metadata proxy for metadata server "
                      "access via Neutron router. If set to dhcp_host_route "
                      "this enables host route injection via the dhcp agent. "
                      "This option is only useful if running on a host that "
                      "does not support namespaces otherwise access_network "
                      "should be used.")),
    cfg.StrOpt('default_transport_type', default='stt',
               deprecated_group='NVP',
               help=_("The default network tranport type to use (stt, gre, "
                      "bridge, ipsec_gre, or ipsec_stt)")),
    cfg.StrOpt('agent_mode', default=AgentModes.AGENT,
               deprecated_group='NVP',
               help=_("The mode used to implement DHCP/metadata services.")),
    cfg.StrOpt('replication_mode', default=ReplicationModes.SERVICE,
               help=_("The default option leverages service nodes to perform"
                      " packet replication though one could set to this to "
                      "'source' to perform replication locally. This is useful"
                      " if one does not want to deploy a service node(s). "
                      "It must be set to 'service' for leveraging distributed "
                      "routers."))
]

sync_opts = [
    cfg.IntOpt('state_sync_interval', default=10,
               deprecated_group='NVP_SYNC',
               help=_("Interval in seconds between runs of the state "
                      "synchronization task. Set it to 0 to disable it")),
    cfg.IntOpt('max_random_sync_delay', default=0,
               deprecated_group='NVP_SYNC',
               help=_("Maximum value for the additional random "
                      "delay in seconds between runs of the state "
                      "synchronization task")),
    cfg.IntOpt('min_sync_req_delay', default=1,
               deprecated_group='NVP_SYNC',
               help=_('Minimum delay, in seconds, between two state '
                      'synchronization queries to NSX. It must not '
                      'exceed state_sync_interval')),
    cfg.IntOpt('min_chunk_size', default=500,
               deprecated_group='NVP_SYNC',
               help=_('Minimum number of resources to be retrieved from NSX '
                      'during state synchronization')),
    cfg.BoolOpt('always_read_status', default=False,
                deprecated_group='NVP_SYNC',
                help=_('Always read operational status from backend on show '
                       'operations. Enabling this option might slow down '
                       'the system.'))
]

connection_opts = [
    cfg.StrOpt('nsx_user',
               default='admin',
               deprecated_name='nvp_user',
               help=_('User name for NSX controllers in this cluster')),
    cfg.StrOpt('nsx_password',
               default='admin',
               deprecated_name='nvp_password',
               secret=True,
               help=_('Password for NSX controllers in this cluster')),
    cfg.IntOpt('http_timeout',
               default=75,
               help=_('Time before aborting a request')),
    cfg.IntOpt('retries',
               default=2,
               help=_('Number of time a request should be retried')),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Number of times a redirect should be followed')),
    cfg.ListOpt('nsx_controllers',
                deprecated_name='nvp_controllers',
                help=_("Lists the NSX controllers in this cluster")),
    cfg.IntOpt('conn_idle_timeout',
               default=900,
               help=_('Reconnect connection to nsx if not used within this '
                      'amount of time.')),
]

cluster_opts = [
    cfg.StrOpt('default_tz_uuid',
               help=_("This is uuid of the default NSX Transport zone that "
                      "will be used for creating tunneled isolated "
                      "\"Neutron\" networks. It needs to be created in NSX "
                      "before starting Neutron with the nsx plugin.")),
    cfg.StrOpt('default_l3_gw_service_uuid',
               help=_("Unique identifier of the NSX L3 Gateway service "
                      "which will be used for implementing routers and "
                      "floating IPs")),
    cfg.StrOpt('default_l2_gw_service_uuid',
               help=_("Unique identifier of the NSX L2 Gateway service "
                      "which will be used by default for network gateways")),
    cfg.StrOpt('default_service_cluster_uuid',
               help=_("Unique identifier of the Service Cluster which will "
                      "be used by logical services like dhcp and metadata")),
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
cfg.CONF.register_opts(vcns_opts, group="vcns")
cfg.CONF.register_opts(base_opts, group="NSX")
cfg.CONF.register_opts(sync_opts, group="NSX_SYNC")


def validate_config_options():
    if cfg.CONF.NSX.replication_mode not in (ReplicationModes.SERVICE,
                                             ReplicationModes.SOURCE):
        error = (_("Invalid replication_mode: %s") %
                 cfg.CONF.NSX.replication_mode)
        raise nsx_exc.NsxPluginException(err_msg=error)
