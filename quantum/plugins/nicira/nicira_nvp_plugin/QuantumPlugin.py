# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
# All Rights Reserved
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
#
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


import hashlib
import logging

from oslo.config import cfg
from sqlalchemy.orm import exc as sa_exc
import webob.exc

from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.common import constants
from quantum import context as q_context
from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.db import portsecurity_db
from quantum.db import quota_db  # noqa
from quantum.db import securitygroups_db
from quantum.extensions import l3
from quantum.extensions import portsecurity as psec
from quantum.extensions import providernet as pnet
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common import importutils
from quantum.openstack.common import rpc
from quantum.plugins.nicira.nicira_nvp_plugin.common import (metadata_access
                                                             as nvp_meta)
from quantum.plugins.nicira.nicira_nvp_plugin.common import (securitygroups
                                                             as nvp_sec)
from quantum import policy
from quantum.plugins.nicira.nicira_nvp_plugin.common import config
from quantum.plugins.nicira.nicira_nvp_plugin.common import (exceptions
                                                             as nvp_exc)
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import (nvp_networkgw
                                                                 as networkgw)
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import (nvp_qos
                                                                 as ext_qos)
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_db
from quantum.plugins.nicira.nicira_nvp_plugin import (nicira_networkgw_db
                                                      as networkgw_db)
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_qos_db as qos_db
from quantum.plugins.nicira.nicira_nvp_plugin import nvp_cluster
from quantum.plugins.nicira.nicira_nvp_plugin.nvp_plugin_version import (
    PLUGIN_VERSION)
from quantum.plugins.nicira.nicira_nvp_plugin import NvpApiClient
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib

LOG = logging.getLogger("QuantumPlugin")
NVP_NOSNAT_RULES_ORDER = 10
NVP_FLOATINGIP_NAT_RULES_ORDER = 200
NVP_EXTGW_NAT_RULES_ORDER = 255


# Provider network extension - allowed network types for the NVP Plugin
class NetworkTypes:
    """ Allowed provider network types for the NVP Plugin """
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'


def parse_config():
    """Parse the supplied plugin configuration.

    :param config: a ConfigParser() object encapsulating nvp.ini.
    :returns: A tuple: (clusters, plugin_config). 'clusters' is a list of
        NVPCluster objects, 'plugin_config' is a dictionary with plugin
        parameters (currently only 'max_lp_per_bridged_ls').
    """
    nvp_conf = config.ClusterConfigOptions(cfg.CONF)
    cluster_names = config.register_cluster_groups(nvp_conf)
    nvp_conf.log_opt_values(LOG, logging.DEBUG)

    clusters_options = []
    for cluster_name in cluster_names:
        clusters_options.append(
            {'name': cluster_name,
             'default_tz_uuid':
             nvp_conf[cluster_name].default_tz_uuid,
             'nvp_cluster_uuid':
             nvp_conf[cluster_name].nvp_cluster_uuid,
             'nova_zone_id':
             nvp_conf[cluster_name].nova_zone_id,
             'nvp_controller_connection':
             nvp_conf[cluster_name].nvp_controller_connection,
             'default_l3_gw_service_uuid':
             nvp_conf[cluster_name].default_l3_gw_service_uuid,
             'default_l2_gw_service_uuid':
             nvp_conf[cluster_name].default_l2_gw_service_uuid,
             'default_interface_name':
             nvp_conf[cluster_name].default_interface_name})
    LOG.debug(_("Cluster options:%s"), clusters_options)

    # If no api_extensions_path is provided set the following
    if not cfg.CONF.api_extensions_path:
        cfg.CONF.set_override(
            'api_extensions_path',
            'quantum/plugins/nicira/nicira_nvp_plugin/extensions')
    if (cfg.CONF.NVP.metadata_mode == "access_network" and
        not cfg.CONF.allow_overlapping_ips):
        LOG.warn(_("Overlapping IPs must be enabled in order to setup "
                   "the metadata access network. Metadata access in "
                   "routed mode will not work with this configuration"))
    return cfg.CONF.NVP, clusters_options


def parse_clusters_opts(clusters_opts, concurrent_connections,
                        nvp_gen_timeout, default_cluster_name):
    # Will store the first cluster in case is needed for default
    # cluster assignment
    clusters = {}
    first_cluster = None
    for c_opts in clusters_opts:
        # Password is guaranteed to be the same across all controllers
        # in the same NVP cluster.
        cluster = nvp_cluster.NVPCluster(c_opts['name'])
        try:
            for ctrl_conn in c_opts['nvp_controller_connection']:
                args = ctrl_conn.split(':')
                try:
                    args.extend([c_opts['default_tz_uuid'],
                                 c_opts['nvp_cluster_uuid'],
                                 c_opts['nova_zone_id'],
                                 c_opts['default_l3_gw_service_uuid'],
                                 c_opts['default_l2_gw_service_uuid'],
                                 c_opts['default_interface_name']])
                    cluster.add_controller(*args)
                except Exception:
                    LOG.exception(_("Invalid connection parameters for "
                                    "controller %(ctrl)s in "
                                    "cluster %(cluster)s"),
                                  {'ctrl': ctrl_conn,
                                   'cluster': c_opts['name']})
                    raise nvp_exc.NvpInvalidConnection(
                        conn_params=ctrl_conn)
        except TypeError:
            msg = _("No controller connection specified in cluster "
                    "configuration. Please ensure at least a value for "
                    "'nvp_controller_connection' is specified in the "
                    "[CLUSTER:%s] section") % c_opts['name']
            LOG.exception(msg)
            raise nvp_exc.NvpPluginException(err_msg=msg)

        api_providers = [(x['ip'], x['port'], True)
                         for x in cluster.controllers]
        cluster.api_client = NvpApiClient.NVPApiHelper(
            api_providers, cluster.user, cluster.password,
            request_timeout=cluster.request_timeout,
            http_timeout=cluster.http_timeout,
            retries=cluster.retries,
            redirects=cluster.redirects,
            concurrent_connections=concurrent_connections,
            nvp_gen_timeout=nvp_gen_timeout)

        if not clusters:
            first_cluster = cluster
        clusters[c_opts['name']] = cluster

    if default_cluster_name and default_cluster_name in clusters:
        default_cluster = clusters[default_cluster_name]
    else:
        default_cluster = first_cluster
    return (clusters, default_cluster)


class NVPRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class NvpPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                  l3_db.L3_NAT_db_mixin,
                  portsecurity_db.PortSecurityDbMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  networkgw_db.NetworkGatewayMixin,
                  qos_db.NVPQoSDbMixin,
                  nvp_sec.NVPSecurityGroups,
                  nvp_meta.NvpMetadataAccess,
                  agentschedulers_db.AgentSchedulerDbMixin):
    """
    NvpPluginV2 is a Quantum plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    supported_extension_aliases = ["provider", "quotas", "port-security",
                                   "router", "security-group", "nvp-qos",
                                   "network-gateway"]

    __native_bulk_support = True

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}
    # Default controller cluster (to be used when nova zone id is unspecified)
    default_cluster = None

    provider_network_view = "extension:provider_network:view"
    provider_network_set = "extension:provider_network:set"
    port_security_enabled_create = "create_port:port_security_enabled"
    port_security_enabled_update = "update_port:port_security_enabled"

    def __init__(self, loglevel=None):
        if loglevel:
            logging.basicConfig(level=loglevel)
            nvplib.LOG.setLevel(loglevel)
            NvpApiClient.LOG.setLevel(loglevel)

        # Routines for managing logical ports in NVP
        self._port_drivers = {
            'create': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_create_ext_gw_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_create_port,
                       l3_db.DEVICE_OWNER_FLOATINGIP:
                       self._nvp_create_fip_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_create_router_port,
                       networkgw_db.DEVICE_OWNER_NET_GW_INTF:
                       self._nvp_create_l2_gw_port,
                       'default': self._nvp_create_port},
            'delete': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_delete_ext_gw_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_delete_router_port,
                       l3_db.DEVICE_OWNER_FLOATINGIP:
                       self._nvp_delete_fip_port,
                       l3_db.DEVICE_OWNER_ROUTER_INTF:
                       self._nvp_delete_port,
                       networkgw_db.DEVICE_OWNER_NET_GW_INTF:
                       self._nvp_delete_port,
                       'default': self._nvp_delete_port}
        }

        self.nvp_opts, self.clusters_opts = parse_config()
        if not self.clusters_opts:
            msg = _("No cluster specified in NVP plugin configuration. "
                    "Unable to start. Please ensure at least a "
                    "[CLUSTER:<cluster_name>] section is specified in "
                    "the NVP Plugin configuration file.")
            LOG.error(msg)
            raise nvp_exc.NvpPluginException(err_msg=msg)

        self.clusters, self.default_cluster = parse_clusters_opts(
            self.clusters_opts, self.nvp_opts.concurrent_connections,
            self.nvp_opts.nvp_gen_timeout, self.nvp_opts.default_cluster_name)

        db.configure_db()
        # Extend the fault map
        self._extend_fault_map()
        # Set up RPC interface for DHCP agent
        self.setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        # TODO(salvatore-orlando): Handle default gateways in multiple clusters
        self._ensure_default_network_gateway()

    def _ensure_default_network_gateway(self):
        # Add the gw in the db as default, and unset any previous default
        def_l2_gw_uuid = self.default_cluster.default_l2_gw_service_uuid
        try:
            ctx = q_context.get_admin_context()
            self._unset_default_network_gateways(ctx)
            if not def_l2_gw_uuid:
                return
            try:
                def_network_gw = self._get_network_gateway(ctx,
                                                           def_l2_gw_uuid)
            except sa_exc.NoResultFound:
                # Create in DB only - don't go on NVP
                def_gw_data = {'id': def_l2_gw_uuid,
                               'name': 'default L2 gateway service',
                               'devices': []}
                gw_res_name = networkgw.RESOURCE_NAME.replace('-', '_')
                def_network_gw = super(
                    NvpPluginV2, self).create_network_gateway(
                        ctx, {gw_res_name: def_gw_data})
            # In any case set is as default
            self._set_default_network_gateway(ctx, def_network_gw['id'])
        except Exception:
            # This is fatal - abort startup
            LOG.exception(_("Unable to process default l2 gw service:%s"),
                          def_l2_gw_uuid)
            raise

    def _build_ip_address_list(self, context, fixed_ips, subnet_ids=None):
        """  Build ip_addresses data structure for logical router port

        No need to perform validation on IPs - this has already been
        done in the l3_db mixin class
        """
        ip_addresses = []
        for ip in fixed_ips:
            if not subnet_ids or (ip['subnet_id'] in subnet_ids):
                subnet = self._get_subnet(context, ip['subnet_id'])
                ip_prefix = '%s/%s' % (ip['ip_address'],
                                       subnet['cidr'].split('/')[1])
                ip_addresses.append(ip_prefix)
        return ip_addresses

    def _create_and_attach_router_port(self, cluster, context,
                                       router_id, port_data,
                                       attachment_type, attachment,
                                       attachment_vlan=None,
                                       subnet_ids=None):
        # Use a fake IP address if gateway port is not 'real'
        ip_addresses = (port_data.get('fake_ext_gw') and
                        ['0.0.0.0/31'] or
                        self._build_ip_address_list(context,
                                                    port_data['fixed_ips'],
                                                    subnet_ids))
        try:
            lrouter_port = nvplib.create_router_lport(
                cluster, router_id, port_data.get('tenant_id', 'fake'),
                port_data.get('id', 'fake'), port_data.get('name', 'fake'),
                port_data.get('admin_state_up', True), ip_addresses)
            LOG.debug(_("Created NVP router port:%s"), lrouter_port['uuid'])
        except NvpApiClient.NvpApiException:
            LOG.exception(_("Unable to create port on NVP logical router %s"),
                          router_id)
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to create logical router port for quantum "
                          "port id %(port_id)s on router %(router_id)s") %
                {'port_id': port_data.get('id'), 'router_id': router_id})
        self._update_router_port_attachment(cluster, context, router_id,
                                            port_data, attachment_type,
                                            attachment, attachment_vlan,
                                            lrouter_port['uuid'])
        return lrouter_port

    def _update_router_port_attachment(self, cluster, context,
                                       router_id, port_data,
                                       attachment_type, attachment,
                                       attachment_vlan=None,
                                       nvp_router_port_id=None):
        if not nvp_router_port_id:
            nvp_router_port_id = self._find_router_gw_port(context, port_data)
        try:
            nvplib.plug_router_port_attachment(cluster, router_id,
                                               nvp_router_port_id,
                                               attachment,
                                               attachment_type,
                                               attachment_vlan)
            LOG.debug(_("Attached %(att)s to NVP router port %(port)s"),
                      {'att': attachment, 'port': nvp_router_port_id})
        except NvpApiClient.NvpApiException:
            # Must remove NVP logical port
            nvplib.delete_router_lport(cluster, router_id,
                                       nvp_router_port_id)
            LOG.exception(_("Unable to plug attachment in NVP logical "
                            "router port %(r_port_id)s, associated with "
                            "Quantum %(q_port_id)s"),
                          {'r_port_id': nvp_router_port_id,
                           'q_port_id': port_data.get('id')})
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to plug attachment in router port "
                           "%(r_port_id)s for quantum port id %(q_port_id)s "
                           "on router %(router_id)s") %
                         {'r_port_id': nvp_router_port_id,
                          'q_port_id': port_data.get('id'),
                          'router_id': router_id}))

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """ Retrieve ports associated with a specific device id.

        Used for retrieving all quantum ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """ Retrieve subnets attached to the specified router """
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        cidrs = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                cidrs.append(self._get_subnet(context,
                                              ip.subnet_id).cidr)
        return cidrs

    def _nvp_find_lswitch_for_port(self, context, port_data):
        network = self._get_network(context, port_data['network_id'])
        network_binding = nicira_db.get_network_binding(
            context.session, port_data['network_id'])
        max_ports = self.nvp_opts.max_lp_per_overlay_ls
        allow_extra_lswitches = False
        if (network_binding and
            network_binding.binding_type in (NetworkTypes.FLAT,
                                             NetworkTypes.VLAN)):
            max_ports = self.nvp_opts.max_lp_per_bridged_ls
            allow_extra_lswitches = True
        try:
            cluster = self._find_target_cluster(port_data)
            return self._handle_lswitch_selection(
                cluster, network, network_binding, max_ports,
                allow_extra_lswitches)
        except NvpApiClient.NvpApiException:
            err_desc = _(("An exception occured while selecting logical "
                          "switch for the port"))
            LOG.exception(err_desc)
            raise nvp_exc.NvpPluginException(err_msg=err_desc)

    def _nvp_create_port_helper(self, cluster, ls_uuid, port_data,
                                do_port_security=True):
        return nvplib.create_lport(cluster, ls_uuid, port_data['tenant_id'],
                                   port_data['id'], port_data['name'],
                                   port_data['device_id'],
                                   port_data['admin_state_up'],
                                   port_data['mac_address'],
                                   port_data['fixed_ips'],
                                   port_data[psec.PORTSECURITY],
                                   port_data[ext_sg.SECURITYGROUPS],
                                   port_data[ext_qos.QUEUE])

    def _nvp_create_port(self, context, port_data):
        """ Driver for creating a logical switch port on NVP platform """
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.error(_("NVP plugin does not support regular VIF ports on "
                        "external networks. Port %s will be down."),
                      port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        try:
            cluster = self._find_target_cluster(port_data)
            selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                               port_data)
            lport = self._nvp_create_port_helper(cluster,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 True)
            nicira_db.add_quantum_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            if (not port_data['device_owner'] in
                (l3_db.DEVICE_OWNER_ROUTER_GW,
                 l3_db.DEVICE_OWNER_ROUTER_INTF)):
                nvplib.plug_interface(cluster, selected_lswitch['uuid'],
                                      lport['uuid'], "VifAttachment",
                                      port_data['id'])
            LOG.debug(_("_nvp_create_port completed for port %(name)s "
                        "on network %(network_id)s. The new port id is "
                        "%(id)s."), port_data)
        except NvpApiClient.NvpApiException:
            msg = (_("An exception occured while plugging the interface "
                     "into network:%s") % port_data['network_id'])
            LOG.exception(msg)
            raise q_exc.QuantumException(message=msg)

    def _nvp_delete_port(self, context, port_data):
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So deleting regular ports from external networks
        # does not make sense. However we cannot raise as this would break
        # unit tests.
        if self._network_is_external(context, port_data['network_id']):
            LOG.error(_("NVP plugin does not support regular VIF ports on "
                        "external networks. Port %s will be down."),
                      port_data['network_id'])
            return
        nvp_port_id = self._nvp_get_port_id(context, self.default_cluster,
                                            port_data)
        if not nvp_port_id:
            LOG.debug(_("Port '%s' was already deleted on NVP platform"), id)
            return
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        try:
            nvplib.delete_port(self.default_cluster,
                               port_data['network_id'],
                               nvp_port_id)
            LOG.debug(_("_nvp_delete_port completed for port %(port_id)s "
                        "on network %(net_id)s"),
                      {'port_id': port_data['id'],
                       'net_id': port_data['network_id']})

        except q_exc.NotFound:
            LOG.warning(_("port %s not found in NVP"), port_data['id'])

    def _nvp_delete_router_port(self, context, port_data):
        # Delete logical router port
        lrouter_id = port_data['device_id']
        nvp_port_id = self._nvp_get_port_id(context, self.default_cluster,
                                            port_data)
        if not nvp_port_id:
            raise q_exc.PortNotFound(port_id=port_data['id'])

        try:
            nvplib.delete_peer_router_lport(self.default_cluster,
                                            lrouter_id,
                                            port_data['network_id'],
                                            nvp_port_id)
        except (NvpApiClient.NvpApiException, NvpApiClient.ResourceNotFound):
            # Do not raise because the issue might as well be that the
            # router has already been deleted, so there would be nothing
            # to do here
            LOG.exception(_("Ignoring exception as this means the peer "
                            "for port '%s' has already been deleted."),
                          nvp_port_id)

        # Delete logical switch port
        self._nvp_delete_port(context, port_data)

    def _nvp_create_router_port(self, context, port_data):
        """ Driver for creating a switch port to be connected to a router """
        # No router ports on external networks!
        if self._network_is_external(context, port_data['network_id']):
            raise nvp_exc.NvpPluginException(
                err_msg=(_("It is not allowed to create router interface "
                           "ports on external networks as '%s'") %
                         port_data['network_id']))
        try:
            selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                               port_data)
            cluster = self._find_target_cluster(port_data)
            # Do not apply port security here!
            lport = self._nvp_create_port_helper(cluster,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 False)
            nicira_db.add_quantum_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            LOG.debug(_("_nvp_create_port completed for port %(name)s on "
                        "network %(network_id)s. The new port id is %(id)s."),
                      port_data)
        except Exception:
            # failed to create port in NVP delete port from quantum_db
            LOG.exception(_("An exception occured while plugging "
                            "the interface"))
            super(NvpPluginV2, self).delete_port(context, port_data["id"])
            raise

    def _find_router_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        cluster = self._find_target_cluster(port_data)
        if not router_id:
            raise q_exc.BadRequest(_("device_id field must be populated in "
                                   "order to create an external gateway "
                                   "port for network %s"),
                                   port_data['network_id'])

        lr_port = nvplib.find_router_gw_port(context, cluster, router_id)
        if not lr_port:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("The gateway port for the router %s "
                           "was not found on the NVP backend")
                         % router_id))
        return lr_port

    def _nvp_create_ext_gw_port(self, context, port_data):
        """ Driver for creating an external gateway port on NVP platform """
        # TODO(salvatore-orlando): Handle NVP resource
        # rollback when something goes not quite as expected
        lr_port = self._find_router_gw_port(context, port_data)
        ip_addresses = self._build_ip_address_list(context,
                                                   port_data['fixed_ips'])
        # This operation actually always updates a NVP logical port
        # instead of creating one. This is because the gateway port
        # is created at the same time as the NVP logical router, otherwise
        # the fabric status of the NVP router will be down.
        # admin_status should always be up for the gateway port
        # regardless of what the user specifies in quantum
        cluster = self._find_target_cluster(port_data)
        router_id = port_data['device_id']
        nvplib.update_router_lport(cluster,
                                   router_id,
                                   lr_port['uuid'],
                                   port_data['tenant_id'],
                                   port_data['id'],
                                   port_data['name'],
                                   True,
                                   ip_addresses)
        ext_network = self.get_network(context, port_data['network_id'])
        if ext_network.get(pnet.NETWORK_TYPE) == NetworkTypes.L3_EXT:
            # Update attachment
            self._update_router_port_attachment(
                cluster, context, router_id, port_data,
                "L3GatewayAttachment",
                ext_network[pnet.PHYSICAL_NETWORK],
                ext_network[pnet.SEGMENTATION_ID],
                lr_port['uuid'])
        # Set the SNAT rule for each subnet (only first IP)
        for cidr in self._find_router_subnets_cidrs(context, router_id):
            nvplib.create_lrouter_snat_rule(
                cluster, router_id,
                ip_addresses[0].split('/')[0],
                ip_addresses[0].split('/')[0],
                order=NVP_EXTGW_NAT_RULES_ORDER,
                match_criteria={'source_ip_addresses': cidr})

        LOG.debug(_("_nvp_create_ext_gw_port completed on external network "
                    "%(ext_net_id)s, attached to router:%(router_id)s. "
                    "NVP port id is %(nvp_port_id)s"),
                  {'ext_net_id': port_data['network_id'],
                   'router_id': router_id,
                   'nvp_port_id': lr_port['uuid']})

    def _nvp_delete_ext_gw_port(self, context, port_data):
        lr_port = self._find_router_gw_port(context, port_data)
        # TODO(salvatore-orlando): Handle NVP resource
        # rollback when something goes not quite as expected
        try:
            # Delete is actually never a real delete, otherwise the NVP
            # logical router will stop working
            cluster = self._find_target_cluster(port_data)
            router_id = port_data['device_id']
            nvplib.update_router_lport(cluster,
                                       router_id,
                                       lr_port['uuid'],
                                       port_data['tenant_id'],
                                       port_data['id'],
                                       port_data['name'],
                                       True,
                                       ['0.0.0.0/31'])
            # Delete the SNAT rule for each subnet
            for cidr in self._find_router_subnets_cidrs(context, router_id):
                nvplib.delete_nat_rules_by_match(
                    cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=cidr)
            # Reset attachment
            self._update_router_port_attachment(
                cluster, context, router_id, port_data,
                "L3GatewayAttachment",
                self.default_cluster.default_l3_gw_service_uuid,
                nvp_router_port_id=lr_port['uuid'])

        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Logical router resource %s not found "
                          "on NVP platform") % router_id)
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to update logical router"
                          "on NVP Platform"))
        LOG.debug(_("_nvp_delete_ext_gw_port completed on external network "
                    "%(ext_net_id)s, attached to router:%(router_id)s"),
                  {'ext_net_id': port_data['network_id'],
                   'router_id': router_id})

    def _nvp_create_l2_gw_port(self, context, port_data):
        """ Create a switch port, and attach it to a L2 gateway attachment """
        # FIXME(salvatore-orlando): On the NVP platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.error(_("NVP plugin does not support regular VIF ports on "
                        "external networks. Port %s will be down."),
                      port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        try:
            cluster = self._find_target_cluster(port_data)
            selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                               port_data)
            lport = self._nvp_create_port_helper(cluster,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 True)
            nicira_db.add_quantum_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            nvplib.plug_l2_gw_service(
                cluster,
                port_data['network_id'],
                lport['uuid'],
                port_data['device_id'],
                int(port_data.get('gw:segmentation_id') or 0))
            LOG.debug(_("_nvp_create_port completed for port %(name)s "
                        "on network %(network_id)s. The new port id "
                        "is %(id)s."), port_data)
        except NvpApiClient.NvpApiException:
            # failed to create port in NVP delete port from quantum_db
            msg = (_("An exception occured while plugging the gateway "
                     "interface into network:%s") % port_data['network_id'])
            LOG.exception(msg)
            super(NvpPluginV2, self).delete_port(context, port_data["id"])
            raise q_exc.QuantumException(message=msg)

    def _nvp_create_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _nvp_delete_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _nvp_get_port_id(self, context, cluster, quantum_port):
        """ Return the NVP port uuid for a given quantum port.
        First, look up the Quantum database. If not found, execute
        a query on NVP platform as the mapping might be missing because
        the port was created before upgrading to grizzly. """
        nvp_port_id = nicira_db.get_nvp_port_id(context.session,
                                                quantum_port['id'])
        if nvp_port_id:
            return nvp_port_id
        # Perform a query to NVP and then update the DB
        try:
            nvp_port = nvplib.get_port_by_quantum_tag(
                cluster,
                quantum_port['network_id'],
                quantum_port['id'])
            if nvp_port:
                nicira_db.add_quantum_nvp_port_mapping(
                    context.session,
                    quantum_port['id'],
                    nvp_port['uuid'])
                return nvp_port['uuid']
        except:
            LOG.exception(_("Unable to find NVP uuid for Quantum port %s"),
                          quantum_port['id'])

    def _extend_fault_map(self):
        """ Extends the Quantum Fault Map

        Exceptions specific to the NVP Plugin are mapped to standard
        HTTP Exceptions
        """
        base.FAULT_MAP.update({nvp_exc.NvpInvalidNovaZone:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpNoMorePortsException:
                               webob.exc.HTTPBadRequest})

    def _novazone_to_cluster(self, novazone_id):
        if novazone_id in self.novazone_cluster_map:
            return self.novazone_cluster_map[novazone_id]
        LOG.debug(_("Looking for nova zone: %s"), novazone_id)
        for x in self.clusters:
            LOG.debug(_("Looking for nova zone %(novazone_id)s in "
                        "cluster: %(x)s"), locals())
            if x.zone == str(novazone_id):
                self.novazone_cluster_map[x.zone] = x
                return x
        LOG.error(_("Unable to find cluster config entry for nova zone: %s"),
                  novazone_id)
        raise nvp_exc.NvpInvalidNovaZone(nova_zone=novazone_id)

    def _find_target_cluster(self, resource):
        """ Return cluster where configuration should be applied

        If the resource being configured has a paremeter expressing
        the zone id (nova_id), then select corresponding cluster,
        otherwise return default cluster.

        """
        if 'nova_id' in resource:
            return self._novazone_to_cluster(resource['nova_id'])
        else:
            return self.default_cluster

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        return policy.enforce(context, action, resource)

    def _handle_provider_create(self, context, attrs):
        # NOTE(salvatore-orlando): This method has been borrowed from
        # the OpenvSwtich plugin, altough changed to match NVP specifics.
        network_type = attrs.get(pnet.NETWORK_TYPE)
        physical_network = attrs.get(pnet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(pnet.SEGMENTATION_ID)
        network_type_set = attr.is_attr_set(network_type)
        physical_network_set = attr.is_attr_set(physical_network)
        segmentation_id_set = attr.is_attr_set(segmentation_id)
        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        # Authorize before exposing plugin details to client
        self._enforce_set_auth(context, attrs, self.provider_network_set)
        err_msg = None
        if not network_type_set:
            err_msg = _("%s required") % pnet.NETWORK_TYPE
        elif network_type in (NetworkTypes.GRE, NetworkTypes.STT,
                              NetworkTypes.FLAT):
            if segmentation_id_set:
                err_msg = _("Segmentation ID cannot be specified with "
                            "flat network type")
        elif network_type == NetworkTypes.VLAN:
            if not segmentation_id_set:
                err_msg = _("Segmentation ID must be specified with "
                            "vlan network type")
            elif (segmentation_id_set and
                  (segmentation_id < 1 or segmentation_id > 4094)):
                err_msg = _("%s out of range (1 to 4094)") % segmentation_id
            else:
                # Verify segment is not already allocated
                binding = nicira_db.get_network_binding_by_vlanid(
                    context.session, segmentation_id)
                if binding:
                    raise q_exc.VlanIdInUse(vlan_id=segmentation_id,
                                            physical_network=physical_network)
        elif network_type == NetworkTypes.L3_EXT:
            if (segmentation_id_set and
                (segmentation_id < 1 or segmentation_id > 4094)):
                err_msg = _("%s out of range (1 to 4094)") % segmentation_id
        else:
            err_msg = _("%(net_type_param)s %(net_type_value)s not "
                        "supported") % {'net_type_param': pnet.NETWORK_TYPE,
                                        'net_type_value': network_type}
        if err_msg:
            raise q_exc.InvalidInput(error_message=err_msg)
        # TODO(salvatore-orlando): Validate tranport zone uuid
        # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network, binding=None):
        if self._check_view_auth(context, network, self.provider_network_view):
            if not binding:
                binding = nicira_db.get_network_binding(context.session,
                                                        network['id'])
            # With NVP plugin 'normal' overlay networks will have no binding
            # TODO(salvatore-orlando) make sure users can specify a distinct
            # phy_uuid as 'provider network' for STT net type
            if binding:
                network[pnet.NETWORK_TYPE] = binding.binding_type
                network[pnet.PHYSICAL_NETWORK] = binding.phy_uuid
                network[pnet.SEGMENTATION_ID] = binding.vlan_id

    def _handle_lswitch_selection(self, cluster, network,
                                  network_binding, max_ports,
                                  allow_extra_lswitches):
        lswitches = nvplib.get_lswitches(cluster, network.id)
        try:
            # TODO find main_ls too!
            return [ls for ls in lswitches
                    if (ls['_relations']['LogicalSwitchStatus']
                        ['lport_count'] < max_ports)].pop(0)
        except IndexError:
            # Too bad, no switch available
            LOG.debug(_("No switch has available ports (%d checked)"),
                      len(lswitches))
        if allow_extra_lswitches:
            main_ls = [ls for ls in lswitches if ls['uuid'] == network.id]
            tag_dict = dict((x['scope'], x['tag']) for x in main_ls[0]['tags'])
            if 'multi_lswitch' not in tag_dict:
                tags = main_ls[0]['tags']
                tags.append({'tag': 'True', 'scope': 'multi_lswitch'})
                nvplib.update_lswitch(cluster,
                                      main_ls[0]['uuid'],
                                      main_ls[0]['display_name'],
                                      network['tenant_id'],
                                      tags=tags)
            selected_lswitch = nvplib.create_lswitch(
                cluster, network.tenant_id,
                "%s-ext-%s" % (network.name, len(lswitches)),
                network_binding.binding_type,
                network_binding.phy_uuid,
                network_binding.vlan_id,
                network.id)
            return selected_lswitch
        else:
            LOG.error(_("Maximum number of logical ports reached for "
                        "logical network %s"), network.id)
            raise nvp_exc.NvpNoMorePortsException(network=network.id)

    def setup_rpc(self):
        # RPC support for dhcp
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = NVPRpcCallbacks().create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def get_all_networks(self, tenant_id, **kwargs):
        networks = []
        for c in self.clusters:
            networks.extend(nvplib.get_all_networks(c, tenant_id, networks))
        LOG.debug(_("get_all_networks() completed for tenant "
                    "%(tenant_id)s: %(networks)s"), locals())
        return networks

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        self._handle_provider_create(context, net_data)
        # Replace ATTR_NOT_SPECIFIED with None before sending to NVP
        for key, value in network['network'].iteritems():
            if value is attr.ATTR_NOT_SPECIFIED:
                net_data[key] = None
        # FIXME(arosen) implement admin_state_up = False in NVP
        if net_data['admin_state_up'] is False:
            LOG.warning(_("Network with admin_state_up=False are not yet "
                          "supported by this plugin. Ignoring setting for "
                          "network %s"), net_data.get('name', '<unknown>'))
        target_cluster = self._find_target_cluster(net_data)
        external = net_data.get(l3.EXTERNAL)
        if (not attr.is_attr_set(external) or
            attr.is_attr_set(external) and not external):
            nvp_binding_type = net_data.get(pnet.NETWORK_TYPE)
            if nvp_binding_type in ('flat', 'vlan'):
                nvp_binding_type = 'bridge'
            lswitch = nvplib.create_lswitch(
                target_cluster, tenant_id, net_data.get('name'),
                nvp_binding_type,
                net_data.get(pnet.PHYSICAL_NETWORK),
                net_data.get(pnet.SEGMENTATION_ID),
                shared=net_data.get(attr.SHARED))
            net_data['id'] = lswitch['uuid']

        with context.session.begin(subtransactions=True):
            new_net = super(NvpPluginV2, self).create_network(context,
                                                              network)
            # Ensure there's an id in net_data
            net_data['id'] = new_net['id']
            # Process port security extension
            self._process_network_create_port_security(context, net_data)
            # DB Operations for setting the network as external
            self._process_l3_create(context, net_data, new_net['id'])
            # Process QoS queue extension
            if network['network'].get(ext_qos.QUEUE):
                new_net[ext_qos.QUEUE] = network['network'][ext_qos.QUEUE]
                # Raises if not found
                self.get_qos_queue(context, new_net[ext_qos.QUEUE])
                self._process_network_queue_mapping(context, new_net)
                self._extend_network_qos_queue(context, new_net)

            if net_data.get(pnet.NETWORK_TYPE):
                net_binding = nicira_db.add_network_binding(
                    context.session, new_net['id'],
                    net_data.get(pnet.NETWORK_TYPE),
                    net_data.get(pnet.PHYSICAL_NETWORK),
                    net_data.get(pnet.SEGMENTATION_ID, 0))
                self._extend_network_dict_provider(context, new_net,
                                                   net_binding)
            self._extend_network_port_security_dict(context, new_net)
            self._extend_network_dict_l3(context, new_net)
        self.schedule_network(context, new_net)
        return new_net

    def delete_network(self, context, id):
        external = self._network_is_external(context, id)
        # Before deleting ports, ensure the peer of a NVP logical
        # port with a patch attachment is removed too
        port_filter = {'network_id': [id],
                       'device_owner': ['network:router_interface']}
        router_iface_ports = self.get_ports(context, filters=port_filter)
        for port in router_iface_ports:
            nvp_port_id = self._nvp_get_port_id(
                context, self.default_cluster, port)
            if nvp_port_id:
                port['nvp_port_id'] = nvp_port_id
            else:
                LOG.warning(_("A nvp lport identifier was not found for "
                              "quantum port '%s'"), port['id'])

        super(NvpPluginV2, self).delete_network(context, id)
        # clean up network owned ports
        for port in router_iface_ports:
            try:
                if 'nvp_port_id' in port:
                    nvplib.delete_peer_router_lport(self.default_cluster,
                                                    port['device_id'],
                                                    port['network_id'],
                                                    port['nvp_port_id'])
            except (TypeError, KeyError,
                    NvpApiClient.NvpApiException,
                    NvpApiClient.ResourceNotFound):
                # Do not raise because the issue might as well be that the
                # router has already been deleted, so there would be nothing
                # to do here
                LOG.warning(_("Ignoring exception as this means the peer for "
                              "port '%s' has already been deleted."),
                            nvp_port_id)

        # Do not go to NVP for external networks
        if not external:
            try:
                # FIXME(salvatore-orlando): Failures here might lead NVP
                # and quantum state to diverge
                pairs = self._get_lswitch_cluster_pairs(id, context.tenant_id)
                for (cluster, switches) in pairs:
                    nvplib.delete_networks(cluster, id, switches)

                LOG.debug(_("delete_network completed for tenant: %s"),
                          context.tenant_id)
            except q_exc.NotFound:
                LOG.warning(_("Did not found lswitch %s in NVP"), id)

    def _get_lswitch_cluster_pairs(self, netw_id, tenant_id):
        """Figure out the set of lswitches on each cluster that maps to this
           network id"""
        pairs = []
        for c in self.clusters.itervalues():
            lswitches = []
            try:
                results = nvplib.get_lswitches(c, netw_id)
                lswitches.extend([ls['uuid'] for ls in results])
            except q_exc.NetworkNotFound:
                continue
            pairs.append((c, lswitches))
        if not pairs:
            raise q_exc.NetworkNotFound(net_id=netw_id)
        LOG.debug(_("Returning pairs for network: %s"), pairs)
        return pairs

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # if the network is external, do not go to NVP
            if not self._network_is_external(context, id):
                # verify the fabric status of the corresponding
                # logical switch(es) in nvp
                try:
                    # FIXME(salvatore-orlando): This is not going to work
                    # unless we store the nova_id in the database once we'll
                    # enable multiple clusters
                    cluster = self._find_target_cluster(network)
                    lswitches = nvplib.get_lswitches(cluster, id)
                    nvp_net_status = constants.NET_STATUS_ACTIVE
                    quantum_status = network.status
                    for lswitch in lswitches:
                        relations = lswitch.get('_relations')
                        if relations:
                            lswitch_status = relations.get(
                                'LogicalSwitchStatus')
                            # FIXME(salvatore-orlando): Being unable to fetch
                            # logical switch status should be an exception.
                            if (lswitch_status and
                                not lswitch_status.get('fabric_status',
                                                       None)):
                                nvp_net_status = constants.NET_STATUS_DOWN
                                break
                    LOG.debug(_("Current network status:%(nvp_net_status)s; "
                                "Status in Quantum DB:%(quantum_status)s"),
                              locals())
                    if nvp_net_status != network.status:
                        # update the network status
                        network.status = nvp_net_status
                except q_exc.NotFound:
                    network.status = constants.NET_STATUS_ERROR
                except Exception:
                    err_msg = _("Unable to get logical switches")
                    LOG.exception(err_msg)
                    raise nvp_exc.NvpPluginException(err_msg=err_msg)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network, None)
            self._extend_network_dict_provider(context, net_result)
            self._extend_network_port_security_dict(context, net_result)
            self._extend_network_dict_l3(context, net_result)
            self._extend_network_qos_queue(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None):
        nvp_lswitches = {}
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            quantum_lswitches = (
                super(NvpPluginV2, self).get_networks(context, filters))
            for net in quantum_lswitches:
                self._extend_network_dict_provider(context, net)
                self._extend_network_port_security_dict(context, net)
                self._extend_network_dict_l3(context, net)
                self._extend_network_qos_queue(context, net)

            tenant_ids = filters and filters.get('tenant_id') or None
        filter_fmt = "&tag=%s&tag_scope=os_tid"
        if context.is_admin and not tenant_ids:
            tenant_filter = ""
        else:
            tenant_ids = tenant_ids or [context.tenant_id]
            tenant_filter = ''.join(filter_fmt % tid for tid in tenant_ids)
        lswitch_filters = "uuid,display_name,fabric_status,tags"
        lswitch_url_path_1 = (
            "/ws.v1/lswitch?fields=%s&relations=LogicalSwitchStatus%s"
            % (lswitch_filters, tenant_filter))
        lswitch_url_path_2 = nvplib._build_uri_path(
            nvplib.LSWITCH_RESOURCE,
            fields=lswitch_filters,
            relations='LogicalSwitchStatus',
            filters={'tag': 'true', 'tag_scope': 'shared'})
        try:
            for c in self.clusters.itervalues():
                res = nvplib.get_all_query_pages(
                    lswitch_url_path_1, c)
                nvp_lswitches.update(dict(
                    (ls['uuid'], ls) for ls in res))
                # Issue a second query for fetching shared networks.
                # We cannot unfortunately use just a single query because tags
                # cannot be or-ed
                res_shared = nvplib.get_all_query_pages(
                    lswitch_url_path_2, c)
                nvp_lswitches.update(dict(
                    (ls['uuid'], ls) for ls in res_shared))
        except Exception:
            err_msg = _("Unable to get logical switches")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)

        if filters.get('id'):
            nvp_lswitches = dict(
                (uuid, ls) for (uuid, ls) in nvp_lswitches.iteritems()
                if uuid in set(filters['id']))

        for quantum_lswitch in quantum_lswitches:
            # Skip external networks as they do not exist in NVP
            if quantum_lswitch[l3.EXTERNAL]:
                continue
            elif quantum_lswitch['id'] not in nvp_lswitches:
                LOG.warning(_("Logical Switch %s found in quantum database "
                              "but not in NVP."), quantum_lswitch["id"])
                quantum_lswitch["status"] = constants.NET_STATUS_ERROR
            else:
                # TODO(salvatore-orlando): be careful about "extended"
                # logical switches
                ls = nvp_lswitches.pop(quantum_lswitch['id'])
                if (ls["_relations"]["LogicalSwitchStatus"]["fabric_status"]):
                    quantum_lswitch["status"] = constants.NET_STATUS_ACTIVE
                else:
                    quantum_lswitch["status"] = constants.NET_STATUS_DOWN

        # do not make the case in which switches are found in NVP
        # but not in Quantum catastrophic.
        if nvp_lswitches:
            LOG.warning(_("Found %s logical switches not bound "
                        "to Quantum networks. Quantum and NVP are "
                        "potentially out of sync"), len(nvp_lswitches))

        LOG.debug(_("get_networks() completed for tenant %s"),
                  context.tenant_id)

        if fields:
            ret_fields = []
            for quantum_lswitch in quantum_lswitches:
                row = {}
                for field in fields:
                    row[field] = quantum_lswitch[field]
                ret_fields.append(row)
            return ret_fields

        return quantum_lswitches

    def update_network(self, context, id, network):
        if network["network"].get("admin_state_up"):
            if network['network']["admin_state_up"] is False:
                raise q_exc.NotImplementedError(_("admin_state_up=False "
                                                  "networks are not "
                                                  "supported."))
        with context.session.begin(subtransactions=True):
            net = super(NvpPluginV2, self).update_network(context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._update_network_security_binding(
                    context, id, network['network'][psec.PORTSECURITY])
            if network['network'].get(ext_qos.QUEUE):
                net[ext_qos.QUEUE] = network['network'][ext_qos.QUEUE]
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context, net)
            self._extend_network_port_security_dict(context, net)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
            self._extend_network_qos_queue(context, net)
        return net

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            quantum_lports = super(NvpPluginV2, self).get_ports(
                context, filters)
            for quantum_lport in quantum_lports:
                self._extend_port_port_security_dict(context, quantum_lport)
                self._extend_port_dict_security_group(context, quantum_lport)
        if (filters.get('network_id') and len(filters.get('network_id')) and
            self._network_is_external(context, filters['network_id'][0])):
            # Do not perform check on NVP platform
            return quantum_lports

        vm_filter = ""
        tenant_filter = ""
        # This is used when calling delete_network. Quantum checks to see if
        # the network has any ports.
        if filters.get("network_id"):
            # FIXME (Aaron) If we get more than one network_id this won't work
            lswitch = filters["network_id"][0]
        else:
            lswitch = "*"

        if filters.get("device_id"):
            for vm_id in filters.get("device_id"):
                vm_filter = ("%stag_scope=vm_id&tag=%s&" % (vm_filter,
                             hashlib.sha1(vm_id).hexdigest()))
        else:
            vm_id = ""

        if filters.get("tenant_id"):
            for tenant in filters.get("tenant_id"):
                tenant_filter = ("%stag_scope=os_tid&tag=%s&" %
                                 (tenant_filter, tenant))

        nvp_lports = {}

        lport_fields_str = ("tags,admin_status_enabled,display_name,"
                            "fabric_status_up")
        try:
            for c in self.clusters.itervalues():
                lport_query_path = (
                    "/ws.v1/lswitch/%s/lport?fields=%s&%s%stag_scope=q_port_id"
                    "&relations=LogicalPortStatus" %
                    (lswitch, lport_fields_str, vm_filter, tenant_filter))

                try:
                    ports = nvplib.get_all_query_pages(lport_query_path, c)
                except q_exc.NotFound:
                    LOG.warn(_("Lswitch %s not found in NVP"), lswitch)
                    ports = None

                if ports:
                    for port in ports:
                        for tag in port["tags"]:
                            if tag["scope"] == "q_port_id":
                                nvp_lports[tag["tag"]] = port

        except Exception:
            err_msg = _("Unable to get ports")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)

        lports = []
        for quantum_lport in quantum_lports:
            # if a quantum port is not found in NVP, this migth be because
            # such port is not mapped to a logical switch - ie: floating ip
            if quantum_lport['device_owner'] in (l3_db.DEVICE_OWNER_FLOATINGIP,
                                                 l3_db.DEVICE_OWNER_ROUTER_GW):
                lports.append(quantum_lport)
                continue
            try:
                quantum_lport["admin_state_up"] = (
                    nvp_lports[quantum_lport["id"]]["admin_status_enabled"])

                if (nvp_lports[quantum_lport["id"]]
                        ["_relations"]
                        ["LogicalPortStatus"]
                        ["fabric_status_up"]):
                    quantum_lport["status"] = constants.PORT_STATUS_ACTIVE
                else:
                    quantum_lport["status"] = constants.PORT_STATUS_DOWN

                del nvp_lports[quantum_lport["id"]]
            except KeyError:
                quantum_lport["status"] = constants.PORT_STATUS_ERROR
                LOG.debug(_("Quantum logical port %s was not found on NVP"),
                          quantum_lport['id'])

            lports.append(quantum_lport)
        # do not make the case in which ports are found in NVP
        # but not in Quantum catastrophic.
        if nvp_lports:
            LOG.warning(_("Found %s logical ports not bound "
                          "to Quantum ports. Quantum and NVP are "
                          "potentially out of sync"), len(nvp_lports))

        if fields:
            ret_fields = []
            for lport in lports:
                row = {}
                for field in fields:
                    row[field] = lport[field]
                ret_fields.append(row)
            return ret_fields
        return lports

    def create_port(self, context, port):
        # If PORTSECURITY is not the default value ATTR_NOT_SPECIFIED
        # then we pass the port to the policy engine. The reason why we don't
        # pass the value to the policy engine when the port is
        # ATTR_NOT_SPECIFIED is for the case where a port is created on a
        # shared network that is not owned by the tenant.
        # TODO(arosen) fix policy engine to do this for us automatically.
        if attr.is_attr_set(port['port'].get(psec.PORTSECURITY)):
            self._enforce_set_auth(context, port,
                                   self.port_security_enabled_create)
        port_data = port['port']
        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            # First we allocate port in quantum database
            quantum_db = super(NvpPluginV2, self).create_port(context, port)
            # Update fields obtained from quantum db (eg: MAC address)
            port["port"].update(quantum_db)
            # metadata_dhcp_host_route
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                quantum_db.get('device_owner') == constants.DEVICE_OWNER_DHCP):
                if (quantum_db.get('fixed_ips') and
                    len(quantum_db['fixed_ips'])):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, quantum_db['fixed_ips'][0])
            # port security extension checks
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, port_data)
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_security_create(context, port_data)
            # security group extension checks
            if port_security and has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif attr.is_attr_set(port_data.get(ext_sg.SECURITYGROUPS)):
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            port_data[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, quantum_db['id'], port_data[ext_sg.SECURITYGROUPS])
            # QoS extension checks
            port_data[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, port_data)
            self._process_port_queue_mapping(context, port_data)
            # provider networking extension checks
            # Fetch the network and network binding from Quantum db
            try:
                port_data = port['port'].copy()
                port_create_func = self._port_drivers['create'].get(
                    port_data['device_owner'],
                    self._port_drivers['create']['default'])

                port_create_func(context, port_data)
            except Exception as e:
                # FIXME (arosen) or the plugin_interface call failed in which
                # case we need to garbage collect the left over port in nvp.
                err_msg = _("Unable to create port or set port attachment "
                            "in NVP.")
                LOG.exception(err_msg)
                raise e

            LOG.debug(_("create_port completed on NVP for tenant "
                        "%(tenant_id)s: (%(id)s)"), port_data)

            # remove since it will be added in extend based on policy
            del port_data[ext_qos.QUEUE]
            self._extend_port_port_security_dict(context, port_data)
            self._extend_port_dict_security_group(context, port_data)
            self._extend_port_qos_queue(context, port_data)
        net = self.get_network(context, port_data['network_id'])
        self.schedule_network(context, net)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, quantum_db['fixed_ips'][0]['subnet_id'])
        return port_data

    def update_port(self, context, id, port):
        if attr.is_attr_set(port['port'].get(psec.PORTSECURITY)):
            self._enforce_set_auth(context, port,
                                   self.port_security_enabled_update)
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(NvpPluginV2, self).update_port(
                context, id, port)
            # copy values over
            ret_port.update(port['port'])
            tenant_id = self._get_tenant_id_for_create(context, ret_port)
            # populate port_security setting
            if psec.PORTSECURITY not in port['port']:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)

            has_ip = self._ip_on_port(ret_port)
            # checks if security groups were updated adding/modifying
            # security groups, port security is set and port has ip
            if not (has_ip and ret_port[psec.PORTSECURITY]):
                if has_security_groups:
                    raise psec.PortSecurityAndIPRequiredForSecurityGroups()
                # Update did not have security groups passed in. Check
                # that port does not have any security groups already on it.
                filters = {'port_id': [id]}
                security_groups = (
                    super(NvpPluginV2, self)._get_port_security_group_bindings(
                        context, filters)
                )
                if security_groups and not delete_security_groups:
                    raise psec.PortSecurityPortHasSecurityGroup()

            if (delete_security_groups or has_security_groups):
                # delete the port binding and read it with the new rules.
                self._delete_port_security_group_bindings(context, id)
                sgids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context, id, sgids)

            if psec.PORTSECURITY in port['port']:
                self._update_port_security_binding(
                    context, id, ret_port[psec.PORTSECURITY])

            ret_port[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, ret_port)
            self._delete_port_queue_mapping(context, ret_port['id'])
            self._process_port_queue_mapping(context, ret_port)
            self._extend_port_port_security_dict(context, ret_port)
            self._extend_port_dict_security_group(context, ret_port)
            LOG.debug(_("Update port request: %s"), port)
            nvp_port_id = self._nvp_get_port_id(
                context, self.default_cluster, ret_port)
            nvplib.update_port(self.default_cluster,
                               ret_port['network_id'],
                               nvp_port_id, id, tenant_id,
                               ret_port['name'], ret_port['device_id'],
                               ret_port['admin_state_up'],
                               ret_port['mac_address'],
                               ret_port['fixed_ips'],
                               ret_port[psec.PORTSECURITY],
                               ret_port[ext_sg.SECURITYGROUPS],
                               ret_port[ext_qos.QUEUE])

            # remove since it will be added in extend based on policy
            del ret_port[ext_qos.QUEUE]
            self._extend_port_qos_queue(context, ret_port)
        # Update the port status from nvp. If we fail here hide it since
        # the port was successfully updated but we were not able to retrieve
        # the status.
        try:
            ret_port['status'] = nvplib.get_port_status(
                self.default_cluster, ret_port['network_id'], nvp_port_id)
        except:
            LOG.warn(_("Unable to retrieve port status for:%s."), nvp_port_id)
        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        quantum_db_port = self.get_port(context, id)
        # Perform the same check for ports owned by layer-2 gateways
        if nw_gw_port_check:
            self.prevent_network_gateway_port_deletion(context,
                                                       quantum_db_port)
        port_delete_func = self._port_drivers['delete'].get(
            quantum_db_port['device_owner'],
            self._port_drivers['delete']['default'])

        port_delete_func(context, quantum_db_port)
        self.disassociate_floatingips(context, id)
        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            queue = self._get_port_queue_bindings(context, {'port_id': [id]})
            # metadata_dhcp_host_route
            port_device_owner = quantum_db_port['device_owner']
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                port_device_owner == constants.DEVICE_OWNER_DHCP):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, quantum_db_port['fixed_ips'][0],
                        is_delete=True)
            super(NvpPluginV2, self).delete_port(context, id)
            # Delete qos queue if possible
            if queue:
                self.delete_qos_queue(context, queue[0]['queue_id'], False)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, quantum_db_port['fixed_ips'][0]['subnet_id'])

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            quantum_db_port = super(NvpPluginV2, self).get_port(context,
                                                                id, fields)
            self._extend_port_port_security_dict(context, quantum_db_port)
            self._extend_port_dict_security_group(context, quantum_db_port)
            self._extend_port_qos_queue(context, quantum_db_port)

            if self._network_is_external(context,
                                         quantum_db_port['network_id']):
                return quantum_db_port
            nvp_id = self._nvp_get_port_id(context, self.default_cluster,
                                           quantum_db_port)
            # If there's no nvp IP do not bother going to NVP and put
            # the port in error state
            if nvp_id:
                #TODO: pass the appropriate cluster here
                try:
                    port = nvplib.get_logical_port_status(
                        self.default_cluster, quantum_db_port['network_id'],
                        nvp_id)
                    quantum_db_port["admin_state_up"] = (
                        port["admin_status_enabled"])
                    if port["fabric_status_up"]:
                        quantum_db_port["status"] = (
                            constants.PORT_STATUS_ACTIVE)
                    else:
                        quantum_db_port["status"] = constants.PORT_STATUS_DOWN
                except q_exc.NotFound:
                    quantum_db_port["status"] = constants.PORT_STATUS_ERROR
            else:
                quantum_db_port["status"] = constants.PORT_STATUS_ERROR
        return quantum_db_port

    def create_router(self, context, router):
        # NOTE(salvatore-orlando): We completely override this method in
        # order to be able to use the NVP ID as Quantum ID
        # TODO(salvatore-orlando): Propose upstream patch for allowing
        # 3rd parties to specify IDs as we do with l2 plugin
        r = router['router']
        has_gw_info = False
        tenant_id = self._get_tenant_id_for_create(context, r)
        # default value to set - nvp wants it (even if we don't have it)
        nexthop = '1.1.1.1'
        try:
            # if external gateway info are set, then configure nexthop to
            # default external gateway
            if 'external_gateway_info' in r and r.get('external_gateway_info'):
                has_gw_info = True
                gw_info = r['external_gateway_info']
                del r['external_gateway_info']
                # The following DB read will be performed again when updating
                # gateway info. This is not great, but still better than
                # creating NVP router here and updating it later
                network_id = (gw_info.get('network_id', None) if gw_info
                              else None)
                if network_id:
                    ext_net = self._get_network(context, network_id)
                    if not self._network_is_external(context, network_id):
                        msg = (_("Network '%s' is not a valid external "
                                 "network") % network_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    if ext_net.subnets:
                        ext_subnet = ext_net.subnets[0]
                        nexthop = ext_subnet.gateway_ip
            cluster = self._find_target_cluster(router)
            lrouter = nvplib.create_lrouter(cluster, tenant_id,
                                            router['router']['name'],
                                            nexthop)
            # Use NVP identfier for Quantum resource
            router['router']['id'] = lrouter['uuid']
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to create logical router on NVP Platform"))
        # Create the port here - and update it later if we have gw_info
        self._create_and_attach_router_port(cluster,
                                            context,
                                            lrouter['uuid'],
                                            {'fake_ext_gw': True},
                                            "L3GatewayAttachment",
                                            cluster.default_l3_gw_service_uuid)

        with context.session.begin(subtransactions=True):
            router_db = l3_db.Router(id=lrouter['uuid'],
                                     tenant_id=tenant_id,
                                     name=r['name'],
                                     admin_state_up=r['admin_state_up'],
                                     status="ACTIVE")
            context.session.add(router_db)
            if has_gw_info:
                self._update_router_gw_info(context, router_db['id'], gw_info)
        return self._make_router_dict(router_db)

    def update_router(self, context, id, router):
        try:
            # Either nexthop is updated or should be kept as it was before
            r = router['router']
            nexthop = None
            if 'external_gateway_info' in r and r.get('external_gateway_info'):
                gw_info = r['external_gateway_info']
                # The following DB read will be performed again when updating
                # gateway info. This is not great, but still better than
                # creating NVP router here and updating it later
                network_id = (gw_info.get('network_id', None) if gw_info
                              else None)
                if network_id:
                    ext_net = self._get_network(context, network_id)
                    if not self._network_is_external(context, network_id):
                        msg = (_("Network '%s' is not a valid external "
                                 "network") % network_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    if ext_net.subnets:
                        ext_subnet = ext_net.subnets[0]
                        nexthop = ext_subnet.gateway_ip
            cluster = self._find_target_cluster(router)
            nvplib.update_lrouter(cluster, id,
                                  router['router'].get('name'), nexthop)
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Logical router %s not found on NVP Platform") % id)
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to update logical router on NVP Platform"))
        return super(NvpPluginV2, self).update_router(context, id, router)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            # Ensure metadata access network is detached and destroyed
            # This will also destroy relevant objects on NVP platform.
            # NOTE(salvatore-orlando): A failure in this operation will
            # cause the router delete operation to fail too.
            self._handle_metadata_access_network(context, id, do_create=False)
            super(NvpPluginV2, self).delete_router(context, id)
            # If removal is successful in Quantum it should be so on
            # the NVP platform too - otherwise the transaction should
            # be automatically aborted
            # TODO(salvatore-orlando): Extend the object models in order to
            # allow an extra field for storing the cluster information
            # together with the resource
            try:
                nvplib.delete_lrouter(self.default_cluster, id)
            except q_exc.NotFound:
                LOG.warning(_("Logical router '%s' not found "
                              "on NVP Platform") % id)
            except NvpApiClient.NvpApiException:
                raise nvp_exc.NvpPluginException(
                    err_msg=(_("Unable to delete logical router"
                               "on NVP Platform")))

    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        try:
            # FIXME(salvatore-orlando): We need to
            # find the appropriate cluster!
            cluster = self.default_cluster
            try:
                lrouter = nvplib.get_lrouter(cluster, id)
            except q_exc.NotFound:
                lrouter = {}
                router_op_status = constants.NET_STATUS_ERROR
            relations = lrouter.get('_relations')
            if relations:
                lrouter_status = relations.get('LogicalRouterStatus')
                # FIXME(salvatore-orlando): Being unable to fetch the
                # logical router status should be an exception.
                if lrouter_status:
                    router_op_status = (lrouter_status.get('fabric_status')
                                        and constants.NET_STATUS_ACTIVE or
                                        constants.NET_STATUS_DOWN)
            if router_op_status != router.status:
                LOG.debug(_("Current router status:%(router_status)s;"
                            "Status in Quantum DB:%(db_router_status)s"),
                          {'router_status': router_op_status,
                           'db_router_status': router.status})
                 # update the router status
                with context.session.begin(subtransactions=True):
                    router.status = router_op_status
        except NvpApiClient.NvpApiException:
            err_msg = _("Unable to get logical router")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)
        return self._make_router_dict(router, fields)

    def get_routers(self, context, filters=None, fields=None):
        router_query = self._apply_filters_to_query(
            self._model_query(context, l3_db.Router),
            l3_db.Router, filters)
        routers = router_query.all()
        # Query routers on NVP for updating operational status
        if context.is_admin and not filters.get("tenant_id"):
            tenant_id = None
        elif 'tenant_id' in filters:
            tenant_id = filters.get('tenant_id')[0]
            del filters['tenant_id']
        else:
            tenant_id = context.tenant_id
        try:
            nvp_lrouters = nvplib.get_lrouters(self.default_cluster,
                                               tenant_id,
                                               fields)
        except NvpApiClient.NvpApiException:
            err_msg = _("Unable to get logical routers from NVP controller")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)

        nvp_lrouters_dict = {}
        for nvp_lrouter in nvp_lrouters:
            nvp_lrouters_dict[nvp_lrouter['uuid']] = nvp_lrouter
        for router in routers:
            nvp_lrouter = nvp_lrouters_dict.get(router['id'])
            if nvp_lrouter:
                if (nvp_lrouter["_relations"]["LogicalRouterStatus"]
                        ["fabric_status"]):
                    router.status = constants.NET_STATUS_ACTIVE
                else:
                    router.status = constants.NET_STATUS_DOWN
                nvp_lrouters.remove(nvp_lrouter)
            else:
                router.status = constants.NET_STATUS_ERROR

        # do not make the case in which routers are found in NVP
        # but not in Quantum catastrophic.
        if nvp_lrouters:
            LOG.warning(_("Found %s logical routers not bound "
                          "to Quantum routers. Quantum and NVP are "
                          "potentially out of sync"), len(nvp_lrouters))

        return [self._make_router_dict(router, fields)
                for router in routers]

    def add_router_interface(self, context, router_id, interface_info):
        router_iface_info = super(NvpPluginV2, self).add_router_interface(
            context, router_id, interface_info)
        # If the above operation succeded interface_info contains a reference
        # to a logical switch port
        port_id = router_iface_info['port_id']
        subnet_id = router_iface_info['subnet_id']
        # Add port to the logical router as well
        # TODO(salvatore-orlando): Identify the appropriate cluster, instead
        # of always defaulting to self.default_cluster
        cluster = self.default_cluster
        # The owner of the router port is always the same as the owner of the
        # router. Use tenant_id from the port instead of fetching more records
        # from the Quantum database
        port = self._get_port(context, port_id)
        # Find the NVP port corresponding to quantum port_id
        results = nvplib.query_lswitch_lports(
            cluster, '*',
            filters={'tag': port_id, 'tag_scope': 'q_port_id'})
        if results:
            ls_port = results[0]
        else:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("The port %(port_id)s, connected to the router "
                           "%(router_id)s was not found on the NVP backend.")
                         % locals()))

        # Create logical router port and patch attachment
        self._create_and_attach_router_port(
            cluster, context, router_id, port,
            "PatchAttachment", ls_port['uuid'],
            subnet_ids=[subnet_id])
        subnet = self._get_subnet(context, subnet_id)
        # If there is an external gateway we need to configure the SNAT rule.
        # Fetch router from DB
        router = self._get_router(context, router_id)
        gw_port = router.gw_port
        if gw_port:
            # There is a change gw_port might have multiple IPs
            # In that case we will consider only the first one
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                nvplib.create_lrouter_snat_rule(
                    cluster, router_id, snat_ip, snat_ip,
                    order=NVP_EXTGW_NAT_RULES_ORDER,
                    match_criteria={'source_ip_addresses': subnet['cidr']})
        nvplib.create_lrouter_nosnat_rule(
            cluster, router_id,
            order=NVP_NOSNAT_RULES_ORDER,
            match_criteria={'destination_ip_addresses': subnet['cidr']})

        # Ensure the NVP logical router has a connection to a 'metadata access'
        # network (with a proxy listening on its DHCP port), by creating it
        # if needed.
        self._handle_metadata_access_network(context, router_id)
        LOG.debug(_("Add_router_interface completed for subnet:%(subnet_id)s "
                    "and router:%(router_id)s"),
                  {'subnet_id': subnet_id, 'router_id': router_id})
        return router_iface_info

    def remove_router_interface(self, context, router_id, interface_info):
        # TODO(salvatore-orlando): Usual thing about cluster selection
        cluster = self.default_cluster
        # The code below is duplicated from base class, but comes handy
        # as we need to retrieve the router port id before removing the port
        subnet = None
        subnet_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
            if not (port['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF and
                    port['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id']).all()
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)
        results = nvplib.query_lswitch_lports(
            cluster, '*', relations="LogicalPortAttachment",
            filters={'tag': port_id, 'tag_scope': 'q_port_id'})
        lrouter_port_id = None
        if results:
            lport = results[0]
            attachment_data = lport['_relations'].get('LogicalPortAttachment')
            lrouter_port_id = (attachment_data and
                               attachment_data.get('peer_port_uuid'))
        else:
            LOG.warning(_("The port %(port_id)s, connected to the router "
                          "%(router_id)s was not found on the NVP backend"),
                        locals())
        # Finally remove the data from the Quantum DB
        # This will also destroy the port on the logical switch
        super(NvpPluginV2, self).remove_router_interface(context,
                                                         router_id,
                                                         interface_info)
        # Destroy router port (no need to unplug the attachment)
        # FIXME(salvatore-orlando): In case of failures in the Quantum plugin
        # this migth leave a dangling port. We perform the operation here
        # to leverage validation performed in the base class
        if not lrouter_port_id:
            LOG.warning(_("Unable to find NVP logical router port for "
                          "Quantum port id:%s. Was this port ever paired "
                          "with a logical router?"), port_id)
            return

        # Ensure the connection to the 'metadata access network'
        # is removed  (with the network) if this the last subnet
        # on the router
        self._handle_metadata_access_network(context, router_id)
        try:
            if not subnet:
                subnet = self._get_subnet(context, subnet_id)
            router = self._get_router(context, router_id)
            # Remove SNAT rule if external gateway is configured
            if router.gw_port:
                nvplib.delete_nat_rules_by_match(
                    cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=subnet['cidr'])
            # Relax the minimum expected number as the nosnat rules
            # do not exist in 2.x deployments
            nvplib.delete_nat_rules_by_match(
                cluster, router_id, "NoSourceNatRule",
                max_num_expected=1, min_num_expected=0,
                destination_ip_addresses=subnet['cidr'])
            nvplib.delete_router_lport(cluster, router_id, lrouter_port_id)
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Logical router port resource %s not found "
                           "on NVP platform"), lrouter_port_id))
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to update logical router"
                           "on NVP Platform")))

    def _retrieve_and_delete_nat_rules(self, floating_ip_address,
                                       internal_ip, router_id,
                                       min_num_rules_expected=0):
        #TODO(salvatore-orlando): Multiple cluster support
        cluster = self.default_cluster
        try:
            nvplib.delete_nat_rules_by_match(
                cluster, router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)

            # Remove SNAT rule associated with the single fixed_ip
            # to floating ip
            nvplib.delete_nat_rules_by_match(
                cluster, router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                source_ip_addresses=internal_ip)
        except NvpApiClient.NvpApiException:
            LOG.exception(_("An error occurred while removing NAT rules "
                            "on the NVP platform for floating ip:%s"),
                          floating_ip_address)
            raise
        except nvp_exc.NvpNatRuleMismatch:
            # Do not surface to the user
            LOG.warning(_("An incorrect number of matching NAT rules "
                          "was found on the NVP platform"))

    def _remove_floatingip_address(self, context, fip_db):
        # Remove floating IP address from logical router port
        # Fetch logical port of router's external gateway
        router_id = fip_db.router_id
        nvp_gw_port_id = nvplib.find_router_gw_port(
            context, self.default_cluster, router_id)['uuid']
        ext_quantum_port_db = self._get_port(context.elevated(),
                                             fip_db.floating_port_id)
        nvp_floating_ips = self._build_ip_address_list(
            context.elevated(), ext_quantum_port_db['fixed_ips'])
        nvplib.update_lrouter_port_ips(self.default_cluster,
                                       router_id,
                                       nvp_gw_port_id,
                                       ips_to_add=[],
                                       ips_to_remove=nvp_floating_ips)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        """ Update floating IP association data.

        Overrides method from base class.
        The method is augmented for creating NAT rules in the process.
        """
        if (('fixed_ip_address' in fip and fip['fixed_ip_address']) and
            not ('port_id' in fip and fip['port_id'])):
            msg = _("fixed_ip_address cannot be specified without a port_id")
            raise q_exc.BadRequest(resource='floatingip', msg=msg)
        port_id = internal_ip = router_id = None
        if 'port_id' in fip and fip['port_id']:
            port_qry = context.session.query(l3_db.FloatingIP)
            try:
                port_qry.filter_by(fixed_port_id=fip['port_id']).one()
                raise l3.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'],
                    fip_id=floatingip_db['id'],
                    floating_ip_address=floatingip_db['floating_ip_address'],
                    fixed_ip=floatingip_db['fixed_ip_address'],
                    net_id=floatingip_db['floating_network_id'])
            except sa_exc.NoResultFound:
                pass
            port_id, internal_ip, router_id = self.get_assoc_data(
                context,
                fip,
                floatingip_db['floating_network_id'])

        cluster = self._find_target_cluster(fip)
        floating_ip = floatingip_db['floating_ip_address']
        # Retrieve and delete existing NAT rules, if any
        if not router_id and floatingip_db.get('fixed_port_id'):
            # This happens if we're disassociating. Need to explicitly
            # find the router serving this floating IP
            tmp_fip = fip.copy()
            tmp_fip['port_id'] = floatingip_db['fixed_port_id']
            _pid, internal_ip, router_id = self.get_assoc_data(
                context, tmp_fip, floatingip_db['floating_network_id'])
        # If there's no association router_id will be None
        if router_id:
            self._retrieve_and_delete_nat_rules(floating_ip,
                                                internal_ip,
                                                router_id)
            # Fetch logical port of router's external gateway
            nvp_gw_port_id = nvplib.find_router_gw_port(
                context, self.default_cluster, router_id)['uuid']
            nvp_floating_ips = self._build_ip_address_list(
                context.elevated(), external_port['fixed_ips'])
            LOG.debug(_("Address list for NVP logical router "
                        "port:%s"), nvp_floating_ips)
            # Re-create NAT rules only if a port id is specified
            if 'port_id' in fip and fip['port_id']:
                try:
                    # Create new NAT rules
                    nvplib.create_lrouter_dnat_rule(
                        cluster, router_id, internal_ip,
                        order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'destination_ip_addresses':
                                        floating_ip})
                    # setup snat rule such that src ip of a IP packet when
                    #  using floating is the floating ip itself.
                    nvplib.create_lrouter_snat_rule(
                        cluster, router_id, floating_ip, floating_ip,
                        order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'source_ip_addresses': internal_ip})
                    # Add Floating IP address to router_port
                    nvplib.update_lrouter_port_ips(cluster,
                                                   router_id,
                                                   nvp_gw_port_id,
                                                   ips_to_add=nvp_floating_ips,
                                                   ips_to_remove=[])
                except NvpApiClient.NvpApiException:
                    LOG.exception(_("An error occurred while creating NAT "
                                    "rules on the NVP platform for floating "
                                    "ip:%(floating_ip)s mapped to "
                                    "internal ip:%(internal_ip)s"),
                                  {'floating_ip': floating_ip,
                                   'internal_ip': internal_ip})
                    raise nvp_exc.NvpPluginException(err_msg=msg)
            elif floatingip_db['fixed_port_id']:
                # This is a disassociation.
                # Remove floating IP address from logical router port
                nvplib.update_lrouter_port_ips(cluster,
                                               router_id,
                                               nvp_gw_port_id,
                                               ips_to_add=[],
                                               ips_to_remove=nvp_floating_ips)

        floatingip_db.update({'fixed_ip_address': internal_ip,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        # Check whether the floating ip is associated or not
        if fip_db.fixed_port_id:
            self._retrieve_and_delete_nat_rules(fip_db.floating_ip_address,
                                                fip_db.fixed_ip_address,
                                                fip_db.router_id,
                                                min_num_rules_expected=1)
            # Remove floating IP address from logical router port
            self._remove_floatingip_address(context, fip_db)
        return super(NvpPluginV2, self).delete_floatingip(context, id)

    def disassociate_floatingips(self, context, port_id):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id).one()
            self._retrieve_and_delete_nat_rules(fip_db.floating_ip_address,
                                                fip_db.fixed_ip_address,
                                                fip_db.router_id,
                                                min_num_rules_expected=1)
            self._remove_floatingip_address(context, fip_db)
        except sa_exc.NoResultFound:
            LOG.debug(_("The port '%s' is not associated with floating IPs"),
                      port_id)
        super(NvpPluginV2, self).disassociate_floatingips(context, port_id)

    def create_network_gateway(self, context, network_gateway):
        """ Create a layer-2 network gateway

        Create the gateway service on NVP platform and corresponding data
        structures in Quantum datase
        """
        # Need to re-do authZ checks here in order to avoid creation on NVP
        gw_data = network_gateway[networkgw.RESOURCE_NAME.replace('-', '_')]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        cluster = self._find_target_cluster(gw_data)
        devices = gw_data['devices']
        # Populate default physical network where not specified
        for device in devices:
            if not device.get('interface_name'):
                device['interface_name'] = cluster.default_interface_name
        try:
            nvp_res = nvplib.create_l2_gw_service(cluster, tenant_id,
                                                  gw_data['name'],
                                                  devices)
            nvp_uuid = nvp_res.get('uuid')
        except Exception:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Create_l2_gw_service did not "
                          "return an uuid for the newly "
                          "created resource:%s") % nvp_res)
        gw_data['id'] = nvp_uuid
        return super(NvpPluginV2, self).create_network_gateway(context,
                                                               network_gateway)

    def delete_network_gateway(self, context, id):
        """ Remove a layer-2 network gateway

        Remove the gateway service from NVP platform and corresponding data
        structures in Quantum datase
        """
        with context.session.begin(subtransactions=True):
            try:
                super(NvpPluginV2, self).delete_network_gateway(context, id)
                nvplib.delete_l2_gw_service(self.default_cluster, id)
            except NvpApiClient.ResourceNotFound:
                # Do not cause a 500 to be returned to the user if
                # the corresponding NVP resource does not exist
                LOG.exception(_("Unable to remove gateway service from "
                                "NVP plaform - the resource was not found"))

    def _ensure_tenant_on_net_gateway(self, context, net_gateway):
        if not net_gateway['tenant_id']:
            net_gateway['tenant_id'] = context.tenant_id
        return net_gateway

    def get_network_gateway(self, context, id, fields=None):
        # Ensure the tenant_id attribute is populated on the returned gateway
        #return self._ensure_tenant_on_net_gateway(
        #    context, super(NvpPluginV2, self).get_network_gateway(
        #        context, id, fields))
        return super(NvpPluginV2, self).get_network_gateway(context,
                                                            id, fields)

    def get_network_gateways(self, context, filters=None, fields=None):
        # Ensure the tenant_id attribute is populated on returned gateways
        net_gateways = super(NvpPluginV2,
                             self).get_network_gateways(context,
                                                        filters,
                                                        fields)
        return net_gateways

    def get_plugin_version(self):
        return PLUGIN_VERSION

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.
        If default_sg is true that means a we are creating a default security
        group and we don't need to check if one exists.
        """
        s = security_group.get('security_group')

        tenant_id = self._get_tenant_id_for_create(context, s)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        nvp_secgroup = nvplib.create_security_profile(self.default_cluster,
                                                      tenant_id, s)
        security_group['security_group']['id'] = nvp_secgroup['uuid']
        return super(NvpPluginV2, self).create_security_group(
            context, security_group, default_sg)

    def delete_security_group(self, context, security_group_id):
        """Delete a security group
        :param security_group_id: security group rule to remove.
        """
        with context.session.begin(subtransactions=True):
            security_group = super(NvpPluginV2, self).get_security_group(
                context, security_group_id)
            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)

            if security_group['name'] == 'default':
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            filters = {'security_group_id': [security_group['id']]}
            if super(NvpPluginV2, self)._get_port_security_group_bindings(
                context, filters):
                raise ext_sg.SecurityGroupInUse(id=security_group['id'])
            nvplib.delete_security_profile(self.default_cluster,
                                           security_group['id'])
            return super(NvpPluginV2, self).delete_security_group(
                context, security_group_id)

    def create_security_group_rule(self, context, security_group_rule):
        """create a single security group rule"""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """ create security group rules
        :param security_group_rule: list of rules to create
        """
        s = security_group_rule.get('security_group_rules')
        tenant_id = self._get_tenant_id_for_create(context, s)

        # TODO(arosen) is there anyway we could avoid having the update of
        # the security group rules in nvp outside of this transaction?
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(context, tenant_id)
            security_group_id = self._validate_security_group_rules(
                context, security_group_rule)

            # Check to make sure security group exists
            security_group = super(NvpPluginV2, self).get_security_group(
                context, security_group_id)

            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)
            # Check for duplicate rules
            self._check_for_duplicate_rules(context, s)
            # gather all the existing security group rules since we need all
            # of them to PUT to NVP.
            combined_rules = self._merge_security_group_rules_with_current(
                context, s, security_group['id'])
            nvplib.update_security_group_rules(self.default_cluster,
                                               security_group['id'],
                                               combined_rules)
            return super(
                NvpPluginV2, self).create_security_group_rule_bulk_native(
                    context, security_group_rule)

    def delete_security_group_rule(self, context, sgrid):
        """ Delete a security group rule
        :param sgrid: security group id to remove.
        """
        with context.session.begin(subtransactions=True):
            # determine security profile id
            security_group_rule = (
                super(NvpPluginV2, self).get_security_group_rule(
                    context, sgrid))
            if not security_group_rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sgrid)

            sgid = security_group_rule['security_group_id']
            current_rules = self._get_security_group_rules_nvp_format(
                context, sgid, True)

            self._remove_security_group_with_id_and_id_field(
                current_rules, sgrid)
            nvplib.update_security_group_rules(
                self.default_cluster, sgid, current_rules)
            return super(NvpPluginV2, self).delete_security_group_rule(context,
                                                                       sgrid)

    def create_qos_queue(self, context, qos_queue, check_policy=True):
        q = qos_queue.get('qos_queue')
        if check_policy:
            self._enforce_set_auth(context, q, ext_qos.qos_queue_create)
        self._validate_qos_queue(context, q)
        q['id'] = nvplib.create_lqueue(self.default_cluster,
                                       self._nvp_lqueue(q))
        return super(NvpPluginV2, self).create_qos_queue(context, qos_queue)

    def delete_qos_queue(self, context, id, raise_in_use=True):
        filters = {'queue_id': [id]}
        queues = self._get_port_queue_bindings(context, filters)
        if queues:
            if raise_in_use:
                raise ext_qos.QueueInUseByPort()
            else:
                return
        nvplib.delete_lqueue(self.default_cluster, id)
        return super(NvpPluginV2, self).delete_qos_queue(context, id)

    def get_qos_queue(self, context, id, fields=None):
        if not self._check_view_auth(context, {}, ext_qos.qos_queue_get):
            # don't want the user to find out that they guessed the right id
            # so  we raise not found if the policy.json file doesn't allow them
            raise ext_qos.QueueNotFound(id=id)

        return super(NvpPluginV2, self).get_qos_queue(context, id, fields)

    def get_qos_queues(self, context, filters=None, fields=None):
        if not self._check_view_auth(context, {'qos_queue': []},
                                     ext_qos.qos_queue_list):
            return []
        return super(NvpPluginV2, self).get_qos_queues(context, filters,
                                                       fields)
