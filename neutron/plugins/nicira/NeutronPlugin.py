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
import os

from oslo.config import cfg
from sqlalchemy.orm import exc as sa_exc
import webob.exc

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context as q_context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import rpc
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import metadata_access as nvp_meta
from neutron.plugins.nicira.common import securitygroups as nvp_sec
from neutron.plugins.nicira.dbexts import maclearning as mac_db
from neutron.plugins.nicira.dbexts import nicira_db
from neutron.plugins.nicira.dbexts import nicira_networkgw_db as networkgw_db
from neutron.plugins.nicira.dbexts import nicira_qos_db as qos_db
from neutron.plugins.nicira.extensions import maclearning as mac_ext
from neutron.plugins.nicira.extensions import nvp_networkgw as networkgw
from neutron.plugins.nicira.extensions import nvp_qos as ext_qos
from neutron.plugins.nicira import nvp_cluster
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib


LOG = logging.getLogger("NeutronPlugin")

NVP_NOSNAT_RULES_ORDER = 10
NVP_FLOATINGIP_NAT_RULES_ORDER = 224
NVP_EXTGW_NAT_RULES_ORDER = 255
NVP_EXT_PATH = os.path.join(os.path.dirname(__file__), 'extensions')


# Provider network extension - allowed network types for the NVP Plugin
class NetworkTypes:
    """Allowed provider network types for the NVP Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'


def create_nvp_cluster(cluster_opts, concurrent_connections,
                       nvp_gen_timeout):
    # NOTE(armando-migliaccio): remove this block once we no longer
    # want to support deprecated options in the nvp config file
    # ### BEGIN
    config.register_deprecated(cfg.CONF)
    # ### END
    cluster = nvp_cluster.NVPCluster(**cluster_opts)
    api_providers = [ctrl.split(':') + [True]
                     for ctrl in cluster.nvp_controllers]
    cluster.api_client = NvpApiClient.NVPApiHelper(
        api_providers, cluster.nvp_user, cluster.nvp_password,
        request_timeout=cluster.req_timeout,
        http_timeout=cluster.http_timeout,
        retries=cluster.retries,
        redirects=cluster.redirects,
        concurrent_connections=concurrent_connections,
        nvp_gen_timeout=nvp_gen_timeout)
    return cluster


class NVPRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class NvpPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  mac_db.MacLearningDbMixin,
                  networkgw_db.NetworkGatewayMixin,
                  qos_db.NVPQoSDbMixin,
                  nvp_sec.NVPSecurityGroups,
                  nvp_meta.NvpMetadataAccess,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin):
    """L2 Virtual network plugin.

    NvpPluginV2 is a Neutron plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    supported_extension_aliases = ["agent",
                                   "binding",
                                   "dhcp_agent_scheduler",
                                   "ext-gw-mode",
                                   "extraroute",
                                   "mac-learning",
                                   "network-gateway",
                                   "nvp-qos",
                                   "port-security",
                                   "provider",
                                   "quotas",
                                   "router",
                                   "security-group", ]

    __native_bulk_support = True

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}

    def __init__(self):

        # Routines for managing logical ports in NVP
        self._port_drivers = {
            'create': {l3_db.DEVICE_OWNER_ROUTER_GW:
                       self._nvp_create_ext_gw_port,
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
                       networkgw_db.DEVICE_OWNER_NET_GW_INTF:
                       self._nvp_delete_port,
                       'default': self._nvp_delete_port}
        }

        # If no api_extensions_path is provided set the following
        if not cfg.CONF.api_extensions_path:
            cfg.CONF.set_override('api_extensions_path', NVP_EXT_PATH)
        self.nvp_opts = cfg.CONF.NVP
        self.cluster = create_nvp_cluster(cfg.CONF,
                                          self.nvp_opts.concurrent_connections,
                                          self.nvp_opts.nvp_gen_timeout)

        self.extra_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_OVS,
            pbin.CAPABILITIES: {
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}

        db.configure_db()
        # Extend the fault map
        self._extend_fault_map()
        # Set up RPC interface for DHCP agent
        self.setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        # Set this flag to false as the default gateway has not
        # been yet updated from the config file
        self._is_default_net_gw_in_sync = False

    def _ensure_default_network_gateway(self):
        if self._is_default_net_gw_in_sync:
            return
        # Add the gw in the db as default, and unset any previous default
        def_l2_gw_uuid = self.cluster.default_l2_gw_service_uuid
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
            # Ensure this method is executed only once
            self._is_default_net_gw_in_sync = True
        except Exception:
            LOG.exception(_("Unable to process default l2 gw service:%s"),
                          def_l2_gw_uuid)
            raise

    def _build_ip_address_list(self, context, fixed_ips, subnet_ids=None):
        """Build ip_addresses data structure for logical router port.

        No need to perform validation on IPs - this has already been
        done in the l3_db mixin class.
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
                err_msg=_("Unable to create logical router port for neutron "
                          "port id %(port_id)s on router %(router_id)s") %
                {'port_id': port_data.get('id'), 'router_id': router_id})
        self._update_router_port_attachment(cluster, context, router_id,
                                            port_data, lrouter_port['uuid'],
                                            attachment_type, attachment,
                                            attachment_vlan)
        return lrouter_port

    def _update_router_gw_info(self, context, router_id, info):
        # NOTE(salvatore-orlando): We need to worry about rollback of NVP
        # configuration in case of failures in the process
        # Ref. LP bug 1102301
        router = self._get_router(context, router_id)
        # Check whether SNAT rule update should be triggered
        # NVP also supports multiple external networks so there is also
        # the possibility that NAT rules should be replaced
        current_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_ext_net_id = info and info.get('network_id')
        # SNAT should be enabled unless info['enable_snat'] is
        # explicitly set to false
        enable_snat = new_ext_net_id and info.get('enable_snat', True)
        # Remove if ext net removed, changed, or if snat disabled
        remove_snat_rules = (current_ext_net_id and
                             new_ext_net_id != current_ext_net_id or
                             router.enable_snat and not enable_snat)
        # Add rules if snat is enabled, and if either the external network
        # changed or snat was previously disabled
        # NOTE: enable_snat == True implies new_ext_net_id != None
        add_snat_rules = (enable_snat and
                          (new_ext_net_id != current_ext_net_id or
                           not router.enable_snat))
        router = super(NvpPluginV2, self)._update_router_gw_info(
            context, router_id, info, router=router)
        # Add/Remove SNAT rules as needed
        # Create an elevated context for dealing with metadata access
        # cidrs which are created within admin context
        ctx_elevated = context.elevated()
        if remove_snat_rules or add_snat_rules:
            cidrs = self._find_router_subnets_cidrs(ctx_elevated, router_id)
        if remove_snat_rules:
            # Be safe and concede NAT rules might not exist.
            # Therefore use min_num_expected=0
            for cidr in cidrs:
                nvplib.delete_nat_rules_by_match(
                    self.cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=0,
                    source_ip_addresses=cidr)
        if add_snat_rules:
            ip_addresses = self._build_ip_address_list(
                ctx_elevated, router.gw_port['fixed_ips'])
            # Set the SNAT rule for each subnet (only first IP)
            for cidr in cidrs:
                cidr_prefix = int(cidr.split('/')[1])
                nvplib.create_lrouter_snat_rule(
                    self.cluster, router_id,
                    ip_addresses[0].split('/')[0],
                    ip_addresses[0].split('/')[0],
                    order=NVP_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                    match_criteria={'source_ip_addresses': cidr})

    def _update_router_port_attachment(self, cluster, context,
                                       router_id, port_data,
                                       nvp_router_port_id,
                                       attachment_type,
                                       attachment,
                                       attachment_vlan=None):
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
                            "Neutron %(q_port_id)s"),
                          {'r_port_id': nvp_router_port_id,
                           'q_port_id': port_data.get('id')})
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to plug attachment in router port "
                           "%(r_port_id)s for neutron port id %(q_port_id)s "
                           "on router %(router_id)s") %
                         {'r_port_id': nvp_router_port_id,
                          'q_port_id': port_data.get('id'),
                          'router_id': router_id}))

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """Retrieve ports associated with a specific device id.

        Used for retrieving all neutron ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """Retrieve subnets attached to the specified router."""
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
            return self._handle_lswitch_selection(self.cluster, network,
                                                  network_binding, max_ports,
                                                  allow_extra_lswitches)
        except NvpApiClient.NvpApiException:
            err_desc = _("An exception occured while selecting logical "
                         "switch for the port")
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
                                   port_data[ext_qos.QUEUE],
                                   port_data.get(mac_ext.MAC_LEARNING))

    def _handle_create_port_exception(self, context, port_id,
                                      ls_uuid, lp_uuid):
        with excutils.save_and_reraise_exception():
            # rollback nvp logical port only if it was successfully
            # created on NVP. Should this command fail the original
            # exception will be raised.
            if lp_uuid:
                # Remove orphaned port from NVP
                nvplib.delete_port(self.cluster, ls_uuid, lp_uuid)
            # rollback the neutron-nvp port mapping
            nicira_db.delete_neutron_nvp_port_mapping(context.session,
                                                      port_id)
            msg = (_("An exception occured while creating the "
                     "quantum port %s on the NVP plaform") % port_id)
            LOG.exception(msg)

    def _nvp_create_port(self, context, port_data):
        """Driver for creating a logical switch port on NVP platform."""
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
        lport = None
        selected_lswitch = None
        try:
            selected_lswitch = self._nvp_find_lswitch_for_port(context,
                                                               port_data)
            lport = self._nvp_create_port_helper(self.cluster,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 True)
            nicira_db.add_neutron_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            if (not port_data['device_owner'] in
                (l3_db.DEVICE_OWNER_ROUTER_GW,
                 l3_db.DEVICE_OWNER_ROUTER_INTF)):
                nvplib.plug_interface(self.cluster, selected_lswitch['uuid'],
                                      lport['uuid'], "VifAttachment",
                                      port_data['id'])
            LOG.debug(_("_nvp_create_port completed for port %(name)s "
                        "on network %(network_id)s. The new port id is "
                        "%(id)s."), port_data)
        except (NvpApiClient.NvpApiException, q_exc.NeutronException):
            self._handle_create_port_exception(
                context, port_data['id'],
                selected_lswitch and selected_lswitch['uuid'],
                lport and lport['uuid'])

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
        nvp_port_id = self._nvp_get_port_id(context, self.cluster,
                                            port_data)
        if not nvp_port_id:
            LOG.debug(_("Port '%s' was already deleted on NVP platform"), id)
            return
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        try:
            nvplib.delete_port(self.cluster,
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
        nvp_port_id = self._nvp_get_port_id(context, self.cluster,
                                            port_data)
        if not nvp_port_id:
            raise q_exc.PortNotFound(port_id=port_data['id'])

        try:
            nvplib.delete_peer_router_lport(self.cluster,
                                            lrouter_id,
                                            port_data['network_id'],
                                            nvp_port_id)
        except NvpApiClient.NvpApiException:
            # Do not raise because the issue might as well be that the
            # router has already been deleted, so there would be nothing
            # to do here
            LOG.exception(_("Ignoring exception as this means the peer "
                            "for port '%s' has already been deleted."),
                          nvp_port_id)

        # Delete logical switch port
        self._nvp_delete_port(context, port_data)

    def _nvp_create_router_port(self, context, port_data):
        """Driver for creating a switch port to be connected to a router."""
        # No router ports on external networks!
        if self._network_is_external(context, port_data['network_id']):
            raise nvp_exc.NvpPluginException(
                err_msg=(_("It is not allowed to create router interface "
                           "ports on external networks as '%s'") %
                         port_data['network_id']))
        ls_port = None
        selected_lswitch = None
        try:
            selected_lswitch = self._nvp_find_lswitch_for_port(
                context, port_data)
            # Do not apply port security here!
            ls_port = self._nvp_create_port_helper(
                self.cluster, selected_lswitch['uuid'],
                port_data, False)
            # Assuming subnet being attached is on first fixed ip
            # element in port data
            subnet_id = port_data['fixed_ips'][0]['subnet_id']
            router_id = port_data['device_id']
            # Create peer port on logical router
            self._create_and_attach_router_port(
                self.cluster, context, router_id, port_data,
                "PatchAttachment", ls_port['uuid'],
                subnet_ids=[subnet_id])
            nicira_db.add_neutron_nvp_port_mapping(
                context.session, port_data['id'], ls_port['uuid'])
            LOG.debug(_("_nvp_create_router_port completed for port "
                        "%(name)s on network %(network_id)s. The new "
                        "port id is %(id)s."),
                      port_data)
        except (NvpApiClient.NvpApiException, q_exc.NeutronException):
            self._handle_create_port_exception(
                context, port_data['id'],
                selected_lswitch and selected_lswitch['uuid'],
                ls_port and ls_port['uuid'])

    def _find_router_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        if not router_id:
            raise q_exc.BadRequest(_("device_id field must be populated in "
                                   "order to create an external gateway "
                                   "port for network %s"),
                                   port_data['network_id'])

        lr_port = nvplib.find_router_gw_port(context, self.cluster, router_id)
        if not lr_port:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("The gateway port for the router %s "
                           "was not found on the NVP backend")
                         % router_id))
        return lr_port

    def _nvp_create_ext_gw_port(self, context, port_data):
        """Driver for creating an external gateway port on NVP platform."""
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
        # regardless of what the user specifies in neutron
        router_id = port_data['device_id']
        nvplib.update_router_lport(self.cluster,
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
                self.cluster, context, router_id, port_data,
                lr_port['uuid'],
                "L3GatewayAttachment",
                ext_network[pnet.PHYSICAL_NETWORK],
                ext_network[pnet.SEGMENTATION_ID])

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
            router_id = port_data['device_id']
            nvplib.update_router_lport(self.cluster,
                                       router_id,
                                       lr_port['uuid'],
                                       port_data['tenant_id'],
                                       port_data['id'],
                                       port_data['name'],
                                       True,
                                       ['0.0.0.0/31'])
            # Reset attachment
            self._update_router_port_attachment(
                self.cluster, context, router_id, port_data,
                lr_port['uuid'],
                "L3GatewayAttachment",
                self.cluster.default_l3_gw_service_uuid)

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
        """Create a switch port, and attach it to a L2 gateway attachment."""
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
        lport = None
        try:
            selected_lswitch = self._nvp_find_lswitch_for_port(
                context, port_data)
            lport = self._nvp_create_port_helper(
                self.cluster,
                selected_lswitch['uuid'],
                port_data,
                True)
            nicira_db.add_neutron_nvp_port_mapping(
                context.session, port_data['id'], lport['uuid'])
            nvplib.plug_l2_gw_service(
                self.cluster,
                port_data['network_id'],
                lport['uuid'],
                port_data['device_id'],
                int(port_data.get('gw:segmentation_id') or 0))
        except Exception:
            with excutils.save_and_reraise_exception():
                if lport:
                    nvplib.delete_port(self.cluster,
                                       selected_lswitch['uuid'],
                                       lport['uuid'])
        LOG.debug(_("_nvp_create_l2_gw_port completed for port %(name)s "
                    "on network %(network_id)s. The new port id "
                    "is %(id)s."), port_data)

    def _nvp_create_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _nvp_delete_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NVP,
        # this is a no-op driver
        pass

    def _nvp_get_port_id(self, context, cluster, neutron_port):
        """Return the NVP port uuid for a given neutron port.

        First, look up the Neutron database. If not found, execute
        a query on NVP platform as the mapping might be missing because
        the port was created before upgrading to grizzly.
        """
        nvp_port_id = nicira_db.get_nvp_port_id(context.session,
                                                neutron_port['id'])
        if nvp_port_id:
            return nvp_port_id
        # Perform a query to NVP and then update the DB
        try:
            nvp_port = nvplib.get_port_by_neutron_tag(
                cluster,
                neutron_port['network_id'],
                neutron_port['id'])
            if nvp_port:
                nicira_db.add_neutron_nvp_port_mapping(
                    context.session,
                    neutron_port['id'],
                    nvp_port['uuid'])
                return nvp_port['uuid']
        except Exception:
            LOG.exception(_("Unable to find NVP uuid for Neutron port %s"),
                          neutron_port['id'])

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NVP Plugin are mapped to standard
        HTTP Exceptions.
        """
        base.FAULT_MAP.update({nvp_exc.NvpInvalidNovaZone:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpNoMorePortsException:
                               webob.exc.HTTPBadRequest})

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
                  not utils.is_valid_vlan_tag(segmentation_id)):
                err_msg = (_("%(segmentation_id)s out of range "
                             "(%(min_id)s through %(max_id)s)") %
                           {'segmentation_id': segmentation_id,
                            'min_id': constants.MIN_VLAN_TAG,
                            'max_id': constants.MAX_VLAN_TAG})
            else:
                # Verify segment is not already allocated
                binding = nicira_db.get_network_binding_by_vlanid(
                    context.session, segmentation_id)
                if binding:
                    raise q_exc.VlanIdInUse(vlan_id=segmentation_id,
                                            physical_network=physical_network)
        elif network_type == NetworkTypes.L3_EXT:
            if (segmentation_id_set and
                not utils.is_valid_vlan_tag(segmentation_id)):
                err_msg = (_("%(segmentation_id)s out of range "
                             "(%(min_id)s through %(max_id)s)") %
                           {'segmentation_id': segmentation_id,
                            'min_id': constants.MIN_VLAN_TAG,
                            'max_id': constants.MAX_VLAN_TAG})
        else:
            err_msg = _("%(net_type_param)s %(net_type_value)s not "
                        "supported") % {'net_type_param': pnet.NETWORK_TYPE,
                                        'net_type_value': network_type}
        if err_msg:
            raise q_exc.InvalidInput(error_message=err_msg)
        # TODO(salvatore-orlando): Validate tranport zone uuid
        # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network, binding=None):
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
            # TODO(salvatore-orlando) find main_ls too!
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
        self.agent_notifiers[constants.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

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
        external = net_data.get(l3.EXTERNAL)
        if (not attr.is_attr_set(external) or
            attr.is_attr_set(external) and not external):
            nvp_binding_type = net_data.get(pnet.NETWORK_TYPE)
            if nvp_binding_type in ('flat', 'vlan'):
                nvp_binding_type = 'bridge'
            lswitch = nvplib.create_lswitch(
                self.cluster, tenant_id, net_data.get('name'),
                nvp_binding_type, net_data.get(pnet.PHYSICAL_NETWORK),
                net_data.get(pnet.SEGMENTATION_ID),
                shared=net_data.get(attr.SHARED))
            net_data['id'] = lswitch['uuid']

        with context.session.begin(subtransactions=True):
            new_net = super(NvpPluginV2, self).create_network(context,
                                                              network)
            # Ensure there's an id in net_data
            net_data['id'] = new_net['id']
            # Process port security extension
            self._process_network_port_security_create(
                context, net_data, new_net)
            # DB Operations for setting the network as external
            self._process_l3_create(context, new_net, net_data)
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
                context, self.cluster, port)
            if nvp_port_id:
                port['nvp_port_id'] = nvp_port_id
            else:
                LOG.warning(_("A nvp lport identifier was not found for "
                              "neutron port '%s'"), port['id'])

        super(NvpPluginV2, self).delete_network(context, id)
        # clean up network owned ports
        for port in router_iface_ports:
            try:
                if 'nvp_port_id' in port:
                    nvplib.delete_peer_router_lport(self.cluster,
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
                lswitch_ids = [ls['uuid'] for ls in
                               nvplib.get_lswitches(self.cluster, id)]
                nvplib.delete_networks(self.cluster, id, lswitch_ids)
                LOG.debug(_("delete_network completed for tenant: %s"),
                          context.tenant_id)
            except q_exc.NotFound:
                LOG.warning(_("Did not found lswitch %s in NVP"), id)

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # if the network is external, do not go to NVP
            if not network.external:
                # verify the fabric status of the corresponding
                # logical switch(es) in nvp
                try:
                    lswitches = nvplib.get_lswitches(self.cluster, id)
                    nvp_net_status = constants.NET_STATUS_ACTIVE
                    neutron_status = network.status
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
                                "Status in Neutron DB:%(neutron_status)s"),
                              {'nvp_net_status': nvp_net_status,
                               'neutron_status': neutron_status})
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
            net_result = self._make_network_dict(network)
            self._extend_network_dict_provider(context, net_result)
            self._extend_network_qos_queue(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None):
        nvp_lswitches = {}
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            neutron_lswitches = (
                super(NvpPluginV2, self).get_networks(context, filters))
            for net in neutron_lswitches:
                self._extend_network_dict_provider(context, net)
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
            res = nvplib.get_all_query_pages(lswitch_url_path_1, self.cluster)
            nvp_lswitches.update(dict((ls['uuid'], ls) for ls in res))
            # Issue a second query for fetching shared networks.
            # We cannot unfortunately use just a single query because tags
            # cannot be or-ed
            res_shared = nvplib.get_all_query_pages(lswitch_url_path_2,
                                                    self.cluster)
            nvp_lswitches.update(dict((ls['uuid'], ls) for ls in res_shared))
        except Exception:
            err_msg = _("Unable to get logical switches")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)

        if filters.get('id'):
            nvp_lswitches = dict(
                (uuid, ls) for (uuid, ls) in nvp_lswitches.iteritems()
                if uuid in set(filters['id']))
        for neutron_lswitch in neutron_lswitches:
            # Skip external networks as they do not exist in NVP
            if neutron_lswitch[l3.EXTERNAL]:
                continue
            elif neutron_lswitch['id'] not in nvp_lswitches:
                LOG.warning(_("Logical Switch %s found in neutron database "
                              "but not in NVP."), neutron_lswitch["id"])
                neutron_lswitch["status"] = constants.NET_STATUS_ERROR
            else:
                # TODO(salvatore-orlando): be careful about "extended"
                # logical switches
                ls = nvp_lswitches.pop(neutron_lswitch['id'])
                if (ls["_relations"]["LogicalSwitchStatus"]["fabric_status"]):
                    neutron_lswitch["status"] = constants.NET_STATUS_ACTIVE
                else:
                    neutron_lswitch["status"] = constants.NET_STATUS_DOWN

        # do not make the case in which switches are found in NVP
        # but not in Neutron catastrophic.
        if nvp_lswitches:
            LOG.warning(_("Found %s logical switches not bound "
                        "to Neutron networks. Neutron and NVP are "
                        "potentially out of sync"), len(nvp_lswitches))

        LOG.debug(_("get_networks() completed for tenant %s"),
                  context.tenant_id)

        if fields:
            ret_fields = []
            for neutron_lswitch in neutron_lswitches:
                row = {}
                for field in fields:
                    row[field] = neutron_lswitch[field]
                ret_fields.append(row)
            return ret_fields
        return neutron_lswitches

    def update_network(self, context, id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        if network["network"].get("admin_state_up"):
            if network['network']["admin_state_up"] is False:
                raise q_exc.NotImplementedError(_("admin_state_up=False "
                                                  "networks are not "
                                                  "supported."))
        with context.session.begin(subtransactions=True):
            net = super(NvpPluginV2, self).update_network(context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._process_network_port_security_update(
                    context, network['network'], net)
            if network['network'].get(ext_qos.QUEUE):
                net[ext_qos.QUEUE] = network['network'][ext_qos.QUEUE]
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context, net)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_qos_queue(context, net)
        return net

    def get_ports(self, context, filters=None, fields=None):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            neutron_lports = super(NvpPluginV2, self).get_ports(
                context, filters)
            for neutron_lport in neutron_lports:
                self._extend_port_mac_learning_state(context, neutron_lport)
        if (filters.get('network_id') and len(filters.get('network_id')) and
            self._network_is_external(context, filters['network_id'][0])):
            # Do not perform check on NVP platform
            return neutron_lports

        vm_filter = ""
        tenant_filter = ""
        # This is used when calling delete_network. Neutron checks to see if
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
            lport_query_path = (
                "/ws.v1/lswitch/%s/lport?fields=%s&%s%stag_scope=q_port_id"
                "&relations=LogicalPortStatus" %
                (lswitch, lport_fields_str, vm_filter, tenant_filter))

            try:
                ports = nvplib.get_all_query_pages(lport_query_path,
                                                   self.cluster)
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
        for neutron_lport in neutron_lports:
            # if a neutron port is not found in NVP, this migth be because
            # such port is not mapped to a logical switch - ie: floating ip
            if neutron_lport['device_owner'] in (l3_db.DEVICE_OWNER_FLOATINGIP,
                                                 l3_db.DEVICE_OWNER_ROUTER_GW):
                lports.append(neutron_lport)
                continue
            try:
                neutron_lport["admin_state_up"] = (
                    nvp_lports[neutron_lport["id"]]["admin_status_enabled"])

                if (nvp_lports[neutron_lport["id"]]
                        ["_relations"]
                        ["LogicalPortStatus"]
                        ["fabric_status_up"]):
                    neutron_lport["status"] = constants.PORT_STATUS_ACTIVE
                else:
                    neutron_lport["status"] = constants.PORT_STATUS_DOWN

                del nvp_lports[neutron_lport["id"]]
            except KeyError:
                neutron_lport["status"] = constants.PORT_STATUS_ERROR
                LOG.debug(_("Neutron logical port %s was not found on NVP"),
                          neutron_lport['id'])

            lports.append(neutron_lport)
        # do not make the case in which ports are found in NVP
        # but not in Neutron catastrophic.
        if nvp_lports:
            LOG.warning(_("Found %s logical ports not bound "
                          "to Neutron ports. Neutron and NVP are "
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
        port_data = port['port']
        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            # First we allocate port in neutron database
            neutron_db = super(NvpPluginV2, self).create_port(context, port)
            neutron_port_id = neutron_db['id']
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            # metadata_dhcp_host_route
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                neutron_db.get('device_owner') == constants.DEVICE_OWNER_DHCP):
                if (neutron_db.get('fixed_ips') and
                    len(neutron_db['fixed_ips'])):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, neutron_db['fixed_ips'][0])
            # port security extension checks
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, port_data)
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # security group extension checks
            if port_security and has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif attr.is_attr_set(port_data.get(ext_sg.SECURITYGROUPS)):
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            port_data[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, port_data, port_data[ext_sg.SECURITYGROUPS])
            # QoS extension checks
            port_data[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, port_data)
            self._process_port_queue_mapping(context, port_data)
            if (isinstance(port_data.get(mac_ext.MAC_LEARNING), bool)):
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                port_data.pop(mac_ext.MAC_LEARNING)

            LOG.debug(_("create_port completed on NVP for tenant "
                        "%(tenant_id)s: (%(id)s)"), port_data)

            # remove since it will be added in extend based on policy
            del port_data[ext_qos.QUEUE]
            self._extend_port_qos_queue(context, port_data)
            self._process_portbindings_create_and_update(context,
                                                         port, port_data)
        # DB Operation is complete, perform NVP operation
        try:
            port_data = port['port'].copy()
            port_create_func = self._port_drivers['create'].get(
                port_data['device_owner'],
                self._port_drivers['create']['default'])
            port_create_func(context, port_data)
        except q_exc.NotFound:
            LOG.warning(_("Logical switch for network %s was not "
                          "found in NVP."), port_data['network_id'])
            # Put port in error on quantum DB
            with context.session.begin(subtransactions=True):
                port = self._get_port(context, neutron_port_id)
                port_data['status'] = constants.PORT_STATUS_ERROR
                port['status'] = port_data['status']
                context.session.add(port)
        except Exception:
            # Port must be removed from Quantum DB
            with excutils.save_and_reraise_exception():
                LOG.error(_("Unable to create port or set port "
                            "attachment in NVP."))
                with context.session.begin(subtransactions=True):
                    self._delete_port(context, neutron_port_id)

        # Port has been created both on DB and NVP - proceed with
        # scheduling network and notifying DHCP agent
        net = self.get_network(context, port_data['network_id'])
        self.schedule_network(context, net)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, neutron_db['fixed_ips'][0]['subnet_id'])
        return port_data

    def update_port(self, context, id, port):
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(NvpPluginV2, self).update_port(
                context, id, port)
            # copy values over - except fixed_ips as
            # they've alreaby been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])
            tenant_id = self._get_tenant_id_for_create(context, ret_port)

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
                self._process_port_create_security_group(context, ret_port,
                                                         sgids)

            if psec.PORTSECURITY in port['port']:
                self._process_port_port_security_update(
                    context, port['port'], ret_port)

            ret_port[ext_qos.QUEUE] = self._check_for_queue_and_create(
                context, ret_port)
            # Populate the mac learning attribute
            new_mac_learning_state = port['port'].get(mac_ext.MAC_LEARNING)
            old_mac_learning_state = self._get_mac_learning_state(context, id)
            if (new_mac_learning_state is not None and
                old_mac_learning_state != new_mac_learning_state):
                self._update_mac_learning_state(context, id,
                                                new_mac_learning_state)
                ret_port[mac_ext.MAC_LEARNING] = new_mac_learning_state
            elif (new_mac_learning_state is None and
                  old_mac_learning_state is not None):
                ret_port[mac_ext.MAC_LEARNING] = old_mac_learning_state
            self._delete_port_queue_mapping(context, ret_port['id'])
            self._process_port_queue_mapping(context, ret_port)
            LOG.warn(_("Update port request: %s"), port)
            nvp_port_id = self._nvp_get_port_id(
                context, self.cluster, ret_port)
            if nvp_port_id:
                try:
                    nvplib.update_port(self.cluster,
                                       ret_port['network_id'],
                                       nvp_port_id, id, tenant_id,
                                       ret_port['name'], ret_port['device_id'],
                                       ret_port['admin_state_up'],
                                       ret_port['mac_address'],
                                       ret_port['fixed_ips'],
                                       ret_port[psec.PORTSECURITY],
                                       ret_port[ext_sg.SECURITYGROUPS],
                                       ret_port[ext_qos.QUEUE],
                                       ret_port.get(mac_ext.MAC_LEARNING))

                    # Update the port status from nvp. If we fail here hide it
                    # since the port was successfully updated but we were not
                    # able to retrieve the status.
                    ret_port['status'] = nvplib.get_port_status(
                        self.cluster, ret_port['network_id'],
                        nvp_port_id)
                # FIXME(arosen) improve exception handling.
                except Exception:
                    ret_port['status'] = constants.PORT_STATUS_ERROR
                    LOG.exception(_("Unable to update port id: %s."),
                                  nvp_port_id)

            # If nvp_port_id is not in database or in nvp put in error state.
            else:
                ret_port['status'] = constants.PORT_STATUS_ERROR

            # remove since it will be added in extend based on policy
            del ret_port[ext_qos.QUEUE]
            self._extend_port_qos_queue(context, ret_port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port)
        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """Deletes a port on a specified Virtual Network.

        If the port contains a remote interface attachment, the remote
        interface is first un-plugged and then the port is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        neutron_db_port = self.get_port(context, id)
        # Perform the same check for ports owned by layer-2 gateways
        if nw_gw_port_check:
            self.prevent_network_gateway_port_deletion(context,
                                                       neutron_db_port)
        port_delete_func = self._port_drivers['delete'].get(
            neutron_db_port['device_owner'],
            self._port_drivers['delete']['default'])

        port_delete_func(context, neutron_db_port)
        self.disassociate_floatingips(context, id)
        notify_dhcp_agent = False
        with context.session.begin(subtransactions=True):
            queue = self._get_port_queue_bindings(context, {'port_id': [id]})
            # metadata_dhcp_host_route
            port_device_owner = neutron_db_port['device_owner']
            if (cfg.CONF.NVP.metadata_mode == "dhcp_host_route" and
                port_device_owner == constants.DEVICE_OWNER_DHCP):
                    notify_dhcp_agent = self._ensure_metadata_host_route(
                        context, neutron_db_port['fixed_ips'][0],
                        is_delete=True)
            super(NvpPluginV2, self).delete_port(context, id)
            # Delete qos queue if possible
            if queue:
                self.delete_qos_queue(context, queue[0]['queue_id'], False)
        if notify_dhcp_agent:
            self._send_subnet_update_end(
                context, neutron_db_port['fixed_ips'][0]['subnet_id'])

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            neutron_db_port = super(NvpPluginV2, self).get_port(context,
                                                                id, fields)
            self._extend_port_qos_queue(context, neutron_db_port)
            self._extend_port_mac_learning_state(context, neutron_db_port)

            if self._network_is_external(context,
                                         neutron_db_port['network_id']):
                return neutron_db_port
            nvp_id = self._nvp_get_port_id(context, self.cluster,
                                           neutron_db_port)
            # If there's no nvp IP do not bother going to NVP and put
            # the port in error state
            if nvp_id:
                    # Find the NVP port corresponding to neutron port_id
                    # Do not query by nvp id as the port might be on
                    # an extended switch and we do not store the extended
                    # switch uuid
                    results = nvplib.query_lswitch_lports(
                        self.cluster, '*',
                        relations='LogicalPortStatus',
                        filters={'tag': id, 'tag_scope': 'q_port_id'})
                    if results:
                        port = results[0]
                        port_status = port["_relations"]["LogicalPortStatus"]
                        neutron_db_port["admin_state_up"] = (
                            port["admin_status_enabled"])
                        if port_status["fabric_status_up"]:
                            neutron_db_port["status"] = (
                                constants.PORT_STATUS_ACTIVE)
                        else:
                            neutron_db_port["status"] = (
                                constants.PORT_STATUS_DOWN)
                    else:
                        neutron_db_port["status"] = (
                            constants.PORT_STATUS_ERROR)
            else:
                neutron_db_port["status"] = constants.PORT_STATUS_ERROR
        return neutron_db_port

    def create_router(self, context, router):
        # NOTE(salvatore-orlando): We completely override this method in
        # order to be able to use the NVP ID as Neutron ID
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
                    if not ext_net.external:
                        msg = (_("Network '%s' is not a valid external "
                                 "network") % network_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    if ext_net.subnets:
                        ext_subnet = ext_net.subnets[0]
                        nexthop = ext_subnet.gateway_ip
            lrouter = nvplib.create_lrouter(self.cluster, tenant_id,
                                            router['router']['name'],
                                            nexthop)
            # Use NVP identfier for Neutron resource
            router['router']['id'] = lrouter['uuid']
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to create logical router on NVP Platform"))
        # Create the port here - and update it later if we have gw_info
        self._create_and_attach_router_port(
            self.cluster, context, lrouter['uuid'], {'fake_ext_gw': True},
            "L3GatewayAttachment", self.cluster.default_l3_gw_service_uuid)

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

    def update_router(self, context, router_id, router):
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
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    nexthop = ext_subnet.gateway_ip
        try:
            for route in r.get('routes', []):
                if route['destination'] == '0.0.0.0/0':
                    msg = _("'routes' cannot contain route '0.0.0.0/0', "
                            "this must be updated through the default "
                            "gateway attribute")
                    raise q_exc.BadRequest(resource='router', msg=msg)
            previous_routes = nvplib.update_lrouter(
                self.cluster, router_id, r.get('name'),
                nexthop, routes=r.get('routes'))
        # NOTE(salv-orlando): The exception handling below is not correct, but
        # unfortunately nvplib raises a neutron notfound exception when an
        # object is not found in the underlying backend
        except q_exc.NotFound:
            # Put the router in ERROR status
            with context.session.begin(subtransactions=True):
                router_db = self._get_router(context, router_id)
                router_db['status'] = constants.NET_STATUS_ERROR
            raise nvp_exc.NvpPluginException(
                err_msg=_("Logical router %s not found "
                          "on NVP Platform") % router_id)
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to update logical router on NVP Platform"))
        except nvp_exc.NvpInvalidVersion:
            msg = _("Request cannot contain 'routes' with the NVP "
                    "platform currently in execution. Please, try "
                    "without specifying the static routes.")
            LOG.exception(msg)
            raise q_exc.BadRequest(resource='router', msg=msg)
        try:
            return super(NvpPluginV2, self).update_router(context,
                                                          router_id, router)
        except (extraroute.InvalidRoutes,
                extraroute.RouterInterfaceInUseByRoute,
                extraroute.RoutesExhausted):
            with excutils.save_and_reraise_exception():
                # revert changes made to NVP
                nvplib.update_explicit_routes_lrouter(
                    self.cluster, router_id, previous_routes)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            # Ensure metadata access network is detached and destroyed
            # This will also destroy relevant objects on NVP platform.
            # NOTE(salvatore-orlando): A failure in this operation will
            # cause the router delete operation to fail too.
            self._handle_metadata_access_network(context, id, do_create=False)
            super(NvpPluginV2, self).delete_router(context, id)
            # If removal is successful in Neutron it should be so on
            # the NVP platform too - otherwise the transaction should
            # be automatically aborted
            # TODO(salvatore-orlando): Extend the object models in order to
            # allow an extra field for storing the cluster information
            # together with the resource
            try:
                nvplib.delete_lrouter(self.cluster, id)
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
            lrouter = nvplib.get_lrouter(self.cluster, id)
            relations = lrouter.get('_relations')
            if relations:
                lrouter_status = relations.get('LogicalRouterStatus')
                # FIXME(salvatore-orlando): Being unable to fetch the
                # logical router status should be an exception.
                if lrouter_status:
                    router_op_status = (lrouter_status.get('fabric_status')
                                        and constants.NET_STATUS_ACTIVE or
                                        constants.NET_STATUS_DOWN)
        except q_exc.NotFound:
            lrouter = {}
            router_op_status = constants.NET_STATUS_ERROR
        if router_op_status != router.status:
            LOG.debug(_("Current router status:%(router_status)s;"
                        "Status in Neutron DB:%(db_router_status)s"),
                      {'router_status': router_op_status,
                       'db_router_status': router.status})
            # update the router status
            with context.session.begin(subtransactions=True):
                router.status = router_op_status
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
            nvp_lrouters = nvplib.get_lrouters(self.cluster,
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
        # but not in Neutron catastrophic.
        if nvp_lrouters:
            LOG.warning(_("Found %s logical routers not bound "
                          "to Neutron routers. Neutron and NVP are "
                          "potentially out of sync"), len(nvp_lrouters))

        return [self._make_router_dict(router, fields)
                for router in routers]

    def add_router_interface(self, context, router_id, interface_info):
        # When adding interface by port_id we need to create the
        # peer port on the nvp logical router in this routine
        port_id = interface_info.get('port_id')
        router_iface_info = super(NvpPluginV2, self).add_router_interface(
            context, router_id, interface_info)
        # router_iface_info will always have a subnet_id attribute
        subnet_id = router_iface_info['subnet_id']
        if port_id:
            port_data = self._get_port(context, port_id)
            nvp_port_id = self._nvp_get_port_id(
                context, self.cluster, port_data)
            # Fetch lswitch port from NVP in order to retrieve LS uuid
            # this is necessary as in the case of bridged networks
            # ls_uuid may be different from network id
            # TODO(salv-orlando): avoid this NVP round trip by storing
            # lswitch uuid together with lport uuid mapping.
            nvp_port = nvplib.query_lswitch_lports(
                self.cluster, '*',
                filters={'uuid': nvp_port_id},
                relations='LogicalSwitchConfig')[0]

            ls_uuid = nvp_port['_relations']['LogicalSwitchConfig']['uuid']
            # Unplug current attachment from lswitch port
            nvplib.plug_interface(self.cluster, ls_uuid,
                                  nvp_port_id, "NoAttachment")
            # Create logical router port and plug patch attachment
            self._create_and_attach_router_port(
                self.cluster, context, router_id, port_data,
                "PatchAttachment", nvp_port_id, subnet_ids=[subnet_id])
        subnet = self._get_subnet(context, subnet_id)
        # If there is an external gateway we need to configure the SNAT rule.
        # Fetch router from DB
        router = self._get_router(context, router_id)
        gw_port = router.gw_port
        if gw_port and router.enable_snat:
            # There is a change gw_port might have multiple IPs
            # In that case we will consider only the first one
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                cidr_prefix = int(subnet['cidr'].split('/')[1])
                nvplib.create_lrouter_snat_rule(
                    self.cluster, router_id, snat_ip, snat_ip,
                    order=NVP_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                    match_criteria={'source_ip_addresses': subnet['cidr']})
        nvplib.create_lrouter_nosnat_rule(
            self.cluster, router_id,
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
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)
        results = nvplib.query_lswitch_lports(
            self.cluster, '*', relations="LogicalPortAttachment",
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
                        {'port_id': port_id, 'router_id': router_id})
        # Finally remove the data from the Neutron DB
        # This will also destroy the port on the logical switch
        info = super(NvpPluginV2, self).remove_router_interface(
            context, router_id, interface_info)
        # Destroy router port (no need to unplug the attachment)
        # FIXME(salvatore-orlando): In case of failures in the Neutron plugin
        # this migth leave a dangling port. We perform the operation here
        # to leverage validation performed in the base class
        if not lrouter_port_id:
            LOG.warning(_("Unable to find NVP logical router port for "
                          "Neutron port id:%s. Was this port ever paired "
                          "with a logical router?"), port_id)
            return info

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
                    self.cluster, router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=1,
                    source_ip_addresses=subnet['cidr'])
            # Relax the minimum expected number as the nosnat rules
            # do not exist in 2.x deployments
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "NoSourceNatRule",
                max_num_expected=1, min_num_expected=0,
                destination_ip_addresses=subnet['cidr'])
            nvplib.delete_router_lport(self.cluster,
                                       router_id, lrouter_port_id)
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Logical router port resource %s not found "
                           "on NVP platform"), lrouter_port_id))
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to update logical router"
                           "on NVP Platform")))
        return info

    def _retrieve_and_delete_nat_rules(self, floating_ip_address,
                                       internal_ip, router_id,
                                       min_num_rules_expected=0):
        try:
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)

            # Remove SNAT rule associated with the single fixed_ip
            # to floating ip
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "SourceNatRule",
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
            context, self.cluster, router_id)['uuid']
        ext_neutron_port_db = self._get_port(context.elevated(),
                                             fip_db.floating_port_id)
        nvp_floating_ips = self._build_ip_address_list(
            context.elevated(), ext_neutron_port_db['fixed_ips'])
        nvplib.update_lrouter_port_ips(self.cluster,
                                       router_id,
                                       nvp_gw_port_id,
                                       ips_to_add=[],
                                       ips_to_remove=nvp_floating_ips)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        """Update floating IP association data.

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
                context, self.cluster, router_id)['uuid']
            nvp_floating_ips = self._build_ip_address_list(
                context.elevated(), external_port['fixed_ips'])
            LOG.debug(_("Address list for NVP logical router "
                        "port:%s"), nvp_floating_ips)
            # Re-create NAT rules only if a port id is specified
            if 'port_id' in fip and fip['port_id']:
                try:
                    # Create new NAT rules
                    nvplib.create_lrouter_dnat_rule(
                        self.cluster, router_id, internal_ip,
                        order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'destination_ip_addresses':
                                        floating_ip})
                    # setup snat rule such that src ip of a IP packet when
                    # using floating is the floating ip itself.
                    nvplib.create_lrouter_snat_rule(
                        self.cluster, router_id, floating_ip, floating_ip,
                        order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'source_ip_addresses': internal_ip})
                    # Add Floating IP address to router_port
                    nvplib.update_lrouter_port_ips(self.cluster,
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
                internal_ip = None
                nvplib.update_lrouter_port_ips(self.cluster,
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
        except q_exc.NotFound:
            LOG.warning(_("Nat rules not found in nvp for port: %s"), id)

        super(NvpPluginV2, self).disassociate_floatingips(context, port_id)

    def create_network_gateway(self, context, network_gateway):
        """Create a layer-2 network gateway.

        Create the gateway service on NVP platform and corresponding data
        structures in Neutron datase.
        """
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Need to re-do authZ checks here in order to avoid creation on NVP
        gw_data = network_gateway[networkgw.RESOURCE_NAME.replace('-', '_')]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        devices = gw_data['devices']
        # Populate default physical network where not specified
        for device in devices:
            if not device.get('interface_name'):
                device['interface_name'] = self.cluster.default_interface_name
        try:
            nvp_res = nvplib.create_l2_gw_service(self.cluster, tenant_id,
                                                  gw_data['name'], devices)
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
        """Remove a layer-2 network gateway.

        Remove the gateway service from NVP platform and corresponding data
        structures in Neutron datase.
        """
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        with context.session.begin(subtransactions=True):
            try:
                super(NvpPluginV2, self).delete_network_gateway(context, id)
                nvplib.delete_l2_gw_service(self.cluster, id)
            except NvpApiClient.ResourceNotFound:
                # Do not cause a 500 to be returned to the user if
                # the corresponding NVP resource does not exist
                LOG.exception(_("Unable to remove gateway service from "
                                "NVP plaform - the resource was not found"))

    def get_network_gateway(self, context, id, fields=None):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).get_network_gateway(context,
                                                            id, fields)

    def get_network_gateways(self, context, filters=None, fields=None):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Ensure the tenant_id attribute is populated on returned gateways
        net_gateways = super(NvpPluginV2,
                             self).get_network_gateways(context,
                                                        filters,
                                                        fields)
        return net_gateways

    def update_network_gateway(self, context, id, network_gateway):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).update_network_gateway(
            context, id, network_gateway)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).connect_network(
            context, network_gateway_id, network_mapping_info)

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NvpPluginV2, self).disconnect_network(
            context, network_gateway_id, network_mapping_info)

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        If default_sg is true that means a we are creating a default security
        group and we don't need to check if one exists.
        """
        s = security_group.get('security_group')

        tenant_id = self._get_tenant_id_for_create(context, s)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        nvp_secgroup = nvplib.create_security_profile(self.cluster,
                                                      tenant_id, s)
        security_group['security_group']['id'] = nvp_secgroup['uuid']
        return super(NvpPluginV2, self).create_security_group(
            context, security_group, default_sg)

    def delete_security_group(self, context, security_group_id):
        """Delete a security group.

        :param security_group_id: security group rule to remove.
        """
        with context.session.begin(subtransactions=True):
            security_group = super(NvpPluginV2, self).get_security_group(
                context, security_group_id)
            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)

            if security_group['name'] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            filters = {'security_group_id': [security_group['id']]}
            if super(NvpPluginV2, self)._get_port_security_group_bindings(
                context, filters):
                raise ext_sg.SecurityGroupInUse(id=security_group['id'])
            nvplib.delete_security_profile(self.cluster,
                                           security_group['id'])
            return super(NvpPluginV2, self).delete_security_group(
                context, security_group_id)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a single security group rule."""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """Create security group rules.

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
            nvplib.update_security_group_rules(self.cluster,
                                               security_group['id'],
                                               combined_rules)
            return super(
                NvpPluginV2, self).create_security_group_rule_bulk_native(
                    context, security_group_rule)

    def delete_security_group_rule(self, context, sgrid):
        """Delete a security group rule
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
                self.cluster, sgid, current_rules)
            return super(NvpPluginV2, self).delete_security_group_rule(context,
                                                                       sgrid)

    def create_qos_queue(self, context, qos_queue, check_policy=True):
        q = qos_queue.get('qos_queue')
        self._validate_qos_queue(context, q)
        q['id'] = nvplib.create_lqueue(self.cluster,
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
        nvplib.delete_lqueue(self.cluster, id)
        return super(NvpPluginV2, self).delete_qos_queue(context, id)
