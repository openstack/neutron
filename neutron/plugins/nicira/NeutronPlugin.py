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


import logging
import os

from oslo.config import cfg
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc as sa_exc
import webob.exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.common import utils
from neutron import context as q_context
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common.db import exception as db_exc
from neutron.openstack.common import excutils
from neutron.openstack.common import lockutils
from neutron.plugins.common import constants as plugin_const
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import nsx_utils
from neutron.plugins.nicira.common import securitygroups as nvp_sec
from neutron.plugins.nicira.common import sync
from neutron.plugins.nicira.dbexts import distributedrouter as dist_rtr
from neutron.plugins.nicira.dbexts import maclearning as mac_db
from neutron.plugins.nicira.dbexts import nicira_db
from neutron.plugins.nicira.dbexts import nicira_networkgw_db as networkgw_db
from neutron.plugins.nicira.dbexts import nicira_qos_db as qos_db
from neutron.plugins.nicira import dhcpmeta_modes
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
NVP_DEFAULT_NEXTHOP = '1.1.1.1'


# Provider network extension - allowed network types for the NVP Plugin
class NetworkTypes:
    """Allowed provider network types for the NVP Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'


def create_nvp_cluster(cluster_opts, concurrent_connections,
                       nsx_gen_timeout):
    cluster = nvp_cluster.NVPCluster(**cluster_opts)

    def _ctrl_split(x, y):
        return (x, int(y), True)

    api_providers = [_ctrl_split(*ctrl.split(':'))
                     for ctrl in cluster.nsx_controllers]
    cluster.api_client = NvpApiClient.NVPApiHelper(
        api_providers, cluster.nsx_user, cluster.nsx_password,
        request_timeout=cluster.req_timeout,
        http_timeout=cluster.http_timeout,
        retries=cluster.retries,
        redirects=cluster.redirects,
        concurrent_connections=concurrent_connections,
        nvp_gen_timeout=nsx_gen_timeout)
    return cluster


class NvpPluginV2(addr_pair_db.AllowedAddressPairsMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin,
                  db_base_plugin_v2.NeutronDbPluginV2,
                  dhcpmeta_modes.DhcpMetadataAccess,
                  dist_rtr.DistributedRouter_mixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  mac_db.MacLearningDbMixin,
                  networkgw_db.NetworkGatewayMixin,
                  nvp_sec.NVPSecurityGroups,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  qos_db.NVPQoSDbMixin,
                  securitygroups_db.SecurityGroupDbMixin):
    """L2 Virtual network plugin.

    NvpPluginV2 is a Neutron plugin that provides L2 Virtual Network
    functionality using NVP.
    """

    supported_extension_aliases = ["agent",
                                   "allowed-address-pairs",
                                   "binding",
                                   "dhcp_agent_scheduler",
                                   "dist-router",
                                   "ext-gw-mode",
                                   "extraroute",
                                   "mac-learning",
                                   "multi-provider",
                                   "network-gateway",
                                   "nvp-qos",
                                   "port-security",
                                   "provider",
                                   "quotas",
                                   "external-net",
                                   "router",
                                   "security-group"]

    __native_bulk_support = True

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}

    def __init__(self):

        # TODO(salv-orlando): Replace These dicts with
        # collections.defaultdict for better handling of default values
        # Routines for managing logical ports in NVP
        self.port_special_owners = [l3_db.DEVICE_OWNER_ROUTER_GW,
                                    l3_db.DEVICE_OWNER_ROUTER_INTF]
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

        neutron_extensions.append_api_extensions_path([NVP_EXT_PATH])
        self.nvp_opts = cfg.CONF.NSX
        self.nvp_sync_opts = cfg.CONF.NSX_SYNC
        self.cluster = create_nvp_cluster(cfg.CONF,
                                          self.nvp_opts.concurrent_connections,
                                          self.nvp_opts.nsx_gen_timeout)

        self.base_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_OVS,
            pbin.CAPABILITIES: {
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}

        db.configure_db()
        self._extend_fault_map()
        self.setup_dhcpmeta_access()
        # Set this flag to false as the default gateway has not
        # been yet updated from the config file
        self._is_default_net_gw_in_sync = False
        # Create a synchronizer instance for backend sync
        self._synchronizer = sync.NvpSynchronizer(
            self, self.cluster,
            self.nvp_sync_opts.state_sync_interval,
            self.nvp_sync_opts.min_sync_req_delay,
            self.nvp_sync_opts.min_chunk_size,
            self.nvp_sync_opts.max_random_sync_delay)

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
            except networkgw_db.GatewayNotFound:
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
                port_data.get('admin_state_up', True), ip_addresses,
                port_data.get('mac_address'))
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
        network_bindings = nicira_db.get_network_bindings(
            context.session, port_data['network_id'])
        max_ports = self.nvp_opts.max_lp_per_overlay_ls
        allow_extra_lswitches = False
        for network_binding in network_bindings:
            if network_binding.binding_type in (NetworkTypes.FLAT,
                                                NetworkTypes.VLAN):
                max_ports = self.nvp_opts.max_lp_per_bridged_ls
                allow_extra_lswitches = True
                break
        try:
            return self._handle_lswitch_selection(self.cluster, network,
                                                  network_bindings, max_ports,
                                                  allow_extra_lswitches)
        except NvpApiClient.NvpApiException:
            err_desc = _("An exception occurred while selecting logical "
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
                                   port_data.get(ext_qos.QUEUE),
                                   port_data.get(mac_ext.MAC_LEARNING),
                                   port_data.get(addr_pair.ADDRESS_PAIRS))

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
            nicira_db.delete_neutron_nsx_port_mapping(context.session,
                                                      port_id)
            msg = (_("An exception occurred while creating the "
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
            nicira_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], lport['uuid'])
            if port_data['device_owner'] not in self.port_special_owners:
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
        except db_exc.DBError as e:
            if (port_data['device_owner'] == constants.DEVICE_OWNER_DHCP and
                isinstance(e.inner_exception, sql_exc.IntegrityError)):
                msg = (_("Concurrent network deletion detected; Back-end Port "
                         "%(nsx_id)s creation to be rolled back for Neutron "
                         "port: %(neutron_id)s")
                       % {'nsx_id': lport['uuid'],
                          'neutron_id': port_data['id']})
                LOG.warning(msg)
                if selected_lswitch and lport:
                    try:
                        nvplib.delete_port(self.cluster,
                                           selected_lswitch['uuid'],
                                           lport['uuid'])
                    except q_exc.NotFound:
                        LOG.debug(_("NSX Port %s already gone"), lport['uuid'])

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
        nvp_switch_id, nvp_port_id = nsx_utils.get_nsx_switch_and_port_id(
            context.session, self.cluster, port_data['id'])
        if not nvp_port_id:
            LOG.debug(_("Port '%s' was already deleted on NVP platform"), id)
            return
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        try:
            nvplib.delete_port(self.cluster,
                               nvp_switch_id,
                               nvp_port_id)
            LOG.debug(_("_nvp_delete_port completed for port %(port_id)s "
                        "on network %(net_id)s"),
                      {'port_id': port_data['id'],
                       'net_id': port_data['network_id']})
        except q_exc.NotFound:
            LOG.warning(_("Port %s not found in NVP"), port_data['id'])

    def _nvp_delete_router_port(self, context, port_data):
        # Delete logical router port
        lrouter_id = port_data['device_id']
        nvp_switch_id, nvp_port_id = nsx_utils.get_nsx_switch_and_port_id(
            context.session, self.cluster, port_data['id'])
        if not nvp_port_id:
            LOG.warn(_("Neutron port %(port_id)s not found on NVP backend. "
                       "Terminating delete operation. A dangling router port "
                       "might have been left on router %(router_id)s"),
                     {'port_id': port_data['id'],
                      'router_id': lrouter_id})
            return
        try:
            nvplib.delete_peer_router_lport(self.cluster,
                                            lrouter_id,
                                            nvp_switch_id,
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
            nicira_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], ls_port['uuid'])
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

    @lockutils.synchronized('nicira', 'neutron-')
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
            physical_network = (ext_network[pnet.PHYSICAL_NETWORK] or
                                self.cluster.default_l3_gw_service_uuid)
            self._update_router_port_attachment(
                self.cluster, context, router_id, port_data,
                lr_port['uuid'],
                "L3GatewayAttachment",
                physical_network,
                ext_network[pnet.SEGMENTATION_ID])

        LOG.debug(_("_nvp_create_ext_gw_port completed on external network "
                    "%(ext_net_id)s, attached to router:%(router_id)s. "
                    "NVP port id is %(nvp_port_id)s"),
                  {'ext_net_id': port_data['network_id'],
                   'router_id': router_id,
                   'nvp_port_id': lr_port['uuid']})

    @lockutils.synchronized('nicira', 'neutron-')
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
            nicira_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], lport['uuid'])
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

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NVP Plugin are mapped to standard
        HTTP Exceptions.
        """
        base.FAULT_MAP.update({nvp_exc.NvpInvalidNovaZone:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.NvpNoMorePortsException:
                               webob.exc.HTTPBadRequest,
                               nvp_exc.MaintenanceInProgress:
                               webob.exc.HTTPServiceUnavailable})

    def _validate_provider_create(self, context, network):
        if not attr.is_attr_set(network.get(mpnet.SEGMENTS)):
            return

        for segment in network[mpnet.SEGMENTS]:
            network_type = segment.get(pnet.NETWORK_TYPE)
            physical_network = segment.get(pnet.PHYSICAL_NETWORK)
            segmentation_id = segment.get(pnet.SEGMENTATION_ID)
            network_type_set = attr.is_attr_set(network_type)
            segmentation_id_set = attr.is_attr_set(segmentation_id)

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
                    bindings = nicira_db.get_network_bindings_by_vlanid(
                        context.session, segmentation_id)
                    if bindings:
                        raise q_exc.VlanIdInUse(
                            vlan_id=segmentation_id,
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
                err_msg = (_("%(net_type_param)s %(net_type_value)s not "
                             "supported") %
                           {'net_type_param': pnet.NETWORK_TYPE,
                            'net_type_value': network_type})
            if err_msg:
                raise q_exc.InvalidInput(error_message=err_msg)
            # TODO(salvatore-orlando): Validate tranport zone uuid
            # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network,
                                      multiprovider=None, bindings=None):
        if not bindings:
            bindings = nicira_db.get_network_bindings(context.session,
                                                      network['id'])
        if not multiprovider:
            multiprovider = nicira_db.is_multiprovider_network(context.session,
                                                               network['id'])
        # With NVP plugin 'normal' overlay networks will have no binding
        # TODO(salvatore-orlando) make sure users can specify a distinct
        # phy_uuid as 'provider network' for STT net type
        if bindings:
            if not multiprovider:
                # network came in through provider networks api
                network[pnet.NETWORK_TYPE] = bindings[0].binding_type
                network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
                network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id
            else:
                # network come in though multiprovider networks api
                network[mpnet.SEGMENTS] = [
                    {pnet.NETWORK_TYPE: binding.binding_type,
                     pnet.PHYSICAL_NETWORK: binding.phy_uuid,
                     pnet.SEGMENTATION_ID: binding.vlan_id}
                    for binding in bindings]

    def _handle_lswitch_selection(self, cluster, network,
                                  network_bindings, max_ports,
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
            transport_zone_config = self._convert_to_nvp_transport_zones(
                cluster, network, bindings=network_bindings)
            selected_lswitch = nvplib.create_lswitch(
                cluster, network.tenant_id,
                "%s-ext-%s" % (network.name, len(lswitches)),
                transport_zone_config,
                network.id)
            return selected_lswitch
        else:
            LOG.error(_("Maximum number of logical ports reached for "
                        "logical network %s"), network.id)
            raise nvp_exc.NvpNoMorePortsException(network=network.id)

    def _convert_to_nvp_transport_zones(self, cluster, network=None,
                                        bindings=None):
        nvp_transport_zones_config = []

        # Convert fields from provider request to nvp format
        if (network and not attr.is_attr_set(
            network.get(mpnet.SEGMENTS))):
            return [{"zone_uuid": cluster.default_tz_uuid,
                     "transport_type": cfg.CONF.NSX.default_transport_type}]

        # Convert fields from db to nvp format
        if bindings:
            transport_entry = {}
            for binding in bindings:
                if binding.binding_type in [NetworkTypes.FLAT,
                                            NetworkTypes.VLAN]:
                    transport_entry['transport_type'] = NetworkTypes.BRIDGE
                    transport_entry['binding_config'] = {}
                    vlan_id = binding.vlan_id
                    if vlan_id:
                        transport_entry['binding_config'] = (
                            {'vlan_translation': [{'transport': vlan_id}]})
                else:
                    transport_entry['transport_type'] = binding.binding_type
                transport_entry['zone_uuid'] = binding.phy_uuid
                nvp_transport_zones_config.append(transport_entry)
            return nvp_transport_zones_config

        for transport_zone in network.get(mpnet.SEGMENTS):
            for value in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                if transport_zone.get(value) == attr.ATTR_NOT_SPECIFIED:
                    transport_zone[value] = None

            transport_entry = {}
            transport_type = transport_zone.get(pnet.NETWORK_TYPE)
            if transport_type in [NetworkTypes.FLAT, NetworkTypes.VLAN]:
                transport_entry['transport_type'] = NetworkTypes.BRIDGE
                transport_entry['binding_config'] = {}
                vlan_id = transport_zone.get(pnet.SEGMENTATION_ID)
                if vlan_id:
                    transport_entry['binding_config'] = (
                        {'vlan_translation': [{'transport': vlan_id}]})
            else:
                transport_entry['transport_type'] = transport_type
            transport_entry['zone_uuid'] = (
                transport_zone[pnet.PHYSICAL_NETWORK] or
                cluster.default_tz_uuid)
            nvp_transport_zones_config.append(transport_entry)
        return nvp_transport_zones_config

    def _convert_to_transport_zones_dict(self, network):
        """Converts the provider request body to multiprovider.
        Returns: True if request is multiprovider False if provider
        and None if neither.
        """
        if any(attr.is_attr_set(network.get(f))
               for f in (pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                         pnet.SEGMENTATION_ID)):
            if attr.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()
            # convert to transport zone list
            network[mpnet.SEGMENTS] = [
                {pnet.NETWORK_TYPE: network[pnet.NETWORK_TYPE],
                 pnet.PHYSICAL_NETWORK: network[pnet.PHYSICAL_NETWORK],
                 pnet.SEGMENTATION_ID: network[pnet.SEGMENTATION_ID]}]
            del network[pnet.NETWORK_TYPE]
            del network[pnet.PHYSICAL_NETWORK]
            del network[pnet.SEGMENTATION_ID]
            return False
        if attr.is_attr_set(mpnet.SEGMENTS):
            return True

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        provider_type = self._convert_to_transport_zones_dict(net_data)
        self._validate_provider_create(context, net_data)
        # Replace ATTR_NOT_SPECIFIED with None before sending to NVP
        for key, value in network['network'].iteritems():
            if value is attr.ATTR_NOT_SPECIFIED:
                net_data[key] = None
        # FIXME(arosen) implement admin_state_up = False in NVP
        if net_data['admin_state_up'] is False:
            LOG.warning(_("Network with admin_state_up=False are not yet "
                          "supported by this plugin. Ignoring setting for "
                          "network %s"), net_data.get('name', '<unknown>'))
        transport_zone_config = self._convert_to_nvp_transport_zones(
            self.cluster, net_data)
        external = net_data.get(ext_net_extn.EXTERNAL)
        if (not attr.is_attr_set(external) or
            attr.is_attr_set(external) and not external):
            lswitch = nvplib.create_lswitch(
                self.cluster, tenant_id, net_data.get('name'),
                transport_zone_config,
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
            net_queue_id = net_data.get(ext_qos.QUEUE)
            if net_queue_id:
                # Raises if not found
                self.get_qos_queue(context, net_queue_id)
                self._process_network_queue_mapping(
                    context, new_net, net_queue_id)

            if (net_data.get(mpnet.SEGMENTS) and
                isinstance(provider_type, bool)):
                net_bindings = []
                for tz in net_data[mpnet.SEGMENTS]:
                    net_bindings.append(nicira_db.add_network_binding(
                        context.session, new_net['id'],
                        tz.get(pnet.NETWORK_TYPE),
                        tz.get(pnet.PHYSICAL_NETWORK),
                        tz.get(pnet.SEGMENTATION_ID, 0)))
                if provider_type:
                    nicira_db.set_multiprovider_network(context.session,
                                                        new_net['id'])
                self._extend_network_dict_provider(context, new_net,
                                                   provider_type,
                                                   net_bindings)
        self.handle_network_dhcp_access(context, new_net,
                                        action='create_network')
        return new_net

    def delete_network(self, context, id):
        external = self._network_is_external(context, id)
        # Before deleting ports, ensure the peer of a NVP logical
        # port with a patch attachment is removed too
        port_filter = {'network_id': [id],
                       'device_owner': ['network:router_interface']}
        router_iface_ports = self.get_ports(context, filters=port_filter)
        for port in router_iface_ports:
            nvp_switch_id, nvp_port_id = nsx_utils.get_nsx_switch_and_port_id(
                context.session, self.cluster, id)

        super(NvpPluginV2, self).delete_network(context, id)
        # clean up network owned ports
        for port in router_iface_ports:
            try:
                if nvp_port_id:
                    nvplib.delete_peer_router_lport(self.cluster,
                                                    port['device_id'],
                                                    nvp_switch_id,
                                                    nvp_port_id)
                else:
                    LOG.warning(_("A nvp lport identifier was not found for "
                                  "neutron port '%s'. Unable to remove "
                                  "the peer router port for this switch port"),
                                port['id'])

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
        self.handle_network_dhcp_access(context, id, action='delete_network')

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            if (self.nvp_sync_opts.always_read_status or
                fields and 'status' in fields):
                # External networks are not backed by nvp lswitches
                if not network.external:
                    # Perform explicit state synchronization
                    self._synchronizer.synchronize_network(context, network)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network)
            self._extend_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = super(NvpPluginV2, self).get_networks(context, filters)
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

    def update_network(self, context, id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        if network["network"].get("admin_state_up") is False:
            raise NotImplementedError(_("admin_state_up=False networks "
                                        "are not supported."))
        with context.session.begin(subtransactions=True):
            net = super(NvpPluginV2, self).update_network(context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._process_network_port_security_update(
                    context, network['network'], net)
            net_queue_id = network['network'].get(ext_qos.QUEUE)
            if net_queue_id:
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context, net, net_queue_id)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
        return net

    def create_port(self, context, port):
        # If PORTSECURITY is not the default value ATTR_NOT_SPECIFIED
        # then we pass the port to the policy engine. The reason why we don't
        # pass the value to the policy engine when the port is
        # ATTR_NOT_SPECIFIED is for the case where a port is created on a
        # shared network that is not owned by the tenant.
        port_data = port['port']
        with context.session.begin(subtransactions=True):
            # First we allocate port in neutron database
            neutron_db = super(NvpPluginV2, self).create_port(context, port)
            neutron_port_id = neutron_db['id']
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            self.handle_port_metadata_access(context, neutron_db)
            # port security extension checks
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, port_data)
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # allowed address pair checks
            if attr.is_attr_set(port_data.get(addr_pair.ADDRESS_PAIRS)):
                if not port_security:
                    raise addr_pair.AddressPairAndPortSecurityRequired()
                else:
                    self._process_create_allowed_address_pairs(
                        context, neutron_db,
                        port_data[addr_pair.ADDRESS_PAIRS])
            else:
                # remove ATTR_NOT_SPECIFIED
                port_data[addr_pair.ADDRESS_PAIRS] = None

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
            port_queue_id = self._check_for_queue_and_create(
                context, port_data)
            self._process_port_queue_mapping(
                context, port_data, port_queue_id)
            if (isinstance(port_data.get(mac_ext.MAC_LEARNING), bool)):
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                port_data.pop(mac_ext.MAC_LEARNING)

            LOG.debug(_("create_port completed on NVP for tenant "
                        "%(tenant_id)s: (%(id)s)"), port_data)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
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

        self.handle_port_dhcp_access(context, port_data, action='create_port')
        return port_data

    def update_port(self, context, id, port):
        changed_fixed_ips = 'fixed_ips' in port['port']
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(NvpPluginV2, self).update_port(
                context, id, port)
            # Save current mac learning state to check whether it's
            # being updated or not
            old_mac_learning_state = ret_port.get(mac_ext.MAC_LEARNING)
            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])
            tenant_id = self._get_tenant_id_for_create(context, ret_port)

            # populate port_security setting
            if psec.PORTSECURITY not in port['port']:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            has_ip = self._ip_on_port(ret_port)
            # validate port security and allowed address pairs
            if not ret_port[psec.PORTSECURITY]:
                #  has address pairs in request
                if has_addr_pairs:
                    raise addr_pair.AddressPairAndPortSecurityRequired()
                elif not delete_addr_pairs:
                    # check if address pairs are in db
                    ret_port[addr_pair.ADDRESS_PAIRS] = (
                        self.get_allowed_address_pairs(context, id))
                    if ret_port[addr_pair.ADDRESS_PAIRS]:
                        raise addr_pair.AddressPairAndPortSecurityRequired()

            if (delete_addr_pairs or has_addr_pairs):
                # delete address pairs and read them in
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port, ret_port[addr_pair.ADDRESS_PAIRS])
            elif changed_fixed_ips:
                self._check_fixed_ips_and_address_pairs_no_overlap(context,
                                                                   ret_port)
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

            port_queue_id = self._check_for_queue_and_create(
                context, ret_port)
            # Populate the mac learning attribute
            new_mac_learning_state = port['port'].get(mac_ext.MAC_LEARNING)
            if (new_mac_learning_state is not None and
                old_mac_learning_state != new_mac_learning_state):
                self._update_mac_learning_state(context, id,
                                                new_mac_learning_state)
                ret_port[mac_ext.MAC_LEARNING] = new_mac_learning_state
            self._delete_port_queue_mapping(context, ret_port['id'])
            self._process_port_queue_mapping(context, ret_port,
                                             port_queue_id)
            LOG.warn(_("Update port request: %s"), port)
            nvp_switch_id, nvp_port_id = nsx_utils.get_nsx_switch_and_port_id(
                context.session, self.cluster, id)
            if nvp_port_id:
                try:
                    nvplib.update_port(self.cluster,
                                       nvp_switch_id,
                                       nvp_port_id, id, tenant_id,
                                       ret_port['name'], ret_port['device_id'],
                                       ret_port['admin_state_up'],
                                       ret_port['mac_address'],
                                       ret_port['fixed_ips'],
                                       ret_port[psec.PORTSECURITY],
                                       ret_port[ext_sg.SECURITYGROUPS],
                                       ret_port[ext_qos.QUEUE],
                                       ret_port.get(mac_ext.MAC_LEARNING),
                                       ret_port.get(addr_pair.ADDRESS_PAIRS))

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

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)
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
        with context.session.begin(subtransactions=True):
            queue = self._get_port_queue_bindings(context, {'port_id': [id]})
            # metadata_dhcp_host_route
            self.handle_port_metadata_access(
                context, neutron_db_port, is_delete=True)
            super(NvpPluginV2, self).delete_port(context, id)
            # Delete qos queue if possible
            if queue:
                self.delete_qos_queue(context, queue[0]['queue_id'], False)
        self.handle_port_dhcp_access(
            context, neutron_db_port, action='delete_port')

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            if (self.nvp_sync_opts.always_read_status or
                fields and 'status' in fields):
                # Perform explicit state synchronization
                db_port = self._get_port(context, id)
                self._synchronizer.synchronize_port(
                    context, db_port)
                return self._make_port_dict(db_port, fields)
            else:
                return super(NvpPluginV2, self).get_port(context, id, fields)

    def get_router(self, context, id, fields=None):
        if (self.nvp_sync_opts.always_read_status or
            fields and 'status' in fields):
            db_router = self._get_router(context, id)
            # Perform explicit state synchronization
            self._synchronizer.synchronize_router(
                context, db_router)
            return self._make_router_dict(db_router, fields)
        else:
            return super(NvpPluginV2, self).get_router(context, id, fields)

    def _create_lrouter(self, context, router, nexthop):
        tenant_id = self._get_tenant_id_for_create(context, router)
        name = router['name']
        distributed = router.get('distributed')
        try:
            lrouter = nvplib.create_lrouter(
                self.cluster, tenant_id, name, nexthop,
                distributed=attr.is_attr_set(distributed) and distributed)
        except nvp_exc.NvpInvalidVersion:
            msg = _("Cannot create a distributed router with the NVP "
                    "platform currently in execution. Please, try "
                    "without specifying the 'distributed' attribute.")
            LOG.exception(msg)
            raise q_exc.BadRequest(resource='router', msg=msg)
        except NvpApiClient.NvpApiException:
            err_msg = _("Unable to create logical router on NVP Platform")
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)

        # Create the port here - and update it later if we have gw_info
        try:
            self._create_and_attach_router_port(
                self.cluster, context, lrouter['uuid'], {'fake_ext_gw': True},
                "L3GatewayAttachment",
                self.cluster.default_l3_gw_service_uuid)
        except nvp_exc.NvpPluginException:
            LOG.exception(_("Unable to create L3GW port on logical router "
                            "%(router_uuid)s. Verify Default Layer-3 Gateway "
                            "service %(def_l3_gw_svc)s id is correct"),
                          {'router_uuid': lrouter['uuid'],
                           'def_l3_gw_svc':
                           self.cluster.default_l3_gw_service_uuid})
            # Try and remove logical router from NVP
            nvplib.delete_lrouter(self.cluster, lrouter['uuid'])
            # Return user a 500 with an apter message
            raise nvp_exc.NvpPluginException(
                err_msg=_("Unable to create router %s") % router['name'])
        lrouter['status'] = plugin_const.ACTIVE
        return lrouter

    def create_router(self, context, router):
        # NOTE(salvatore-orlando): We completely override this method in
        # order to be able to use the NVP ID as Neutron ID
        # TODO(salvatore-orlando): Propose upstream patch for allowing
        # 3rd parties to specify IDs as we do with l2 plugin
        r = router['router']
        has_gw_info = False
        tenant_id = self._get_tenant_id_for_create(context, r)
        # default value to set - nvp wants it (even if we don't have it)
        nexthop = NVP_DEFAULT_NEXTHOP
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
        lrouter = self._create_lrouter(context, r, nexthop)
        # Use NVP identfier for Neutron resource
        r['id'] = lrouter['uuid']
        # Update 'distributed' with value returned from NVP
        # This will be useful for setting the value if the API request
        # did not specify any value for the 'distributed' attribute
        # Platforms older than 3.x do not support the attribute
        r['distributed'] = lrouter.get('distributed', False)
        # TODO(salv-orlando): Deal with backend object removal in case
        # of db failures
        with context.session.begin(subtransactions=True):
            # Transaction nesting is needed to avoid foreign key violations
            # when processing the distributed router binding
            with context.session.begin(subtransactions=True):
                router_db = l3_db.Router(id=lrouter['uuid'],
                                         tenant_id=tenant_id,
                                         name=r['name'],
                                         admin_state_up=r['admin_state_up'],
                                         status=lrouter['status'])
                self._process_nsx_router_create(context, router_db, r)
                context.session.add(router_db)
        if has_gw_info:
            # NOTE(salv-orlando): This operation has been moved out of the
            # database transaction since it performs several NVP queries,
            # ithis ncreasing the risk of deadlocks between eventlet and
            # sqlalchemy operations.
            # Set external gateway and remove router in case of failure
            try:
                self._update_router_gw_info(context, router_db['id'], gw_info)
            except (q_exc.NeutronException, NvpApiClient.NvpApiException):
                with excutils.save_and_reraise_exception():
                    # As setting gateway failed, the router must be deleted
                    # in order to ensure atomicity
                    router_id = router_db['id']
                    LOG.warn(_("Failed to set gateway info for router being "
                               "created:%s - removing router"), router_id)
                    self.delete_router(context, router_id)
                    LOG.info(_("Create router failed while setting external "
                               "gateway. Router:%s has been removed from "
                               "DB and backend"),
                             router_id)
        router = self._make_router_dict(router_db)
        return router

    def _update_lrouter(self, context, router_id, name, nexthop, routes=None):
        return nvplib.update_lrouter(
            self.cluster, router_id, name,
            nexthop, routes=routes)

    def _update_lrouter_routes(self, router_id, routes):
        nvplib.update_explicit_routes_lrouter(
            self.cluster, router_id, routes)

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
            previous_routes = self._update_lrouter(
                context, router_id, r.get('name'),
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
                self._update_lrouter_routes(
                    router_id, previous_routes)

    def _delete_lrouter(self, context, id):
        nvplib.delete_lrouter(self.cluster, id)

    def delete_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            # TODO(salv-orlando): This call should have no effect on delete
            # router, but if it does, it should not happen within a
            # transaction, and it should be restored on rollback
            self.handle_router_metadata_access(
                context, router_id, interface=None)
            # Pre-delete checks
            # NOTE(salv-orlando): These checks will be repeated anyway when
            # calling the superclass. This is wasteful, but is the simplest
            # way of ensuring a consistent removal of the router both in
            # the neutron Database and in the NVP backend.
            # TODO(salv-orlando): split pre-delete checks and actual
            # deletion in superclass.

            # Ensure that the router is not used
            fips = self.get_floatingips_count(
                context.elevated(), filters={'router_id': [router_id]})
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {'device_id': [router_id],
                             'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
            ports = self._core_plugin.get_ports_count(context.elevated(),
                                                      filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

        # It is safe to remove the router from the database, so remove it
        # from the backend
        try:
            self._delete_lrouter(context, router_id)
        except q_exc.NotFound:
            # This is not a fatal error, but needs to be logged
            LOG.warning(_("Logical router '%s' not found "
                        "on NVP Platform"), router_id)
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to delete logical router '%s' "
                           "on NVP Platform") % router_id))

        # Perform the actual delete on the Neutron DB
        try:
            super(NvpPluginV2, self).delete_router(context, router_id)
        except Exception:
            # NOTE(salv-orlando): Broad catching as the following action
            # needs to be performed for every exception.
            # Put the router in ERROR status
            LOG.exception(_("Failure while removing router:%s from database. "
                            "The router will be put in ERROR status"),
                          router_id)
            with context.session.begin(subtransactions=True):
                router_db = self._get_router(context, router_id)
                router_db['status'] = constants.NET_STATUS_ERROR

    def _add_subnet_snat_rule(self, router, subnet):
        gw_port = router.gw_port
        if gw_port and router.enable_snat:
            # There is a change gw_port might have multiple IPs
            # In that case we will consider only the first one
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                cidr_prefix = int(subnet['cidr'].split('/')[1])
                nvplib.create_lrouter_snat_rule(
                    self.cluster, router['id'], snat_ip, snat_ip,
                    order=NVP_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                    match_criteria={'source_ip_addresses': subnet['cidr']})

    def _delete_subnet_snat_rule(self, router, subnet):
        # Remove SNAT rule if external gateway is configured
        if router.gw_port:
            nvplib.delete_nat_rules_by_match(
                self.cluster, router['id'], "SourceNatRule",
                max_num_expected=1, min_num_expected=1,
                source_ip_addresses=subnet['cidr'])

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
            nvp_switch_id, nvp_port_id = nsx_utils.get_nsx_switch_and_port_id(
                context.session, self.cluster, port_id)
            # Unplug current attachment from lswitch port
            nvplib.plug_interface(self.cluster, nvp_switch_id,
                                  nvp_port_id, "NoAttachment")
            # Create logical router port and plug patch attachment
            self._create_and_attach_router_port(
                self.cluster, context, router_id, port_data,
                "PatchAttachment", nvp_port_id, subnet_ids=[subnet_id])
        subnet = self._get_subnet(context, subnet_id)
        # If there is an external gateway we need to configure the SNAT rule.
        # Fetch router from DB
        router = self._get_router(context, router_id)
        self._add_subnet_snat_rule(router, subnet)
        nvplib.create_lrouter_nosnat_rule(
            self.cluster, router_id,
            order=NVP_NOSNAT_RULES_ORDER,
            match_criteria={'destination_ip_addresses': subnet['cidr']})

        # Ensure the NVP logical router has a connection to a 'metadata access'
        # network (with a proxy listening on its DHCP port), by creating it
        # if needed.
        self.handle_router_metadata_access(
            context, router_id, interface=router_iface_info)
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
        # Finally remove the data from the Neutron DB
        # This will also destroy the port on the logical switch
        info = super(NvpPluginV2, self).remove_router_interface(
            context, router_id, interface_info)

        # Ensure the connection to the 'metadata access network'
        # is removed  (with the network) if this the last subnet
        # on the router
        self.handle_router_metadata_access(
            context, router_id, interface=info)
        try:
            if not subnet:
                subnet = self._get_subnet(context, subnet_id)
            router = self._get_router(context, router_id)
            # If router is enabled_snat = False there are no snat rules to
            # delete.
            if router.enable_snat:
                self._delete_subnet_snat_rule(router, subnet)
            # Relax the minimum expected number as the nosnat rules
            # do not exist in 2.x deployments
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "NoSourceNatRule",
                max_num_expected=1, min_num_expected=0,
                destination_ip_addresses=subnet['cidr'])
        except NvpApiClient.ResourceNotFound:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Logical router resource %s not found "
                           "on NVP platform") % router_id))
        except NvpApiClient.NvpApiException:
            raise nvp_exc.NvpPluginException(
                err_msg=(_("Unable to update logical router"
                           "on NVP Platform")))
        return info

    def _retrieve_and_delete_nat_rules(self, context, floating_ip_address,
                                       internal_ip, router_id,
                                       min_num_rules_expected=0):
        try:
            # Remove DNAT rule for the floating IP
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)

            # Remove SNAT rules for the floating IP
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                source_ip_addresses=internal_ip)
            nvplib.delete_nat_rules_by_match(
                self.cluster, router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=internal_ip)

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

    def _get_fip_assoc_data(self, context, fip, floatingip_db):
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
        return (port_id, internal_ip, router_id)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        """Update floating IP association data.

        Overrides method from base class.
        The method is augmented for creating NAT rules in the process.
        """
        # Store router currently serving the floating IP
        old_router_id = floatingip_db.router_id
        port_id, internal_ip, router_id = self._get_fip_assoc_data(
            context, fip, floatingip_db)
        floating_ip = floatingip_db['floating_ip_address']
        # If there's no association router_id will be None
        if router_id:
            self._retrieve_and_delete_nat_rules(context,
                                                floating_ip,
                                                internal_ip,
                                                router_id)
            # Fetch logical port of router's external gateway
        # Fetch logical port of router's external gateway
        nvp_floating_ips = self._build_ip_address_list(
            context.elevated(), external_port['fixed_ips'])
        floating_ip = floatingip_db['floating_ip_address']
        # Retrieve and delete existing NAT rules, if any
        if old_router_id:
            # Retrieve the current internal ip
            _p, _s, old_internal_ip = self._internal_fip_assoc_data(
                context, {'id': floatingip_db.id,
                          'port_id': floatingip_db.fixed_port_id,
                          'fixed_ip_address': floatingip_db.fixed_ip_address,
                          'tenant_id': floatingip_db.tenant_id})
            nvp_gw_port_id = nvplib.find_router_gw_port(
                context, self.cluster, old_router_id)['uuid']
            self._retrieve_and_delete_nat_rules(
                context, floating_ip, old_internal_ip, old_router_id)
            nvplib.update_lrouter_port_ips(
                self.cluster, old_router_id, nvp_gw_port_id,
                ips_to_add=[], ips_to_remove=nvp_floating_ips)

        if router_id:
            nvp_gw_port_id = nvplib.find_router_gw_port(
                context, self.cluster, router_id)['uuid']
            # Re-create NAT rules only if a port id is specified
            if fip.get('port_id'):
                try:
                    # Setup DNAT rules for the floating IP
                    nvplib.create_lrouter_dnat_rule(
                        self.cluster, router_id, internal_ip,
                        order=NVP_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'destination_ip_addresses':
                                        floating_ip})
                    # Setup SNAT rules for the floating IP
                    # Create a SNAT rule for enabling connectivity to the
                    # floating IP from the same network as the internal port
                    # Find subnet id for internal_ip from fixed_ips
                    internal_port = self._get_port(context, port_id)
                    # Cchecks not needed on statements below since otherwise
                    # _internal_fip_assoc_data would have raised
                    subnet_ids = [ip['subnet_id'] for ip in
                                  internal_port['fixed_ips'] if
                                  ip['ip_address'] == internal_ip]
                    internal_subnet_cidr = self._build_ip_address_list(
                        context, internal_port['fixed_ips'],
                        subnet_ids=subnet_ids)[0]
                    nvplib.create_lrouter_snat_rule(
                        self.cluster, router_id, floating_ip, floating_ip,
                        order=NVP_NOSNAT_RULES_ORDER - 1,
                        match_criteria={'source_ip_addresses':
                                        internal_subnet_cidr,
                                        'destination_ip_addresses':
                                        internal_ip})
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
                    msg = _("Failed to update NAT rules for floatingip update")
                    raise nvp_exc.NvpPluginException(err_msg=msg)

        floatingip_db.update({'fixed_ip_address': internal_ip,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        # Check whether the floating ip is associated or not
        if fip_db.fixed_port_id:
            self._retrieve_and_delete_nat_rules(context,
                                                fip_db.floating_ip_address,
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
            self._retrieve_and_delete_nat_rules(context,
                                                fip_db.floating_ip_address,
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
        except NvpApiClient.Conflict:
            raise nvp_exc.NvpL2GatewayAlreadyInUse(gateway=gw_data['name'])
        except NvpApiClient.NvpApiException:
            err_msg = _("Unable to create l2_gw_service for: %s") % gw_data
            LOG.exception(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)
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
        # Update gateway on backend when there's a name change
        name = network_gateway[networkgw.RESOURCE_NAME].get('name')
        if name:
            try:
                nvplib.update_l2_gw_service(self.cluster, id, name)
            except NvpApiClient.NvpApiException:
                # Consider backend failures as non-fatal, but still warn
                # because this might indicate something dodgy is going on
                LOG.warn(_("Unable to update name on NVP backend "
                           "for network gateway: %s"), id)
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

    def _validate_security_group_rules(self, context, rules):
        for rule in rules['security_group_rules']:
            r = rule.get('security_group_rule')
            port_based_proto = (self._get_ip_proto_number(r['protocol'])
                                in securitygroups_db.IP_PROTOCOL_MAP.values())
            if (not port_based_proto and
                (r['port_range_min'] is not None or
                 r['port_range_max'] is not None)):
                msg = (_("Port values not valid for "
                         "protocol: %s") % r['protocol'])
                raise q_exc.BadRequest(resource='security_group_rule',
                                       msg=msg)
        return super(NvpPluginV2, self)._validate_security_group_rules(context,
                                                                       rules)

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
