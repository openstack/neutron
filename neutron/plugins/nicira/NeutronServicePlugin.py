# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
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

import netaddr
from oslo.config import cfg
from sqlalchemy.orm import exc as sa_exc

from neutron.common import exceptions as q_exc
from neutron.db import l3_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as service_constants
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.dbexts import servicerouter as sr_db
from neutron.plugins.nicira.dbexts import vcns_db
from neutron.plugins.nicira.dbexts import vcns_models
from neutron.plugins.nicira.extensions import servicerouter as sr
from neutron.plugins.nicira import NeutronPlugin
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib
from neutron.plugins.nicira.vshield.common import (
    constants as vcns_const)
from neutron.plugins.nicira.vshield.common.constants import RouterStatus
from neutron.plugins.nicira.vshield.common import exceptions
from neutron.plugins.nicira.vshield.tasks.constants import TaskStatus
from neutron.plugins.nicira.vshield import vcns_driver

LOG = logging.getLogger(__name__)

ROUTER_TYPE_BASIC = 1
ROUTER_TYPE_ADVANCED = 2

ROUTER_STATUS = [
    service_constants.ACTIVE,
    service_constants.DOWN,
    service_constants.PENDING_CREATE,
    service_constants.PENDING_DELETE,
    service_constants.ERROR
]

ROUTER_STATUS_LEVEL = {
    service_constants.ACTIVE: RouterStatus.ROUTER_STATUS_ACTIVE,
    service_constants.DOWN: RouterStatus.ROUTER_STATUS_DOWN,
    service_constants.PENDING_CREATE: (
        RouterStatus.ROUTER_STATUS_PENDING_CREATE
    ),
    service_constants.PENDING_DELETE: (
        RouterStatus.ROUTER_STATUS_PENDING_DELETE
    ),
    service_constants.ERROR: RouterStatus.ROUTER_STATUS_ERROR
}


class NvpAdvancedPlugin(sr_db.ServiceRouter_mixin,
                        NeutronPlugin.NvpPluginV2):

    supported_extension_aliases = (
        NeutronPlugin.NvpPluginV2.supported_extension_aliases + [
            'service-router'
        ])

    def __init__(self):
        super(NvpAdvancedPlugin, self).__init__()

        self._super_create_ext_gw_port = (
            self._port_drivers['create'][l3_db.DEVICE_OWNER_ROUTER_GW])
        self._super_delete_ext_gw_port = (
            self._port_drivers['delete'][l3_db.DEVICE_OWNER_ROUTER_GW])

        self._port_drivers['create'][l3_db.DEVICE_OWNER_ROUTER_GW] = (
            self._vcns_create_ext_gw_port)
        self._port_drivers['delete'][l3_db.DEVICE_OWNER_ROUTER_GW] = (
            self._vcns_delete_ext_gw_port)

        # cache router type based on router id
        self._router_type = {}
        self.callbacks = VcnsCallbacks(self)

        # load the vCNS driver
        self._load_vcns_drivers()

    def _load_vcns_drivers(self):
        self.vcns_driver = vcns_driver.VcnsDriver(self.callbacks)

    def _set_router_type(self, router_id, router_type):
        self._router_type[router_id] = router_type

    def _get_router_type(self, context=None, router_id=None, router=None):
        if not router:
            if router_id in self._router_type:
                return self._router_type[router_id]
            router = self._get_router(context, router_id)

        LOG.debug(_("EDGE: router = %s"), router)
        if router['nsx_attributes']['service_router']:
            router_type = ROUTER_TYPE_ADVANCED
        else:
            router_type = ROUTER_TYPE_BASIC
        self._set_router_type(router['id'], router_type)
        return router_type

    def _find_router_type(self, router):
        is_service_router = router.get(sr.SERVICE_ROUTER, False)
        if is_service_router:
            return ROUTER_TYPE_ADVANCED
        else:
            return ROUTER_TYPE_BASIC

    def _is_advanced_service_router(self, context=None, router_id=None,
                                    router=None):
        if router:
            router_type = self._get_router_type(router=router)
        else:
            router_type = self._get_router_type(context, router_id)
        return (router_type == ROUTER_TYPE_ADVANCED)

    def _vcns_create_ext_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        if not self._is_advanced_service_router(context, router_id):
            self._super_create_ext_gw_port(context, port_data)
            return

        # NOP for Edge because currently the port will be create internally
        # by VSM
        LOG.debug(_("EDGE: _vcns_create_ext_gw_port"))

    def _vcns_delete_ext_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        if not self._is_advanced_service_router(context, router_id):
            self._super_delete_ext_gw_port(context, port_data)
            return

        # NOP for Edge
        LOG.debug(_("EDGE: _vcns_delete_ext_gw_port"))

    def _get_external_attachment_info(self, context, router):
        gw_port = router.gw_port
        ipaddress = None
        netmask = None
        nexthop = None

        if gw_port:
            # gw_port may have multiple IPs, only configure the first one
            if gw_port.get('fixed_ips'):
                ipaddress = gw_port['fixed_ips'][0]['ip_address']

            network_id = gw_port.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise q_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    netmask = str(netaddr.IPNetwork(ext_subnet.cidr).netmask)
                    nexthop = ext_subnet.gateway_ip

        return (ipaddress, netmask, nexthop)

    def _get_external_gateway_address(self, context, router):
        ipaddress, netmask, nexthop = self._get_external_attachment_info(
            context, router)
        return nexthop

    def _vcns_update_static_routes(self, context, **kwargs):
        router = kwargs.get('router')
        if router is None:
            router = self._get_router(context, kwargs['router_id'])

        edge_id = kwargs.get('edge_id')
        if edge_id is None:
            binding = vcns_db.get_vcns_router_binding(context.session,
                                                      router['id'])
            edge_id = binding['edge_id']

        skippable = True
        if 'nexthop' in kwargs:
            nexthop = kwargs['nexthop']
            # The default gateway and vnic config has dependencies, if we
            # explicitly specify nexthop to change, tell the driver not to
            # skip this route update
            skippable = False
        else:
            nexthop = self._get_external_gateway_address(context,
                                                         router)

        if 'subnets' in kwargs:
            subnets = kwargs['subnets']
        else:
            subnets = self._find_router_subnets_cidrs(context.elevated(),
                                                      router['id'])

        routes = []
        for subnet in subnets:
            routes.append({
                'cidr': subnet,
                'nexthop': vcns_const.INTEGRATION_LR_IPADDRESS.split('/')[0]
            })
        self.vcns_driver.update_routes(router['id'], edge_id, nexthop, routes,
                                       skippable)

    def _get_nat_rules(self, context, router):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router['id']).all()

        dnat = []
        snat = []
        for fip in fip_db:
            if fip.fixed_port_id:
                dnat.append({
                    'dst': fip.floating_ip_address,
                    'translated': fip.fixed_ip_address
                })

        gw_port = router.gw_port
        if gw_port and router.enable_snat:
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                subnets = self._find_router_subnets_cidrs(context.elevated(),
                                                          router['id'])
                for subnet in subnets:
                    snat.append({
                        'src': subnet,
                        'translated': snat_ip
                    })

        return (snat, dnat)

    def _update_nat_rules(self, context, router):
        snat, dnat = self._get_nat_rules(context, router)
        binding = vcns_db.get_vcns_router_binding(context.session,
                                                  router['id'])
        self.vcns_driver.update_nat_rules(router['id'],
                                          binding['edge_id'],
                                          snat, dnat)

    def _update_interface(self, context, router):
        addr, mask, nexthop = self._get_external_attachment_info(
            context, router)

        secondary = []
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router['id']).all()
        for fip in fip_db:
            if fip.fixed_port_id:
                secondary.append(fip.floating_ip_address)

        binding = vcns_db.get_vcns_router_binding(context.session,
                                                  router['id'])
        self.vcns_driver.update_interface(
            router['id'], binding['edge_id'],
            vcns_const.EXTERNAL_VNIC_INDEX,
            self.vcns_driver.external_network,
            addr, mask, secondary=secondary)

    def _update_router_gw_info(self, context, router_id, info):
        if not self._is_advanced_service_router(context, router_id):
            super(NvpAdvancedPlugin, self)._update_router_gw_info(
                context, router_id, info)
            return

        # get original gw_port config
        router = self._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, orgnexthop = self._get_external_attachment_info(
            context, router)

        super(NeutronPlugin.NvpPluginV2, self)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_enable_snat = router.enable_snat
        newaddr, newmask, newnexthop = self._get_external_attachment_info(
            context, router)

        binding = vcns_db.get_vcns_router_binding(context.session, router_id)

        if new_ext_net_id != org_ext_net_id and orgnexthop:
            # network changed, need to remove default gateway before vnic
            # can be configured
            LOG.debug(_("VCNS: delete default gateway %s"), orgnexthop)
            self._vcns_update_static_routes(context,
                                            router=router,
                                            edge_id=binding['edge_id'],
                                            nexthop=None)

        if orgaddr != newaddr or orgmask != newmask:
            self.vcns_driver.update_interface(
                router_id, binding['edge_id'],
                vcns_const.EXTERNAL_VNIC_INDEX,
                self.vcns_driver.external_network,
                newaddr, newmask)

        if orgnexthop != newnexthop:
            self._vcns_update_static_routes(context,
                                            router=router,
                                            edge_id=binding['edge_id'],
                                            nexthop=newnexthop)

        if (new_ext_net_id == org_ext_net_id and
            org_enable_snat == new_enable_snat):
            return

        self._update_nat_rules(context, router)

    def _add_subnet_snat_rule(self, router, subnet):
        # NOP for service router
        if not self._is_advanced_service_router(router=router):
            super(NvpAdvancedPlugin, self)._add_subnet_snat_rule(
                router, subnet)

    def _delete_subnet_snat_rule(self, router, subnet):
        # NOP for service router
        if not self._is_advanced_service_router(router=router):
            super(NvpAdvancedPlugin, self)._delete_subnet_snat_rule(
                router, subnet)

    def _remove_floatingip_address(self, context, fip_db):
        # NOP for service router
        router_id = fip_db.router_id
        if not self._is_advanced_service_router(context, router_id):
            super(NvpAdvancedPlugin, self)._remove_floatingip_address(
                context, fip_db)

    def _create_advanced_service_router(self, context, name, lrouter, lswitch):

        # store binding
        binding = vcns_db.add_vcns_router_binding(
            context.session, lrouter['uuid'], None, lswitch['uuid'],
            service_constants.PENDING_CREATE)

        # deploy edge
        jobdata = {
            'lrouter': lrouter,
            'lswitch': lswitch,
            'context': context
        }

        # deploy and wait until the deploy requeste has been requested
        # so we will have edge_id ready. The wait here should be fine
        # as we're not in a database transaction now
        self.vcns_driver.deploy_edge(
            lrouter['uuid'], name, lswitch['uuid'], jobdata=jobdata,
            wait_for_exec=True)

        return binding

    def _create_integration_lswitch(self, tenant_id, name):
        # use defautl transport zone
        transport_zone_config = [{
            "zone_uuid": self.cluster.default_tz_uuid,
            "transport_type": cfg.CONF.NVP.default_transport_type
        }]
        return self.vcns_driver.create_lswitch(name, transport_zone_config)

    def _add_router_integration_interface(self, tenant_id, name,
                                          lrouter, lswitch):
        # create logic switch port
        try:
            ls_port = nvplib.create_lport(
                self.cluster, lswitch['uuid'], tenant_id,
                '', '', lrouter['uuid'], True)
        except NvpApiClient.NvpApiException:
            msg = (_("An exception occured while creating a port "
                     "on lswitch %s") % lswitch['uuid'])
            LOG.exception(msg)
            raise q_exc.NeutronException(message=msg)

        # create logic router port
        try:
            neutron_port_id = ''
            pname = name[:36] + '-lp'
            admin_status_enabled = True
            lr_port = nvplib.create_router_lport(
                self.cluster, lrouter['uuid'], tenant_id,
                neutron_port_id, pname, admin_status_enabled,
                [vcns_const.INTEGRATION_LR_IPADDRESS])
        except NvpApiClient.NvpApiException:
            msg = (_("Unable to create port on NVP logical router %s") % name)
            LOG.exception(msg)
            nvplib.delete_port(self.cluster, lswitch['uuid'], ls_port['uuid'])
            raise q_exc.NeutronException(message=msg)

        # attach logic router port to switch port
        try:
            self._update_router_port_attachment(
                self.cluster, None, lrouter['uuid'], {}, lr_port['uuid'],
                'PatchAttachment', ls_port['uuid'], None)
        except NvpApiClient.NvpApiException as e:
            # lr_port should have been deleted
            nvplib.delete_port(self.cluster, lswitch['uuid'], ls_port['uuid'])
            raise e

    def _create_lrouter(self, context, router, nexthop):
        lrouter = super(NvpAdvancedPlugin, self)._create_lrouter(
            context, router, vcns_const.INTEGRATION_EDGE_IPADDRESS)

        router_type = self._find_router_type(router)
        self._set_router_type(lrouter['uuid'], router_type)
        if router_type == ROUTER_TYPE_BASIC:
            return lrouter

        tenant_id = self._get_tenant_id_for_create(context, router)
        name = router['name']
        try:
            lsname = name[:36] + '-ls'
            lswitch = self._create_integration_lswitch(
                tenant_id, lsname)
        except Exception:
            msg = _("Unable to create integration logic switch "
                    "for router %s") % name
            LOG.exception(msg)
            nvplib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise q_exc.NeutronException(message=msg)

        try:
            self._add_router_integration_interface(tenant_id, name,
                                                   lrouter, lswitch)
        except Exception:
            msg = _("Unable to add router interface to integration lswitch "
                    "for router %s") % name
            LOG.exception(msg)
            nvplib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise q_exc.NeutronException(message=msg)

        try:
            self._create_advanced_service_router(
                context, name, lrouter, lswitch)
        except Exception:
            msg = (_("Unable to create advance service router for %s") % name)
            LOG.exception(msg)
            self.vcns_driver.delete_lswitch(lswitch('uuid'))
            nvplib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise q_exc.NeutronException(message=msg)

        lrouter['status'] = service_constants.PENDING_CREATE
        return lrouter

    def _delete_lrouter(self, context, id):
        if not self._is_advanced_service_router(context, id):
            super(NvpAdvancedPlugin, self)._delete_lrouter(context, id)
            if id in self._router_type:
                del self._router_type[id]
            return

        binding = vcns_db.get_vcns_router_binding(context.session, id)
        if binding:
            vcns_db.update_vcns_router_binding(
                context.session, id, status=service_constants.PENDING_DELETE)

            lswitch_id = binding['lswitch_id']
            edge_id = binding['edge_id']

            # delete lswitch
            try:
                self.vcns_driver.delete_lswitch(lswitch_id)
            except exceptions.ResourceNotFound:
                LOG.warning(_("Did not found lswitch %s in NVP"), lswitch_id)

            # delete edge
            jobdata = {
                'context': context
            }
            self.vcns_driver.delete_edge(id, edge_id, jobdata=jobdata)

        # delete LR
        nvplib.delete_lrouter(self.cluster, id)
        if id in self._router_type:
            del self._router_type[id]

    def _update_lrouter(self, context, router_id, name, nexthop, routes=None):
        if not self._is_advanced_service_router(context, router_id):
            return super(NvpAdvancedPlugin, self)._update_lrouter(
                context, router_id, name, nexthop, routes=routes)

        previous_routes = super(NvpAdvancedPlugin, self)._update_lrouter(
            context, router_id, name,
            vcns_const.INTEGRATION_EDGE_IPADDRESS, routes=routes)

        # TODO(fank): Theoretically users can specify extra routes for
        # physical network, and routes for phyiscal network needs to be
        # configured on Edge. This can be done by checking if nexthop is in
        # external network. But for now we only handle routes for logic
        # space and leave it for future enhancement.

        # Let _update_router_gw_info handle nexthop change
        #self._vcns_update_static_routes(context, router_id=router_id)

        return previous_routes

    def _retrieve_and_delete_nat_rules(self, context, floating_ip_address,
                                       internal_ip, router_id,
                                       min_num_rules_expected=0):
        # NOP for advanced service router
        if not self._is_advanced_service_router(context, router_id):
            super(NvpAdvancedPlugin, self)._retrieve_and_delete_nat_rules(
                context, floating_ip_address, internal_ip, router_id,
                min_num_rules_expected=min_num_rules_expected)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        # Update DB model only  for advanced service router
        router_id = self._get_fip_assoc_data(context, fip, floatingip_db)[2]
        if (router_id and
            not self._is_advanced_service_router(context, router_id)):
            super(NvpAdvancedPlugin, self)._update_fip_assoc(
                context, fip, floatingip_db, external_port)
        else:
            super(NeutronPlugin.NvpPluginV2, self)._update_fip_assoc(
                context, fip, floatingip_db, external_port)

    def _get_nvp_lrouter_status(self, id):
        try:
            lrouter = nvplib.get_lrouter(self.cluster, id)
            lr_status = lrouter["_relations"]["LogicalRouterStatus"]
            if lr_status["fabric_status"]:
                nvp_status = RouterStatus.ROUTER_STATUS_ACTIVE
            else:
                nvp_status = RouterStatus.ROUTER_STATUS_DOWN
        except q_exc.NotFound:
            nvp_status = RouterStatus.ROUTER_STATUS_ERROR

        return nvp_status

    def _get_vse_status(self, context, id):
        binding = vcns_db.get_vcns_router_binding(context.session, id)

        edge_status_level = self.vcns_driver.get_edge_status(
            binding['edge_id'])
        edge_db_status_level = ROUTER_STATUS_LEVEL[binding.status]

        if edge_status_level > edge_db_status_level:
            return edge_status_level
        else:
            return edge_db_status_level

    def _get_all_nvp_lrouters_statuses(self, tenant_id, fields):
        # get nvp lrouters status
        nvp_lrouters = nvplib.get_lrouters(self.cluster,
                                           tenant_id,
                                           fields)

        nvp_status = {}
        for nvp_lrouter in nvp_lrouters:
            if (nvp_lrouter["_relations"]["LogicalRouterStatus"]
                ["fabric_status"]):
                nvp_status[nvp_lrouter['uuid']] = (
                    RouterStatus.ROUTER_STATUS_ACTIVE
                )
            else:
                nvp_status[nvp_lrouter['uuid']] = (
                    RouterStatus.ROUTER_STATUS_DOWN
                )

        return nvp_status

    def _get_all_vse_statuses(self, context):
        bindings = self._model_query(
            context, vcns_models.VcnsRouterBinding)

        vse_db_status_level = {}
        edge_id_to_router_id = {}
        router_ids = []
        for binding in bindings:
            if not binding['edge_id']:
                continue
            router_id = binding['router_id']
            router_ids.append(router_id)
            edge_id_to_router_id[binding['edge_id']] = router_id
            vse_db_status_level[router_id] = (
                ROUTER_STATUS_LEVEL[binding['status']])

        if not vse_db_status_level:
            # no advanced service router, no need to query
            return {}

        vse_status_level = {}
        edges_status_level = self.vcns_driver.get_edges_statuses()
        for edge_id, status_level in edges_status_level.iteritems():
            if edge_id in edge_id_to_router_id:
                router_id = edge_id_to_router_id[edge_id]
                db_status_level = vse_db_status_level[router_id]
                if status_level > db_status_level:
                    vse_status_level[router_id] = status_level
                else:
                    vse_status_level[router_id] = db_status_level

        return vse_status_level

    def get_router(self, context, id, fields=None):
        if fields and 'status' not in fields:
            return super(NvpAdvancedPlugin, self).get_router(
                context, id, fields=fields)

        router = super(NvpAdvancedPlugin, self).get_router(context, id)

        router_type = self._find_router_type(router)
        if router_type == ROUTER_TYPE_ADVANCED:
            vse_status_level = self._get_vse_status(context, id)
            if vse_status_level > ROUTER_STATUS_LEVEL[router['status']]:
                router['status'] = ROUTER_STATUS[vse_status_level]

        return self._fields(router, fields)

    def get_routers(self, context, filters=None, fields=None, **kwargs):
        routers = super(NvpAdvancedPlugin, self).get_routers(
            context, filters=filters, **kwargs)

        if fields and 'status' not in fields:
            # no status checking, just return regular get_routers
            return [self._fields(router, fields) for router in routers]

        for router in routers:
            router_type = self._find_router_type(router)
            if router_type == ROUTER_TYPE_ADVANCED:
                break
        else:
            # no advanced service router, return here
            return [self._fields(router, fields) for router in routers]

        vse_status_all = self._get_all_vse_statuses(context)
        for router in routers:
            router_type = self._find_router_type(router)
            if router_type == ROUTER_TYPE_ADVANCED:
                vse_status_level = vse_status_all.get(router['id'])
                if vse_status_level is None:
                    vse_status_level = RouterStatus.ROUTER_STATUS_ERROR
                if vse_status_level > ROUTER_STATUS_LEVEL[router['status']]:
                    router['status'] = ROUTER_STATUS[vse_status_level]

        return [self._fields(router, fields) for router in routers]

    def add_router_interface(self, context, router_id, interface_info):
        info = super(NvpAdvancedPlugin, self).add_router_interface(
            context, router_id, interface_info)
        if self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            if router.enable_snat:
                self._update_nat_rules(context, router)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._vcns_update_static_routes(context, router=router)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(NvpAdvancedPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        if self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            if router.enable_snat:
                self._update_nat_rules(context, router)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._vcns_update_static_routes(context, router=router)
        return info

    def create_floatingip(self, context, floatingip):
        fip = super(NvpAdvancedPlugin, self).create_floatingip(
            context, floatingip)
        router_id = fip.get('router_id')
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_interface(context, router)
            self._update_nat_rules(context, router)
        return fip

    def update_floatingip(self, context, id, floatingip):
        fip = super(NvpAdvancedPlugin, self).update_floatingip(
            context, id, floatingip)
        router_id = fip.get('router_id')
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_interface(context, router)
            self._update_nat_rules(context, router)
        return fip

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        router_id = None
        if fip_db.fixed_port_id:
            router_id = fip_db.router_id
        super(NvpAdvancedPlugin, self).delete_floatingip(context, id)
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_interface(context, router)
            self._update_nat_rules(context, router)

    def disassociate_floatingips(self, context, port_id):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id).one()
            router_id = fip_db.router_id
        except sa_exc.NoResultFound:
            router_id = None
        super(NvpAdvancedPlugin, self).disassociate_floatingips(context,
                                                                port_id)
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback if error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_interface(context, router)
            self._update_nat_rules(context, router)


class VcnsCallbacks(object):
    """Edge callback implementation

    Callback functions for asynchronous tasks
    """
    def __init__(self, plugin):
        self.plugin = plugin

    def edge_deploy_started(self, task):
        """callback when deployment task started."""
        jobdata = task.userdata['jobdata']
        lrouter = jobdata['lrouter']
        context = jobdata['context']
        edge_id = task.userdata.get('edge_id')
        name = task.userdata['router_name']
        if edge_id:
            LOG.debug(_("Start deploying %(edge_id)s for router %(name)s"), {
                'edge_id': edge_id,
                'name': name})
            vcns_db.update_vcns_router_binding(
                context.session, lrouter['uuid'], edge_id=edge_id)
        else:
                LOG.debug(_("Failed to deploy Edge for router %s"), name)
                vcns_db.update_vcns_router_binding(
                    context.session, lrouter['uuid'],
                    status=service_constants.ERROR)

    def edge_deploy_result(self, task):
        """callback when deployment task finished."""
        jobdata = task.userdata['jobdata']
        lrouter = jobdata['lrouter']
        context = jobdata['context']
        name = task.userdata['router_name']
        router_db = self.plugin._get_router(context, lrouter['uuid'])
        if task.status == TaskStatus.COMPLETED:
            LOG.debug(_("Successfully deployed %(edge_id)s for "
                        "router %(name)s"), {
                            'edge_id': task.userdata['edge_id'],
                            'name': name})
            if router_db['status'] == service_constants.PENDING_CREATE:
                router_db['status'] = service_constants.ACTIVE
                binding = vcns_db.get_vcns_router_binding(
                    context.session, lrouter['uuid'])
                # only update status to active if its status is pending create
                if binding['status'] == service_constants.PENDING_CREATE:
                    vcns_db.update_vcns_router_binding(
                        context.session, lrouter['uuid'],
                        status=service_constants.ACTIVE)
        else:
            LOG.debug(_("Failed to deploy Edge for router %s"), name)
            router_db['status'] = service_constants.ERROR
            vcns_db.update_vcns_router_binding(
                context.session, lrouter['uuid'],
                status=service_constants.ERROR)

    def edge_delete_result(self, task):
        jobdata = task.userdata['jobdata']
        router_id = task.userdata['router_id']
        context = jobdata['context']
        if task.status == TaskStatus.COMPLETED:
            vcns_db.delete_vcns_router_binding(context.session,
                                               router_id)

    def interface_update_result(self, task):
        LOG.debug(_("interface_update_result %d"), task.status)

    def snat_create_result(self, task):
        LOG.debug(_("snat_create_result %d"), task.status)

    def snat_delete_result(self, task):
        LOG.debug(_("snat_delete_result %d"), task.status)

    def dnat_create_result(self, task):
        LOG.debug(_("dnat_create_result %d"), task.status)

    def dnat_delete_result(self, task):
        LOG.debug(_("dnat_delete_result %d"), task.status)

    def routes_update_result(self, task):
        LOG.debug(_("routes_update_result %d"), task.status)

    def nat_update_result(self, task):
        LOG.debug(_("nat_update_result %d"), task.status)
