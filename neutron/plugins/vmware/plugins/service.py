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

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.db.firewall import firewall_db
from neutron.db import l3_db
from neutron.db.loadbalancer import loadbalancer_db
from neutron.db import routedserviceinsertion_db as rsi_db
from neutron.db.vpn import vpn_db
from neutron.extensions import firewall as fw_ext
from neutron.extensions import l3
from neutron.extensions import routedserviceinsertion as rsi
from neutron.extensions import vpnaas as vpn_ext
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as service_constants
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import config  # noqa
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.dbexts import servicerouter as sr_db
from neutron.plugins.vmware.dbexts import vcns_db
from neutron.plugins.vmware.dbexts import vcns_models
from neutron.plugins.vmware.extensions import servicerouter as sr
from neutron.plugins.vmware.nsxlib import router as routerlib
from neutron.plugins.vmware.nsxlib import switch as switchlib
from neutron.plugins.vmware.plugins import base
from neutron.plugins.vmware.vshield.common import constants as vcns_const
from neutron.plugins.vmware.vshield.common import exceptions
from neutron.plugins.vmware.vshield.tasks import constants as tasks_const
from neutron.plugins.vmware.vshield import vcns_driver
from sqlalchemy.orm import exc as sa_exc

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
    service_constants.ACTIVE: vcns_const.RouterStatus.ROUTER_STATUS_ACTIVE,
    service_constants.DOWN: vcns_const.RouterStatus.ROUTER_STATUS_DOWN,
    service_constants.PENDING_CREATE: (
        vcns_const.RouterStatus.ROUTER_STATUS_PENDING_CREATE
    ),
    service_constants.PENDING_DELETE: (
        vcns_const.RouterStatus.ROUTER_STATUS_PENDING_DELETE
    ),
    service_constants.ERROR: vcns_const.RouterStatus.ROUTER_STATUS_ERROR
}


class NsxAdvancedPlugin(sr_db.ServiceRouter_mixin,
                        base.NsxPluginV2,
                        rsi_db.RoutedServiceInsertionDbMixin,
                        firewall_db.Firewall_db_mixin,
                        loadbalancer_db.LoadBalancerPluginDb,
                        vpn_db.VPNPluginDb
                        ):

    supported_extension_aliases = (
        base.NsxPluginV2.supported_extension_aliases + [
            "service-router",
            "routed-service-insertion",
            "fwaas",
            "lbaas",
            "vpnaas"
        ])
    # The service plugin cannot currently support pagination
    __native_pagination_support = False
    __native_sorting_support = False

    def __init__(self):
        super(NsxAdvancedPlugin, self).__init__()

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
        self.callbacks = VcnsCallbacks(self.safe_reference)

        # load the vCNS driver
        self._load_vcns_drivers()

        # switchlib's create_lswitch needs to be replaced in order to proxy
        # logical switch create requests to vcns
        self._set_create_lswitch_proxy()

    def _set_create_lswitch_proxy(self):
        base.switchlib.create_lswitch = self._proxy_create_lswitch

    def _proxy_create_lswitch(self, *args, **kwargs):
        name, tz_config, tags = (
            _process_base_create_lswitch_args(*args, **kwargs)
        )
        return self.vcns_driver.create_lswitch(
            name, tz_config, tags=tags,
            port_isolation=None, replication_mode=None)

    def _load_vcns_drivers(self):
        self.vcns_driver = vcns_driver.VcnsDriver(self.callbacks)

    def _set_router_type(self, router_id, router_type):
        self._router_type[router_id] = router_type

    def _get_router_type(self, context=None, router_id=None, router=None):
        if not router:
            if router_id in self._router_type:
                return self._router_type[router_id]
            router = self._get_router(context, router_id)

        LOG.debug("EDGE: router = %s", router)
        if router['extra_attributes']['service_router']:
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
        LOG.debug("EDGE: _vcns_create_ext_gw_port")

    def _vcns_delete_ext_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        if not self._is_advanced_service_router(context, router_id):
            self._super_delete_ext_gw_port(context, port_data)
            return

        # NOP for Edge
        LOG.debug("EDGE: _vcns_delete_ext_gw_port")

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
                    raise n_exc.BadRequest(resource='router', msg=msg)
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

    def _update_interface(self, context, router, sync=False):
        addr, mask, nexthop = self._get_external_attachment_info(
            context, router)

        secondary = []
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router['id']).all()
        for fip in fip_db:
            if fip.fixed_port_id:
                secondary.append(fip.floating_ip_address)
        #Add all vip addresses bound on the router
        vip_addrs = self._get_all_vip_addrs_by_router_id(context,
                                                         router['id'])
        secondary.extend(vip_addrs)

        binding = vcns_db.get_vcns_router_binding(context.session,
                                                  router['id'])
        task = self.vcns_driver.update_interface(
            router['id'], binding['edge_id'],
            vcns_const.EXTERNAL_VNIC_INDEX,
            self.vcns_driver.external_network,
            addr, mask, secondary=secondary)
        if sync:
            task.wait(tasks_const.TaskState.RESULT)

    def _update_router_gw_info(self, context, router_id, info):
        if not self._is_advanced_service_router(context, router_id):
            super(NsxAdvancedPlugin, self)._update_router_gw_info(
                context, router_id, info)
            return

        # get original gw_port config
        router = self._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, orgnexthop = self._get_external_attachment_info(
            context, router)

        super(base.NsxPluginV2, self)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_enable_snat = router.enable_snat
        newaddr, newmask, newnexthop = self._get_external_attachment_info(
            context, router)

        binding = vcns_db.get_vcns_router_binding(context.session, router_id)

        if new_ext_net_id != org_ext_net_id and orgnexthop:
            # network changed, need to remove default gateway before vnic
            # can be configured
            LOG.debug("VCNS: delete default gateway %s", orgnexthop)
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

    def _add_subnet_snat_rule(self, context, router, subnet):
        # NOP for service router
        if not self._is_advanced_service_router(router=router):
            super(NsxAdvancedPlugin, self)._add_subnet_snat_rule(
                context, router, subnet)

    def _delete_subnet_snat_rule(self, context, router, subnet):
        # NOP for service router
        if not self._is_advanced_service_router(router=router):
            super(NsxAdvancedPlugin, self)._delete_subnet_snat_rule(
                context, router, subnet)

    def _remove_floatingip_address(self, context, fip_db):
        # NOP for service router
        router_id = fip_db.router_id
        if not self._is_advanced_service_router(context, router_id):
            super(NsxAdvancedPlugin, self)._remove_floatingip_address(
                context, fip_db)

    def _create_advanced_service_router(self, context, neutron_router_id,
                                        name, lrouter, lswitch):

        # store binding
        binding = vcns_db.add_vcns_router_binding(
            context.session, neutron_router_id, None, lswitch['uuid'],
            service_constants.PENDING_CREATE)

        # deploy edge
        jobdata = {
            'neutron_router_id': neutron_router_id,
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
            "transport_type": cfg.CONF.NSX.default_transport_type
        }]
        return self.vcns_driver.create_lswitch(name, transport_zone_config)

    def _add_router_integration_interface(self, tenant_id, name,
                                          lrouter, lswitch):
        # create logic switch port
        try:
            ls_port = switchlib.create_lport(
                self.cluster, lswitch['uuid'], tenant_id,
                '', '', lrouter['uuid'], True)
        except api_exc.NsxApiException:
            msg = (_("An exception occurred while creating a port "
                     "on lswitch %s") % lswitch['uuid'])
            LOG.exception(msg)
            raise n_exc.NeutronException(message=msg)

        # create logic router port
        try:
            neutron_port_id = ''
            pname = name[:36] + '-lp'
            admin_status_enabled = True
            lr_port = routerlib.create_router_lport(
                self.cluster, lrouter['uuid'], tenant_id,
                neutron_port_id, pname, admin_status_enabled,
                [vcns_const.INTEGRATION_LR_IPADDRESS])
        except api_exc.NsxApiException:
            msg = (_("Unable to create port on NSX logical router %s") % name)
            LOG.exception(msg)
            switchlib.delete_port(
                self.cluster, lswitch['uuid'], ls_port['uuid'])
            raise n_exc.NeutronException(message=msg)

        # attach logic router port to switch port
        try:
            self._update_router_port_attachment(
                self.cluster, None, lrouter['uuid'], {}, lr_port['uuid'],
                'PatchAttachment', ls_port['uuid'], None)
        except api_exc.NsxApiException as e:
            # lr_port should have been deleted
            switchlib.delete_port(
                self.cluster, lswitch['uuid'], ls_port['uuid'])
            raise e

    def _create_lrouter(self, context, router, nexthop):
        lrouter = super(NsxAdvancedPlugin, self)._create_lrouter(
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
            routerlib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise n_exc.NeutronException(message=msg)

        try:
            self._add_router_integration_interface(tenant_id, name,
                                                   lrouter, lswitch)
        except Exception:
            msg = _("Unable to add router interface to integration lswitch "
                    "for router %s") % name
            LOG.exception(msg)
            routerlib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise n_exc.NeutronException(message=msg)

        try:
            self._create_advanced_service_router(
                context, router['id'], name, lrouter, lswitch)
        except Exception:
            msg = (_("Unable to create advance service router for %s") % name)
            LOG.exception(msg)
            self.vcns_driver.delete_lswitch(lswitch('uuid'))
            routerlib.delete_lrouter(self.cluster, lrouter['uuid'])
            raise n_exc.NeutronException(message=msg)

        lrouter['status'] = service_constants.PENDING_CREATE
        return lrouter

    def check_router_in_use(self, context, router_id):
        router_filter = {'router_id': [router_id]}
        vpnservices = self.get_vpnservices(
            context, filters={'router_id': [router_id]})
        if vpnservices:
            raise vpn_ext.RouterInUseByVPNService(
                router_id=router_id,
                vpnservice_id=vpnservices[0]['id'])
        vips = self.get_vips(
            context, filters=router_filter)
        if vips:
            raise nsx_exc.RouterInUseByLBService(
                router_id=router_id,
                vip_id=vips[0]['id'])
        firewalls = self.get_firewalls(
            context, filters=router_filter)
        if firewalls:
            raise nsx_exc.RouterInUseByFWService(
                router_id=router_id,
                firewall_id=firewalls[0]['id'])

    def _delete_lrouter(self, context, router_id, nsx_router_id):
        binding = vcns_db.get_vcns_router_binding(context.session, router_id)
        if not binding:
            super(NsxAdvancedPlugin, self)._delete_lrouter(
                context, router_id, nsx_router_id)
        else:
            #Check whether router has an advanced service inserted.
            self.check_router_in_use(context, router_id)
            vcns_db.update_vcns_router_binding(
                context.session, router_id,
                status=service_constants.PENDING_DELETE)

            lswitch_id = binding['lswitch_id']
            edge_id = binding['edge_id']

            # delete lswitch
            try:
                self.vcns_driver.delete_lswitch(lswitch_id)
            except exceptions.ResourceNotFound:
                LOG.warning(_("Did not found lswitch %s in NSX"), lswitch_id)

            # delete edge
            jobdata = {
                'context': context
            }
            self.vcns_driver.delete_edge(router_id, edge_id, jobdata=jobdata)

            # delete NSX logical router
            routerlib.delete_lrouter(self.cluster, nsx_router_id)

        if id in self._router_type:
            del self._router_type[router_id]

    def _update_lrouter(self, context, router_id, name, nexthop, routes=None):
        if not self._is_advanced_service_router(context, router_id):
            return super(NsxAdvancedPlugin, self)._update_lrouter(
                context, router_id, name, nexthop, routes=routes)

        previous_routes = super(NsxAdvancedPlugin, self)._update_lrouter(
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
            super(NsxAdvancedPlugin, self)._retrieve_and_delete_nat_rules(
                context, floating_ip_address, internal_ip, router_id,
                min_num_rules_expected=min_num_rules_expected)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        # Update DB model only  for advanced service router
        router_id = self._get_fip_assoc_data(context, fip, floatingip_db)[2]
        if (router_id and
            not self._is_advanced_service_router(context, router_id)):
            super(NsxAdvancedPlugin, self)._update_fip_assoc(
                context, fip, floatingip_db, external_port)
        else:
            super(base.NsxPluginV2, self)._update_fip_assoc(
                context, fip, floatingip_db, external_port)

    def _get_nsx_lrouter_status(self, id):
        try:
            lrouter = routerlib.get_lrouter(self.cluster, id)
            lr_status = lrouter["_relations"]["LogicalRouterStatus"]
            if lr_status["fabric_status"]:
                nsx_status = vcns_const.RouterStatus.ROUTER_STATUS_ACTIVE
            else:
                nsx_status = vcns_const.RouterStatus.ROUTER_STATUS_DOWN
        except n_exc.NotFound:
            nsx_status = vcns_const.RouterStatus.ROUTER_STATUS_ERROR

        return nsx_status

    def _get_vse_status(self, context, id):
        binding = vcns_db.get_vcns_router_binding(context.session, id)
        edge_status_level = self.vcns_driver.get_edge_status(
            binding['edge_id'])
        edge_db_status_level = ROUTER_STATUS_LEVEL[binding.status]

        if edge_status_level > edge_db_status_level:
            return edge_status_level
        else:
            return edge_db_status_level

    def _get_all_nsx_lrouters_statuses(self, tenant_id, fields):
        # get nsx lrouters status
        nsx_lrouters = routerlib.get_lrouters(self.cluster,
                                              tenant_id,
                                              fields)

        nsx_status = {}
        for nsx_lrouter in nsx_lrouters:
            if (nsx_lrouter["_relations"]["LogicalRouterStatus"]
                ["fabric_status"]):
                nsx_status[nsx_lrouter['uuid']] = (
                    vcns_const.RouterStatus.ROUTER_STATUS_ACTIVE
                )
            else:
                nsx_status[nsx_lrouter['uuid']] = (
                    vcns_const.RouterStatus.ROUTER_STATUS_DOWN
                )

        return nsx_status

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
            return super(NsxAdvancedPlugin, self).get_router(
                context, id, fields=fields)

        router = super(NsxAdvancedPlugin, self).get_router(context, id)

        router_type = self._find_router_type(router)
        if router_type == ROUTER_TYPE_ADVANCED:
            vse_status_level = self._get_vse_status(context, id)
            if vse_status_level > ROUTER_STATUS_LEVEL[router['status']]:
                router['status'] = ROUTER_STATUS[vse_status_level]

        return self._fields(router, fields)

    def get_routers(self, context, filters=None, fields=None, **kwargs):
        routers = super(NsxAdvancedPlugin, self).get_routers(
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
                    vse_status_level = (
                        vcns_const.RouterStatus.ROUTER_STATUS_ERROR)
                if vse_status_level > ROUTER_STATUS_LEVEL[router['status']]:
                    router['status'] = ROUTER_STATUS[vse_status_level]

        return [self._fields(router, fields) for router in routers]

    def add_router_interface(self, context, router_id, interface_info):
        info = super(NsxAdvancedPlugin, self).add_router_interface(
            context, router_id, interface_info)
        if self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            if router.enable_snat:
                self._update_nat_rules(context, router)
            # TODO(fank): do rollback on error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._vcns_update_static_routes(context, router=router)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(NsxAdvancedPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        if self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            if router.enable_snat:
                self._update_nat_rules(context, router)
            # TODO(fank): do rollback on error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._vcns_update_static_routes(context, router=router)
        return info

    def create_floatingip(self, context, floatingip):
        fip = super(NsxAdvancedPlugin, self).create_floatingip(
            context, floatingip)
        router_id = fip.get('router_id')
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback on error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_nat_rules(context, router)
            self._update_interface(context, router)
        return fip

    def update_floatingip(self, context, id, floatingip):
        fip = super(NsxAdvancedPlugin, self).update_floatingip(
            context, id, floatingip)
        router_id = fip.get('router_id')
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback on error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_nat_rules(context, router)
            self._update_interface(context, router)
        elif not router_id:
            # The floating IP has been disassociated and should be set to DOWN
            self.update_floatingip_status(context, fip['id'],
                                          constants.FLOATINGIP_STATUS_DOWN)
        return fip

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        router_id = None
        if fip_db.fixed_port_id:
            router_id = fip_db.router_id
        super(NsxAdvancedPlugin, self).delete_floatingip(context, id)
        if router_id and self._is_advanced_service_router(context, router_id):
            router = self._get_router(context, router_id)
            # TODO(fank): do rollback on error, or have a dedicated thread
            # do sync work (rollback, re-configure, or make router down)
            self._update_interface(context, router)
            self._update_nat_rules(context, router)

    def disassociate_floatingips(self, context, port_id):
        routers = set()

        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)
            for fip_db in fip_dbs:
                routers.add(fip_db.router_id)
        except sa_exc.NoResultFound:
            pass
        super(NsxAdvancedPlugin, self).disassociate_floatingips(context,
                                                                port_id)

        for router_id in routers:
            if self._is_advanced_service_router(context, router_id):
                router = self._get_router(context, router_id)
                # TODO(fank): do rollback on error, or have a dedicated thread
                # do sync work (rollback, re-configure, or make router down)
                self._update_interface(context, router)
                self._update_nat_rules(context, router)

    #
    # FWaaS plugin implementation
    #
    def _firewall_set_status(
        self, context, firewall_id, status, firewall=None):
        with context.session.begin(subtransactions=True):
            fw_db = self._get_firewall(context, firewall_id)
            if status == service_constants.PENDING_UPDATE and (
                fw_db.status == service_constants.PENDING_DELETE):
                    raise fw_ext.FirewallInPendingState(
                        firewall_id=firewall_id, pending_state=status)
            else:
                fw_db.status = status
                if firewall:
                    firewall['status'] = status

    def _ensure_firewall_update_allowed(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [service_constants.PENDING_CREATE,
                               service_constants.PENDING_UPDATE,
                               service_constants.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_firewall_policy_update_allowed(
        self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        for firewall_id in firewall_policy.get('firewall_list', []):
            self._ensure_firewall_update_allowed(context, firewall_id)

    def _ensure_update_or_delete_firewall_rule(
        self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if fw_rule.get('firewall_policy_id'):
            self._ensure_firewall_policy_update_allowed(
                context, fw_rule['firewall_policy_id'])

    def _make_firewall_rule_list_by_policy_id(self, context, fw_policy_id):
        if not fw_policy_id:
            return []
        firewall_policy_db = self._get_firewall_policy(context, fw_policy_id)
        return [
            self._make_firewall_rule_dict(fw_rule_db)
            for fw_rule_db in firewall_policy_db['firewall_rules']
        ]

    def _get_edge_id_by_vcns_edge_binding(self, context,
                                          router_id):
        #Get vcns_router_binding mapping between router and edge
        router_binding = vcns_db.get_vcns_router_binding(
            context.session, router_id)
        return router_binding.edge_id

    def _get_firewall_list_from_firewall_policy(self, context, policy_id):
        firewall_policy_db = self._get_firewall_policy(context, policy_id)
        return [
            self._make_firewall_dict(fw_db)
            for fw_db in firewall_policy_db['firewalls']
        ]

    def _get_firewall_list_from_firewall_rule(self, context, rule_id):
        rule = self._get_firewall_rule(context, rule_id)
        if not rule.firewall_policy_id:
            # The firewall rule is not associated with firewall policy yet
            return None

        return self._get_firewall_list_from_firewall_policy(
            context, rule.firewall_policy_id)

    def _vcns_update_firewall(self, context, fw, router_id=None, **kwargs):
        edge_id = kwargs.get('edge_id')
        if not edge_id:
            edge_id = self._get_edge_id_by_vcns_edge_binding(
                context, router_id)
        firewall_rule_list = kwargs.get('firewall_rule_list')
        if not firewall_rule_list:
            firewall_rule_list = self._make_firewall_rule_list_by_policy_id(
                context, fw['firewall_policy_id'])
        fw_with_rules = fw
        fw_with_rules['firewall_rule_list'] = firewall_rule_list
        try:
            self.vcns_driver.update_firewall(context, edge_id, fw_with_rules)
        except exceptions.VcnsApiException as e:
            self._firewall_set_status(
                context, fw['id'], service_constants.ERROR)
            msg = (_("Failed to create firewall on vShield Edge "
                     "bound on router %s") % router_id)
            LOG.exception(msg)
            raise e

        except exceptions.VcnsBadRequest as e:
            self._firewall_set_status(
                context, fw['id'], service_constants.ERROR)
            LOG.exception(_("Bad Firewall request Input"))
            raise e

    def _vcns_delete_firewall(self, context, router_id=None, **kwargs):
        edge_id = kwargs.get('edge_id')
        if not edge_id:
            edge_id = self._get_edge_id_by_vcns_edge_binding(
                context, router_id)
        #TODO(linb):do rollback on error
        self.vcns_driver.delete_firewall(context, edge_id)

    def create_firewall(self, context, firewall):
        LOG.debug("create_firewall() called")
        router_id = firewall['firewall'].get(vcns_const.ROUTER_ID)
        if not router_id:
            msg = _("router_id is not provided!")
            LOG.error(msg)
            raise n_exc.BadRequest(resource='router', msg=msg)
        if not self._is_advanced_service_router(context, router_id):
            msg = _("router_id:%s is not an advanced router!") % router_id
            LOG.error(msg)
            raise n_exc.BadRequest(resource='router', msg=msg)
        if self._get_resource_router_id_binding(
            context, firewall_db.Firewall, router_id=router_id):
            msg = _("A firewall is already associated with the router")
            LOG.error(msg)
            raise nsx_exc.ServiceOverQuota(
                overs='firewall', err_msg=msg)

        fw = super(NsxAdvancedPlugin, self).create_firewall(context, firewall)
        #Add router service insertion binding with firewall object
        res = {
            'id': fw['id'],
            'router_id': router_id
        }
        self._process_create_resource_router_id(
            context, res, firewall_db.Firewall)
        # Since there is only one firewall per edge,
        # here would be bulk configuration operation on firewall
        self._vcns_update_firewall(context, fw, router_id)
        self._firewall_set_status(
            context, fw['id'], service_constants.ACTIVE, fw)
        fw[rsi.ROUTER_ID] = router_id
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug("update_firewall() called")
        self._ensure_firewall_update_allowed(context, id)
        service_router_binding = self._get_resource_router_id_binding(
            context, firewall_db.Firewall, resource_id=id)
        rule_list_pre = self._make_firewall_rule_list_by_policy_id(
            context,
            self.get_firewall(context, id)['firewall_policy_id'])
        firewall['firewall']['status'] = service_constants.PENDING_UPDATE
        fw = super(NsxAdvancedPlugin, self).update_firewall(
            context, id, firewall)
        fw[rsi.ROUTER_ID] = service_router_binding['router_id']
        rule_list_new = self._make_firewall_rule_list_by_policy_id(
            context, fw['firewall_policy_id'])
        if rule_list_pre == rule_list_new:
            self._firewall_set_status(
                context, fw['id'], service_constants.ACTIVE, fw)
            return fw
        else:
            self._vcns_update_firewall(
                context, fw, service_router_binding.router_id,
                firewall_rule_list=rule_list_new)
            self._firewall_set_status(
                context, fw['id'], service_constants.ACTIVE, fw)
            return fw

    def delete_firewall(self, context, id):
        LOG.debug("delete_firewall() called")
        self._firewall_set_status(
            context, id, service_constants.PENDING_DELETE)
        service_router_binding = self._get_resource_router_id_binding(
            context, firewall_db.Firewall, resource_id=id)
        self._vcns_delete_firewall(context, service_router_binding.router_id)
        super(NsxAdvancedPlugin, self).delete_firewall(context, id)
        self._delete_resource_router_id_binding(
            context, id, firewall_db.Firewall)

    def get_firewall(self, context, id, fields=None):
        fw = super(NsxAdvancedPlugin, self).get_firewall(
            context, id, fields)
        if fields and rsi.ROUTER_ID not in fields:
            return fw

        service_router_binding = self._get_resource_router_id_binding(
            context, firewall_db.Firewall, resource_id=fw['id'])
        fw[rsi.ROUTER_ID] = service_router_binding['router_id']
        return fw

    def get_firewalls(self, context, filters=None, fields=None):
        fws = super(NsxAdvancedPlugin, self).get_firewalls(
            context, filters, fields)
        if fields and rsi.ROUTER_ID not in fields:
            return fws
        service_router_bindings = self._get_resource_router_id_bindings(
            context, firewall_db.Firewall,
            resource_ids=[fw['id'] for fw in fws])
        mapping = dict([(binding['resource_id'], binding['router_id'])
                        for binding in service_router_bindings])
        for fw in fws:
            fw[rsi.ROUTER_ID] = mapping[fw['id']]
        return fws

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() called")
        self._ensure_update_or_delete_firewall_rule(context, id)
        fwr_pre = self.get_firewall_rule(context, id)
        fwr = super(NsxAdvancedPlugin, self).update_firewall_rule(
            context, id, firewall_rule)
        if fwr_pre == fwr:
            return fwr

        # check if this rule is associated with firewall
        fw_list = self._get_firewall_list_from_firewall_rule(context, id)
        if not fw_list:
            return fwr

        for fw in fw_list:
            # get router service insertion binding with firewall id
            service_router_binding = self._get_resource_router_id_binding(
                context, firewall_db.Firewall, resource_id=fw['id'])
            edge_id = self._get_edge_id_by_vcns_edge_binding(
                context, service_router_binding.router_id)

            #TODO(linb): do rollback on error
            self.vcns_driver.update_firewall_rule(context, id, edge_id, fwr)

        return fwr

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy() called")
        self._ensure_firewall_policy_update_allowed(context, id)
        firewall_rules_pre = self._make_firewall_rule_list_by_policy_id(
            context, id)
        fwp = super(NsxAdvancedPlugin, self).update_firewall_policy(
            context, id, firewall_policy)
        firewall_rules = self._make_firewall_rule_list_by_policy_id(
            context, id)
        if firewall_rules_pre == firewall_rules:
            return fwp

        # check if this policy is associated with firewall
        fw_list = self._get_firewall_list_from_firewall_policy(context, id)
        if not fw_list:
            return fwp

        for fw in fw_list:
            # Get the router_service insertion binding with firewall id
            # TODO(fank): optimized by using _get_resource_router_id_bindings
            service_router_binding = self._get_resource_router_id_binding(
                context, firewall_db.Firewall, resource_id=fw['id'])
            self._vcns_update_firewall(
                context, fw, service_router_binding.router_id,
                firewall_rule_list=firewall_rules)
        return fwp

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._ensure_firewall_policy_update_allowed(context, id)
        fwp = super(NsxAdvancedPlugin, self).insert_rule(
            context, id, rule_info)
        fwr = super(NsxAdvancedPlugin, self).get_firewall_rule(
            context, rule_info['firewall_rule_id'])

        # check if this policy is associated with firewall
        fw_list = self._get_firewall_list_from_firewall_policy(context, id)
        if not fw_list:
            return fwp
        for fw in fw_list:
            # TODO(fank): optimized by using _get_resource_router_id_bindings
            service_router_binding = self._get_resource_router_id_binding(
                context, firewall_db.Firewall, resource_id=fw['id'])
            edge_id = self._get_edge_id_by_vcns_edge_binding(
                context, service_router_binding.router_id)

            if rule_info.get('insert_before') or rule_info.get('insert_after'):
                #if insert_before or insert_after is set, we would call
                #VCNS insert_rule API
                #TODO(linb): do rollback on error
                self.vcns_driver.insert_rule(context, rule_info, edge_id, fwr)
            else:
                #Else we would call bulk configuration on the firewall
                self._vcns_update_firewall(context, fw, edge_id=edge_id)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._ensure_firewall_policy_update_allowed(context, id)
        fwp = super(NsxAdvancedPlugin, self).remove_rule(
            context, id, rule_info)
        fwr = super(NsxAdvancedPlugin, self).get_firewall_rule(
            context, rule_info['firewall_rule_id'])

        # check if this policy is associated with firewall
        fw_list = self._get_firewall_list_from_firewall_policy(context, id)
        if not fw_list:
            return fwp
        for fw in fw_list:
            # TODO(fank): optimized by using _get_resource_router_id_bindings
            service_router_binding = self._get_resource_router_id_binding(
                context, firewall_db.Firewall, resource_id=fw['id'])
            edge_id = self._get_edge_id_by_vcns_edge_binding(
                context, service_router_binding.router_id)
            #TODO(linb): do rollback on error
            self.vcns_driver.delete_firewall_rule(
                context, fwr['id'], edge_id)
        return fwp

    #
    # LBAAS service plugin implementation
    #
    def _get_edge_id_by_vip_id(self, context, vip_id):
        try:
            service_router_binding = self._get_resource_router_id_binding(
                context, loadbalancer_db.Vip, resource_id=vip_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to find the edge with "
                                "vip_id: %s"), vip_id)
        return self._get_edge_id_by_vcns_edge_binding(
            context, service_router_binding.router_id)

    def _get_all_vip_addrs_by_router_id(
        self, context, router_id):
        vip_bindings = self._get_resource_router_id_bindings(
            context, loadbalancer_db.Vip, router_ids=[router_id])
        vip_addrs = []
        for vip_binding in vip_bindings:
            vip = self.get_vip(context, vip_binding.resource_id)
            vip_addrs.append(vip.get('address'))
        return vip_addrs

    def _add_router_service_insertion_binding(self, context, resource_id,
                                              router_id,
                                              model):
        res = {
            'id': resource_id,
            'router_id': router_id
        }
        self._process_create_resource_router_id(context, res,
                                                model)

    def _resource_set_status(self, context, model, id, status, obj=None,
                             pool_id=None):
        with context.session.begin(subtransactions=True):
            try:
                qry = context.session.query(model)
                if issubclass(model, loadbalancer_db.PoolMonitorAssociation):
                    res = qry.filter_by(monitor_id=id,
                                        pool_id=pool_id).one()
                else:
                    res = qry.filter_by(id=id).one()
                if status == service_constants.PENDING_UPDATE and (
                    res.get('status') == service_constants.PENDING_DELETE):
                    msg = (_("Operation can't be performed, Since resource "
                             "%(model)s : %(id)s is in DELETEing status!") %
                           {'model': model,
                            'id': id})
                    LOG.error(msg)
                    raise nsx_exc.NsxPluginException(err_msg=msg)
                else:
                    res.status = status
            except sa_exc.NoResultFound:
                msg = (_("Resource %(model)s : %(id)s not found!") %
                       {'model': model,
                        'id': id})
                LOG.exception(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)
            if obj:
                obj['status'] = status

    def _vcns_create_pool_and_monitors(self, context, pool_id, **kwargs):
        pool = self.get_pool(context, pool_id)
        edge_id = kwargs.get('edge_id')
        if not edge_id:
            edge_id = self._get_edge_id_by_vip_id(
                context, pool['vip_id'])
        #Check wheter the pool is already created on the router
        #in case of future's M:N relation between Pool and Vip

        #Check associated HealthMonitors and then create them
        for monitor_id in pool.get('health_monitors'):
            hm = self.get_health_monitor(context, monitor_id)
            try:
                self.vcns_driver.create_health_monitor(
                    context, edge_id, hm)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Failed to create healthmonitor "
                                    "associated with pool id: %s!") % pool_id)
                    for monitor_ide in pool.get('health_monitors'):
                        if monitor_ide == monitor_id:
                            break
                        self.vcns_driver.delete_health_monitor(
                            context, monitor_ide, edge_id)
        #Create the pool on the edge
        members = [
            super(NsxAdvancedPlugin, self).get_member(
                context, member_id)
            for member_id in pool.get('members')
        ]
        try:
            self.vcns_driver.create_pool(context, edge_id, pool, members)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create pool on vshield edge"))
                self.vcns_driver.delete_pool(
                    context, pool_id, edge_id)
                for monitor_id in pool.get('health_monitors'):
                    self.vcns_driver.delete_health_monitor(
                        context, monitor_id, edge_id)

    def _vcns_update_pool(self, context, pool, **kwargs):
        edge_id = self._get_edge_id_by_vip_id(context, pool['vip_id'])
        members = kwargs.get('members')
        if not members:
            members = [
                super(NsxAdvancedPlugin, self).get_member(
                    context, member_id)
                for member_id in pool.get('members')
            ]
        self.vcns_driver.update_pool(context, edge_id, pool, members)

    def create_vip(self, context, vip):
        LOG.debug("create_vip() called")
        router_id = vip['vip'].get(vcns_const.ROUTER_ID)
        if not router_id:
            msg = _("router_id is not provided!")
            LOG.error(msg)
            raise n_exc.BadRequest(resource='router', msg=msg)

        if not self._is_advanced_service_router(context, router_id):
            msg = _("router_id: %s is not an advanced router!") % router_id
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        #Check whether the vip port is an external port
        subnet_id = vip['vip']['subnet_id']
        network_id = self.get_subnet(context, subnet_id)['network_id']
        ext_net = self._get_network(context, network_id)
        if not ext_net.external:
            msg = (_("Network '%s' is not a valid external "
                     "network") % network_id)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        v = super(NsxAdvancedPlugin, self).create_vip(context, vip)
        #Get edge_id for the resource
        router_binding = vcns_db.get_vcns_router_binding(
            context.session,
            router_id)
        edge_id = router_binding.edge_id
        #Add vip_router binding
        self._add_router_service_insertion_binding(context, v['id'],
                                                   router_id,
                                                   loadbalancer_db.Vip)
        #Create the vip port on vShield Edge
        router = self._get_router(context, router_id)
        self._update_interface(context, router, sync=True)
        #Create the vip and associated pool/monitor on the corresponding edge
        try:
            self._vcns_create_pool_and_monitors(
                context, v['pool_id'], edge_id=edge_id)
            self.vcns_driver.create_vip(context, edge_id, v)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create vip!"))
                self._delete_resource_router_id_binding(
                    context, v['id'], loadbalancer_db.Vip)
                super(NsxAdvancedPlugin, self).delete_vip(context, v['id'])
        self._resource_set_status(context, loadbalancer_db.Vip,
                                  v['id'], service_constants.ACTIVE, v)
        v[rsi.ROUTER_ID] = router_id

        return v

    def update_vip(self, context, id, vip):
        edge_id = self._get_edge_id_by_vip_id(context, id)
        old_vip = self.get_vip(context, id)
        session_persistence_update = bool(
            vip['vip'].get('session_persistence'))
        vip['vip']['status'] = service_constants.PENDING_UPDATE
        v = super(NsxAdvancedPlugin, self).update_vip(context, id, vip)
        v[rsi.ROUTER_ID] = self._get_resource_router_id_binding(
            context, loadbalancer_db.Vip, resource_id=id)['router_id']
        if old_vip['pool_id'] != v['pool_id']:
            self.vcns_driver.delete_vip(context, id)
            #Delete old pool/monitor on the edge
            #TODO(linb): Factor out procedure for removing pool and health
            #separate method
            old_pool = self.get_pool(context, old_vip['pool_id'])
            self.vcns_driver.delete_pool(
                context, old_vip['pool_id'], edge_id)
            for monitor_id in old_pool.get('health_monitors'):
                self.vcns_driver.delete_health_monitor(
                    context, monitor_id, edge_id)
            #Create new pool/monitor object on the edge
            #TODO(linb): add exception handle if error
            self._vcns_create_pool_and_monitors(
                context, v['pool_id'], edge_id=edge_id)
            self.vcns_driver.create_vip(context, edge_id, v)
            return v
        try:
            self.vcns_driver.update_vip(context, v, session_persistence_update)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update vip with id: %s!"), id)
                self._resource_set_status(context, loadbalancer_db.Vip,
                                          id, service_constants.ERROR, v)

        self._resource_set_status(context, loadbalancer_db.Vip,
                                  v['id'], service_constants.ACTIVE, v)
        return v

    def delete_vip(self, context, id):
        v = self.get_vip(context, id)
        self._resource_set_status(
            context, loadbalancer_db.Vip,
            id, service_constants.PENDING_DELETE)
        try:
            self.vcns_driver.delete_vip(context, id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete vip with id: %s!"), id)
                self._resource_set_status(context, loadbalancer_db.Vip,
                                          id, service_constants.ERROR)
        edge_id = self._get_edge_id_by_vip_id(context, id)
        #Check associated HealthMonitors and then delete them
        pool = self.get_pool(context, v['pool_id'])
        self.vcns_driver.delete_pool(context, v['pool_id'], edge_id)
        for monitor_id in pool.get('health_monitors'):
            #TODO(linb): do exception handle if error
            self.vcns_driver.delete_health_monitor(
                context, monitor_id, edge_id)

        router_binding = self._get_resource_router_id_binding(
            context, loadbalancer_db.Vip, resource_id=id)
        router = self._get_router(context, router_binding.router_id)
        self._delete_resource_router_id_binding(
            context, id, loadbalancer_db.Vip)
        super(NsxAdvancedPlugin, self).delete_vip(context, id)
        self._update_interface(context, router, sync=True)

    def get_vip(self, context, id, fields=None):
        vip = super(NsxAdvancedPlugin, self).get_vip(context, id, fields)
        if fields and rsi.ROUTER_ID not in fields:
            return vip

        service_router_binding = self._get_resource_router_id_binding(
            context, loadbalancer_db.Vip, resource_id=vip['id'])
        vip[rsi.ROUTER_ID] = service_router_binding['router_id']
        return vip

    def get_vips(self, context, filters=None, fields=None):
        vips = super(NsxAdvancedPlugin, self).get_vips(
            context, filters, fields)
        if fields and rsi.ROUTER_ID not in fields:
            return vips
        service_router_bindings = self._get_resource_router_id_bindings(
            context, loadbalancer_db.Vip,
            resource_ids=[vip['id'] for vip in vips])
        mapping = dict([(binding['resource_id'], binding['router_id'])
                        for binding in service_router_bindings])
        for vip in vips:
            vip[rsi.ROUTER_ID] = mapping[vip['id']]
        return vips

    def update_pool(self, context, id, pool):
        pool['pool']['status'] = service_constants.PENDING_UPDATE
        p = super(NsxAdvancedPlugin, self).update_pool(context, id, pool)
        #Check whether the pool is already associated with the vip
        if not p.get('vip_id'):
            self._resource_set_status(context, loadbalancer_db.Pool,
                                      p['id'], service_constants.ACTIVE, p)
            return p
        try:
            self._vcns_update_pool(context, p)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update pool with id: %s!"), id)
                self._resource_set_status(context, loadbalancer_db.Pool,
                                          p['id'], service_constants.ERROR, p)
        self._resource_set_status(context, loadbalancer_db.Pool,
                                  p['id'], service_constants.ACTIVE, p)
        return p

    def create_member(self, context, member):
        m = super(NsxAdvancedPlugin, self).create_member(context, member)
        pool_id = m.get('pool_id')
        pool = self.get_pool(context, pool_id)
        if not pool.get('vip_id'):
            self._resource_set_status(context, loadbalancer_db.Member,
                                      m['id'], service_constants.ACTIVE, m)
            return m
        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id,
                                  service_constants.PENDING_UPDATE)
        try:
            self._vcns_update_pool(context, pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update pool with the member"))
                super(NsxAdvancedPlugin, self).delete_member(context, m['id'])

        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id, service_constants.ACTIVE)
        self._resource_set_status(context, loadbalancer_db.Member,
                                  m['id'], service_constants.ACTIVE, m)
        return m

    def update_member(self, context, id, member):
        member['member']['status'] = service_constants.PENDING_UPDATE
        old_member = self.get_member(context, id)
        m = super(NsxAdvancedPlugin, self).update_member(
            context, id, member)

        if m['pool_id'] != old_member['pool_id']:
            old_pool_id = old_member['pool_id']
            old_pool = self.get_pool(context, old_pool_id)
            if old_pool.get('vip_id'):
                self._resource_set_status(
                    context, loadbalancer_db.Pool,
                    old_pool_id, service_constants.PENDING_UPDATE)
                try:
                    self._vcns_update_pool(context, old_pool)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Failed to update old pool "
                                        "with the member"))
                        super(NsxAdvancedPlugin, self).delete_member(
                            context, m['id'])
                self._resource_set_status(
                    context, loadbalancer_db.Pool,
                    old_pool_id, service_constants.ACTIVE)

        pool_id = m['pool_id']
        pool = self.get_pool(context, pool_id)
        if not pool.get('vip_id'):
            self._resource_set_status(context, loadbalancer_db.Member,
                                      m['id'], service_constants.ACTIVE, m)
            return m
        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id,
                                  service_constants.PENDING_UPDATE)
        try:
            self._vcns_update_pool(context, pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update pool with the member"))
                super(NsxAdvancedPlugin, self).delete_member(
                    context, m['id'])

        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id, service_constants.ACTIVE)
        self._resource_set_status(context, loadbalancer_db.Member,
                                  m['id'], service_constants.ACTIVE, m)
        return m

    def delete_member(self, context, id):
        m = self.get_member(context, id)
        super(NsxAdvancedPlugin, self).delete_member(context, id)
        pool_id = m['pool_id']
        pool = self.get_pool(context, pool_id)
        if not pool.get('vip_id'):
            return
        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id, service_constants.PENDING_UPDATE)
        try:
            self._vcns_update_pool(context, pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update pool with the member"))
        self._resource_set_status(context, loadbalancer_db.Pool,
                                  pool_id, service_constants.ACTIVE)

    def update_health_monitor(self, context, id, health_monitor):
        old_hm = super(NsxAdvancedPlugin, self).get_health_monitor(
            context, id)
        hm = super(NsxAdvancedPlugin, self).update_health_monitor(
            context, id, health_monitor)
        for hm_pool in hm.get('pools'):
            pool_id = hm_pool['pool_id']
            pool = self.get_pool(context, pool_id)
            if pool.get('vip_id'):
                edge_id = self._get_edge_id_by_vip_id(
                    context, pool['vip_id'])
                try:
                    self.vcns_driver.update_health_monitor(
                        context, edge_id, old_hm, hm)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Failed to update monitor "
                                        "with id: %s!"), id)
        return hm

    def create_pool_health_monitor(self, context,
                                   health_monitor, pool_id):
        monitor_id = health_monitor['health_monitor']['id']
        pool = self.get_pool(context, pool_id)
        monitors = pool.get('health_monitors')
        if len(monitors) > 0:
            msg = _("Vcns right now can only support "
                    "one monitor per pool")
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        #Check whether the pool is already associated with the vip
        if not pool.get('vip_id'):
            res = super(NsxAdvancedPlugin,
                        self).create_pool_health_monitor(context,
                                                         health_monitor,
                                                         pool_id)
            return res
        #Get the edge_id
        edge_id = self._get_edge_id_by_vip_id(context, pool['vip_id'])
        res = super(NsxAdvancedPlugin,
                    self).create_pool_health_monitor(context,
                                                     health_monitor,
                                                     pool_id)
        monitor = self.get_health_monitor(context, monitor_id)
        #TODO(linb)Add Exception handle if error
        self.vcns_driver.create_health_monitor(context, edge_id, monitor)
        #Get updated pool
        pool['health_monitors'].append(monitor['id'])
        self._resource_set_status(
            context, loadbalancer_db.Pool,
            pool_id, service_constants.PENDING_UPDATE)
        try:
            self._vcns_update_pool(context, pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to associate monitor with pool!"))
                self._resource_set_status(
                    context, loadbalancer_db.Pool,
                    pool_id, service_constants.ERROR)
                super(NsxAdvancedPlugin, self).delete_pool_health_monitor(
                    context, monitor_id, pool_id)
        self._resource_set_status(
            context, loadbalancer_db.Pool,
            pool_id, service_constants.ACTIVE)
        self._resource_set_status(
            context, loadbalancer_db.PoolMonitorAssociation,
            monitor_id, service_constants.ACTIVE, res,
            pool_id=pool_id)
        return res

    def delete_pool_health_monitor(self, context, id, pool_id):
        super(NsxAdvancedPlugin, self).delete_pool_health_monitor(
            context, id, pool_id)
        pool = self.get_pool(context, pool_id)
        #Check whether the pool is already associated with the vip
        if pool.get('vip_id'):
            #Delete the monitor on vshield edge
            edge_id = self._get_edge_id_by_vip_id(context, pool['vip_id'])
            self._resource_set_status(
                context, loadbalancer_db.Pool,
                pool_id, service_constants.PENDING_UPDATE)
            try:
                self._vcns_update_pool(context, pool)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Failed to update pool with pool_monitor!"))
                    self._resource_set_status(
                        context, loadbalancer_db.Pool,
                        pool_id, service_constants.ERROR)
            #TODO(linb): Add exception handle if error
            self.vcns_driver.delete_health_monitor(context, id, edge_id)
            self._resource_set_status(
                context, loadbalancer_db.Pool,
                pool_id, service_constants.ACTIVE)

    def _vcns_update_ipsec_config(
        self, context, vpnservice_id, removed_ipsec_conn_id=None):
        sites = []
        vpn_service = self._get_vpnservice(context, vpnservice_id)
        edge_id = self._get_edge_id_by_vcns_edge_binding(
            context, vpn_service.router_id)
        if not vpn_service.router.gw_port:
            msg = _("Failed to update ipsec vpn configuration on edge, since "
                    "the router: %s does not have a gateway yet!"
                    ) % vpn_service.router_id
            LOG.error(msg)
            raise exceptions.VcnsBadRequest(resource='router', msg=msg)

        external_ip = vpn_service.router.gw_port['fixed_ips'][0]['ip_address']
        subnet = self._make_subnet_dict(vpn_service.subnet)
        for ipsec_site_conn in vpn_service.ipsec_site_connections:
            if ipsec_site_conn.id != removed_ipsec_conn_id:
                site = self._make_ipsec_site_connection_dict(ipsec_site_conn)
                ikepolicy = self._make_ikepolicy_dict(
                    ipsec_site_conn.ikepolicy)
                ipsecpolicy = self._make_ipsecpolicy_dict(
                    ipsec_site_conn.ipsecpolicy)
                sites.append({'site': site,
                              'ikepolicy': ikepolicy,
                              'ipsecpolicy': ipsecpolicy,
                              'subnet': subnet,
                              'external_ip': external_ip})
        try:
            self.vcns_driver.update_ipsec_config(
                edge_id, sites, enabled=vpn_service.admin_state_up)
        except exceptions.VcnsBadRequest:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Bad or unsupported Input request!"))
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                msg = (_("Failed to update ipsec VPN configuration "
                         "with vpnservice: %(vpnservice_id)s on vShield Edge: "
                         "%(edge_id)s") % {'vpnservice_id': vpnservice_id,
                                           'edge_id': edge_id})
                LOG.exception(msg)

    def create_vpnservice(self, context, vpnservice):
        LOG.debug("create_vpnservice() called")
        router_id = vpnservice['vpnservice'].get('router_id')
        if not self._is_advanced_service_router(context, router_id):
            msg = _("router_id:%s is not an advanced router!") % router_id
            LOG.warning(msg)
            raise exceptions.VcnsBadRequest(resource='router', msg=msg)

        if self.get_vpnservices(context, filters={'router_id': [router_id]}):
            msg = _("a vpnservice is already associated with the router: %s"
                    ) % router_id
            LOG.warning(msg)
            raise nsx_exc.ServiceOverQuota(
                overs='vpnservice', err_msg=msg)

        service = super(NsxAdvancedPlugin, self).create_vpnservice(
            context, vpnservice)
        self._resource_set_status(
            context, vpn_db.VPNService,
            service['id'], service_constants.ACTIVE, service)
        return service

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        vpnservice['vpnservice']['status'] = service_constants.PENDING_UPDATE
        service = super(NsxAdvancedPlugin, self).update_vpnservice(
            context, vpnservice_id, vpnservice)
        # Only admin_state_up attribute is configurable on Edge.
        if vpnservice['vpnservice'].get('admin_state_up') is None:
            self._resource_set_status(
                context, vpn_db.VPNService,
                service['id'], service_constants.ACTIVE, service)
            return service
        # Test whether there is one ipsec site connection attached to
        # the vpnservice. If not, just return without updating ipsec
        # config on edge side.
        vpn_service_db = self._get_vpnservice(context, vpnservice_id)
        if not vpn_service_db.ipsec_site_connections:
            self._resource_set_status(
                context, vpn_db.VPNService,
                service['id'], service_constants.ACTIVE, service)
            return service
        try:
            self._vcns_update_ipsec_config(context, service['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self._resource_set_status(
                    context, vpn_db.VPNService,
                    service['id'], service_constants.ERROR, service)
        self._resource_set_status(
            context, vpn_db.VPNService,
            service['id'], service_constants.ACTIVE, service)
        return service

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_site_conn = super(
            NsxAdvancedPlugin, self).create_ipsec_site_connection(
                context, ipsec_site_connection)
        try:
            self._vcns_update_ipsec_config(
                context, ipsec_site_conn['vpnservice_id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NsxAdvancedPlugin, self).delete_ipsec_site_connection(
                    context, ipsec_site_conn['id'])
        self._resource_set_status(
            context, vpn_db.IPsecSiteConnection,
            ipsec_site_conn['id'], service_constants.ACTIVE, ipsec_site_conn)
        return ipsec_site_conn

    def update_ipsec_site_connection(self, context, ipsec_site_connection_id,
                                     ipsec_site_connection):
        ipsec_site_connection['ipsec_site_connection']['status'] = (
            service_constants.PENDING_UPDATE)
        ipsec_site_conn = super(
            NsxAdvancedPlugin, self).update_ipsec_site_connection(
                context, ipsec_site_connection_id, ipsec_site_connection)
        try:
            self._vcns_update_ipsec_config(
                context, ipsec_site_conn['vpnservice_id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self._resource_set_status(
                    context, vpn_db.IPsecSiteConnection, ipsec_site_conn['id'],
                    service_constants.ERROR, ipsec_site_conn)
        self._resource_set_status(
            context, vpn_db.IPsecSiteConnection,
            ipsec_site_conn['id'], service_constants.ACTIVE, ipsec_site_conn)
        return ipsec_site_conn

    def delete_ipsec_site_connection(self, context, ipsec_site_conn_id):
        self._resource_set_status(
            context, vpn_db.IPsecSiteConnection,
            ipsec_site_conn_id, service_constants.PENDING_DELETE)
        vpnservice_id = self.get_ipsec_site_connection(
            context, ipsec_site_conn_id)['vpnservice_id']
        try:
            self._vcns_update_ipsec_config(
                context, vpnservice_id, ipsec_site_conn_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._resource_set_status(
                    context, vpn_db.IPsecSiteConnection, ipsec_site_conn_id,
                    service_constants.ERROR)
        super(NsxAdvancedPlugin, self).delete_ipsec_site_connection(
            context, ipsec_site_conn_id)


class VcnsCallbacks(object):
    """Edge callback implementation Callback functions for
    asynchronous tasks.
    """
    def __init__(self, plugin):
        self.plugin = plugin

    def edge_deploy_started(self, task):
        """callback when deployment task started."""
        jobdata = task.userdata['jobdata']
        context = jobdata['context']
        edge_id = task.userdata.get('edge_id')
        neutron_router_id = jobdata['neutron_router_id']
        name = task.userdata['router_name']
        if edge_id:
            LOG.debug("Start deploying %(edge_id)s for router %(name)s", {
                'edge_id': edge_id,
                'name': name})
            vcns_db.update_vcns_router_binding(
                context.session, neutron_router_id, edge_id=edge_id)
        else:
            LOG.debug("Failed to deploy Edge for router %s", name)
            vcns_db.update_vcns_router_binding(
                context.session, neutron_router_id,
                status=service_constants.ERROR)

    def edge_deploy_result(self, task):
        """callback when deployment task finished."""
        jobdata = task.userdata['jobdata']
        lrouter = jobdata['lrouter']
        context = jobdata['context']
        name = task.userdata['router_name']
        neutron_router_id = jobdata['neutron_router_id']
        router_db = None
        try:
            router_db = self.plugin._get_router(
                context, neutron_router_id)
        except l3.RouterNotFound:
            # Router might have been deleted before deploy finished
            LOG.exception(_("Router %s not found"), lrouter['uuid'])

        if task.status == tasks_const.TaskStatus.COMPLETED:
            LOG.debug("Successfully deployed %(edge_id)s for "
                      "router %(name)s", {
                          'edge_id': task.userdata['edge_id'],
                          'name': name})
            if (router_db and
                    router_db['status'] == service_constants.PENDING_CREATE):
                router_db['status'] = service_constants.ACTIVE

            binding = vcns_db.get_vcns_router_binding(
                context.session, neutron_router_id)
            # only update status to active if its status is pending create
            if binding['status'] == service_constants.PENDING_CREATE:
                vcns_db.update_vcns_router_binding(
                    context.session, neutron_router_id,
                    status=service_constants.ACTIVE)
        else:
            LOG.debug("Failed to deploy Edge for router %s", name)
            if router_db:
                router_db['status'] = service_constants.ERROR
            vcns_db.update_vcns_router_binding(
                context.session, neutron_router_id,
                status=service_constants.ERROR)

    def edge_delete_result(self, task):
        jobdata = task.userdata['jobdata']
        router_id = task.userdata['router_id']
        context = jobdata['context']
        if task.status == tasks_const.TaskStatus.COMPLETED:
            vcns_db.delete_vcns_router_binding(context.session,
                                               router_id)

    def interface_update_result(self, task):
        LOG.debug("interface_update_result %d", task.status)

    def snat_create_result(self, task):
        LOG.debug("snat_create_result %d", task.status)

    def snat_delete_result(self, task):
        LOG.debug("snat_delete_result %d", task.status)

    def dnat_create_result(self, task):
        LOG.debug("dnat_create_result %d", task.status)

    def dnat_delete_result(self, task):
        LOG.debug("dnat_delete_result %d", task.status)

    def routes_update_result(self, task):
        LOG.debug("routes_update_result %d", task.status)

    def nat_update_result(self, task):
        LOG.debug("nat_update_result %d", task.status)


def _process_base_create_lswitch_args(*args, **kwargs):
    tags = utils.get_tags()
    tags.append({"tag": args[1],
                 "scope": "quantum_net_id"})
    if args[2]:
        tags.append({"tag": args[2], "scope": "os_tid"})
    switch_name = args[3]
    tz_config = args[4]
    if kwargs.get("shared", False) or len(args) >= 6:
        tags.append({"tag": "true", "scope": "shared"})
    if kwargs.get("tags"):
        tags.extend(kwargs["tags"])
    return switch_name, tz_config, tags
