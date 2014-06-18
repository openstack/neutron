# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Embrane, Inc.
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
#
# @author: Ivar Lazzaro, Embrane, Inc.

from heleosapi import backend_operations as h_op
from heleosapi import constants as h_con
from heleosapi import exceptions as h_exc
from oslo.config import cfg
from sqlalchemy.orm import exc

from neutron.common import constants as l3_constants
from neutron.common import exceptions as neutron_exc
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.openstack.common import log as logging
from neutron.plugins.embrane.agent import dispatcher
from neutron.plugins.embrane.common import config  # noqa
from neutron.plugins.embrane.common import constants as p_con
from neutron.plugins.embrane.common import contexts as embrane_ctx
from neutron.plugins.embrane.common import operation
from neutron.plugins.embrane.common import utils

LOG = logging.getLogger(__name__)
conf = cfg.CONF.heleos


class EmbranePlugin(object):
    """Embrane Neutron plugin.

    uses the heleos(c) platform and a support L2 plugin to leverage networking
    in cloud environments.

    """
    _l3super = extraroute_db.ExtraRoute_db_mixin

    def __init__(self):
        pass

    def _run_embrane_config(self):
        # read configurations
        config_esm_mgmt = conf.esm_mgmt
        config_admin_username = conf.admin_username
        config_admin_password = conf.admin_password
        config_router_image_id = conf.router_image
        config_security_zones = {h_con.SzType.IB: conf.inband_id,
                                 h_con.SzType.OOB: conf.oob_id,
                                 h_con.SzType.MGMT: conf.mgmt_id,
                                 h_con.SzType.DUMMY: conf.dummy_utif_id}
        config_resource_pool = conf.resource_pool_id
        self._embrane_async = conf.async_requests
        self._esm_api = h_op.BackendOperations(
            esm_mgmt=config_esm_mgmt,
            admin_username=config_admin_username,
            admin_password=config_admin_password,
            router_image_id=config_router_image_id,
            security_zones=config_security_zones,
            resource_pool=config_resource_pool)
        self._dispatcher = dispatcher.Dispatcher(self, self._embrane_async)

    def _make_router_dict(self, *args, **kwargs):
        return self._l3super._make_router_dict(self, *args, **kwargs)

    def _delete_router(self, context, router_id):
        self._l3super.delete_router(self, context, router_id)

    def _update_db_router_state(self, context, neutron_router, dva_state):
        if not dva_state:
            new_state = p_con.Status.ERROR
        elif dva_state == h_con.DvaState.POWER_ON:
            new_state = p_con.Status.ACTIVE
        else:
            new_state = p_con.Status.READY
        self._set_db_router_state(context, neutron_router, new_state)
        return new_state

    def _set_db_router_state(self, context, neutron_router, new_state):
        return utils.set_db_item_state(context, neutron_router, new_state)

    def _update_db_interfaces_state(self, context, neutron_router):
        router_ports = self.get_ports(context,
                                      {"device_id": [neutron_router["id"]]})
        self._esm_api.update_ports_status(neutron_router["id"], router_ports)
        for port in router_ports:
            db_port = self._get_port(context, port["id"])
            db_port["status"] = port["status"]
            context.session.merge(db_port)

    def _update_neutron_state(self, context, neutron_router, state):
        try:
            self._update_db_interfaces_state(context, neutron_router)
        except Exception:
            LOG.exception(_("Unhandled exception occurred"))
        return self._set_db_router_state(context, neutron_router, state)

    def _retrieve_prefix_from_port(self, context, neutron_port):
        subnet_id = neutron_port["fixed_ips"][0]["subnet_id"]
        subnet = utils.retrieve_subnet(context, subnet_id)
        prefix = subnet["cidr"].split("/")[1]
        return prefix

    # L3 extension
    def create_router(self, context, router):
        r = router["router"]
        self._get_tenant_id_for_create(context, r)
        db_router = self._l3super.create_router(self, context, router)
        neutron_router = self._get_router(context, db_router['id'])
        gw_port = neutron_router.gw_port
        # For now, only small flavor is used
        utif_info = (self._plugin_support.retrieve_utif_info(context,
                                                             gw_port)
                     if gw_port else None)
        ip_allocation_info = (utils.retrieve_ip_allocation_info(context,
                                                                gw_port)
                              if gw_port else None)
        neutron_router = self._l3super._get_router(self, context,
                                                   neutron_router["id"])
        neutron_router["status"] = p_con.Status.CREATING
        self._dispatcher.dispatch_l3(
            d_context=embrane_ctx.DispatcherContext(
                p_con.Events.CREATE_ROUTER, neutron_router, context, None),
            args=(h_con.Flavor.SMALL, utif_info, ip_allocation_info))
        return self._make_router_dict(neutron_router)

    def update_router(self, context, id, router):
        db_router = self._l3super.update_router(self, context, id, router)
        neutron_router = self._get_router(context, db_router['id'])
        gw_port = neutron_router.gw_port
        utif_info = (self._plugin_support.retrieve_utif_info(context,
                                                             gw_port)
                     if gw_port else None)
        ip_allocation_info = (utils.retrieve_ip_allocation_info(context,
                                                                gw_port)
                              if gw_port else None)

        routes_info = router["router"].get("routes")

        neutron_router = self._l3super._get_router(self, context, id)
        state_change = operation.Operation(
            self._set_db_router_state,
            args=(context, neutron_router, p_con.Status.UPDATING))
        self._dispatcher.dispatch_l3(
            d_context=embrane_ctx.DispatcherContext(
                p_con.Events.UPDATE_ROUTER, neutron_router, context,
                state_change),
            args=(utif_info, ip_allocation_info, routes_info))
        return self._make_router_dict(neutron_router)

    def get_router(self, context, id, fields=None):
        """Ensures that id does exist in the ESM."""
        neutron_router = self._get_router(context, id)

        try:
            if neutron_router["status"] != p_con.Status.CREATING:
                self._esm_api.get_dva(id)
        except h_exc.DvaNotFound:

            LOG.error(_("The following routers have not physical match: %s"),
                      id)
            self._set_db_router_state(context, neutron_router,
                                      p_con.Status.ERROR)

        LOG.debug(_("Requested router: %s"), neutron_router)
        return self._make_router_dict(neutron_router, fields)

    def get_routers(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        """Retrieves the router list defined by the incoming filters."""
        router_query = self._apply_filters_to_query(
            self._model_query(context, l3_db.Router),
            l3_db.Router, filters)
        id_list = [x["id"] for x in router_query
                   if x["status"] != p_con.Status.CREATING]
        try:
            self._esm_api.get_dvas(id_list)
        except h_exc.DvaNotFound:
            LOG.error(_("The following routers have not physical match: %s"),
                      repr(id_list))
            error_routers = []
            for id in id_list:
                try:
                    error_routers.append(self._get_router(context, id))
                except l3.RouterNotFound:
                    pass
            for error_router in error_routers:
                self._set_db_router_state(context, error_router,
                                          p_con.Status.ERROR)
        return [self._make_router_dict(router, fields)
                for router in router_query]

    def delete_router(self, context, id):
        """Deletes the DVA with the specific router id."""
        # Copy of the parent validation code, shouldn't the base modules
        # provide functions for validating operations?
        device_owner_router_intf = l3_constants.DEVICE_OWNER_ROUTER_INTF
        fips = self.get_floatingips_count(context.elevated(),
                                          filters={"router_id": [id]})
        if fips:
            raise l3.RouterInUse(router_id=id)

        device_filter = {"device_id": [id],
                         "device_owner": [device_owner_router_intf]}
        ports = self.get_ports_count(context.elevated(),
                                     filters=device_filter)
        if ports:
            raise l3.RouterInUse(router_id=id)
        neutron_router = self._get_router(context, id)
        state_change = operation.Operation(self._set_db_router_state,
                                           args=(context, neutron_router,
                                                 p_con.Status.DELETING))
        self._dispatcher.dispatch_l3(
            d_context=embrane_ctx.DispatcherContext(
                p_con.Events.DELETE_ROUTER, neutron_router, context,
                state_change), args=())
        LOG.debug(_("Deleting router=%s"), neutron_router)
        return neutron_router

    def add_router_interface(self, context, router_id, interface_info):
        """Grows DVA interface in the specified subnet."""
        neutron_router = self._get_router(context, router_id)
        rport_qry = context.session.query(models_v2.Port)
        ports = rport_qry.filter_by(
            device_id=router_id).all()
        if len(ports) >= p_con.UTIF_LIMIT:
            raise neutron_exc.BadRequest(
                resource=router_id,
                msg=("this router doesn't support more than "
                     + str(p_con.UTIF_LIMIT) + " interfaces"))
        neutron_router_iface = self._l3super.add_router_interface(
            self, context, router_id, interface_info)
        port = self._get_port(context, neutron_router_iface["port_id"])
        utif_info = self._plugin_support.retrieve_utif_info(context, port)
        ip_allocation_info = utils.retrieve_ip_allocation_info(context,
                                                               port)
        state_change = operation.Operation(self._set_db_router_state,
                                           args=(context, neutron_router,
                                                 p_con.Status.UPDATING))
        self._dispatcher.dispatch_l3(
            d_context=embrane_ctx.DispatcherContext(
                p_con.Events.GROW_ROUTER_IF, neutron_router, context,
                state_change),
            args=(utif_info, ip_allocation_info))
        return neutron_router_iface

    def remove_router_interface(self, context, router_id, interface_info):
        port_id = None
        if "port_id" in interface_info:
            port_id = interface_info["port_id"]
        elif "subnet_id" in interface_info:
            subnet_id = interface_info["subnet_id"]
            subnet = utils.retrieve_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_constants.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet["network_id"])
            for p in ports:
                if p["fixed_ips"][0]["subnet_id"] == subnet_id:
                    port_id = p["id"]
                    break
        neutron_router = self._get_router(context, router_id)
        self._l3super.remove_router_interface(self, context, router_id,
                                              interface_info)
        state_change = operation.Operation(self._set_db_router_state,
                                           args=(context, neutron_router,
                                                 p_con.Status.UPDATING))
        self._dispatcher.dispatch_l3(
            d_context=embrane_ctx.DispatcherContext(
                p_con.Events.SHRINK_ROUTER_IF, neutron_router, context,
                state_change),
            args=(port_id,))

    def create_floatingip(self, context, floatingip):
        result = self._l3super.create_floatingip(
            self, context, floatingip)

        if result["port_id"]:
            neutron_router = self._get_router(context, result["router_id"])
            db_fixed_port = self._get_port(context, result["port_id"])
            fixed_prefix = self._retrieve_prefix_from_port(context,
                                                           db_fixed_port)
            db_floating_port = neutron_router["gw_port"]
            floating_prefix = self._retrieve_prefix_from_port(
                context, db_floating_port)
            nat_info = utils.retrieve_nat_info(context, result,
                                               fixed_prefix,
                                               floating_prefix,
                                               neutron_router)
            state_change = operation.Operation(
                self._set_db_router_state,
                args=(context, neutron_router, p_con.Status.UPDATING))

            self._dispatcher.dispatch_l3(
                d_context=embrane_ctx.DispatcherContext(
                    p_con.Events.SET_NAT_RULE, neutron_router, context,
                    state_change),
                args=(nat_info,))
        return result

    def update_floatingip(self, context, id, floatingip):
        db_fip = self._l3super.get_floatingip(self, context, id)
        result = self._l3super.update_floatingip(self, context, id,
                                                 floatingip)

        if db_fip["port_id"] and db_fip["port_id"] != result["port_id"]:
            neutron_router = self._get_router(context, db_fip["router_id"])
            fip_id = db_fip["id"]
            state_change = operation.Operation(
                self._set_db_router_state,
                args=(context, neutron_router, p_con.Status.UPDATING))

            self._dispatcher.dispatch_l3(
                d_context=embrane_ctx.DispatcherContext(
                    p_con.Events.RESET_NAT_RULE, neutron_router, context,
                    state_change),
                args=(fip_id,))
        if result["port_id"]:
            neutron_router = self._get_router(context, result["router_id"])
            db_fixed_port = self._get_port(context, result["port_id"])
            fixed_prefix = self._retrieve_prefix_from_port(context,
                                                           db_fixed_port)
            db_floating_port = neutron_router["gw_port"]
            floating_prefix = self._retrieve_prefix_from_port(
                context, db_floating_port)
            nat_info = utils.retrieve_nat_info(context, result,
                                               fixed_prefix,
                                               floating_prefix,
                                               neutron_router)
            state_change = operation.Operation(
                self._set_db_router_state,
                args=(context, neutron_router, p_con.Status.UPDATING))

            self._dispatcher.dispatch_l3(
                d_context=embrane_ctx.DispatcherContext(
                    p_con.Events.SET_NAT_RULE, neutron_router, context,
                    state_change),
                args=(nat_info,))
        return result

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            floating_ip = fip_qry.filter_by(fixed_port_id=port_id).one()
            router_id = floating_ip["router_id"]
        except exc.NoResultFound:
            return
        router_ids = self._l3super.disassociate_floatingips(
            self, context, port_id, do_notify=do_notify)
        if router_id:
            neutron_router = self._get_router(context, router_id)
            fip_id = floating_ip["id"]
            state_change = operation.Operation(
                self._set_db_router_state,
                args=(context, neutron_router, p_con.Status.UPDATING))

            self._dispatcher.dispatch_l3(
                d_context=embrane_ctx.DispatcherContext(
                    p_con.Events.RESET_NAT_RULE, neutron_router, context,
                    state_change),
                args=(fip_id,))
        return router_ids
