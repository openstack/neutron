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

import functools

from heleosapi import exceptions as h_exc
from oslo_log import log as logging

from neutron.i18n import _LW
from neutron.plugins.embrane.common import constants as p_con

LOG = logging.getLogger(__name__)
handlers = dict()


def handler(event, handler):
    def wrap(f):
        if event not in handler.keys():
            new_func_list = [f]
            handler[event] = new_func_list
        else:
            handler[event].append(f)

        @functools.wraps(f)
        def wrapped_f(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapped_f
    return wrap


@handler(p_con.Events.CREATE_ROUTER, handlers)
def _create_dva_and_assign_address(api, tenant_id, neutron_router,
                                   flavor, utif_info=None,
                                   ip_allocation_info=None):
    """Creates a new router, and assign the gateway interface if any."""

    dva = api.create_router(tenant_id=tenant_id,
                            router_id=neutron_router["id"],
                            name=neutron_router["name"],
                            flavor=flavor,
                            up=neutron_router["admin_state_up"])
    try:
        if utif_info:
            api.grow_interface(utif_info, neutron_router["admin_state_up"],
                               tenant_id, neutron_router["id"])
        if ip_allocation_info:
            dva = api.allocate_address(neutron_router["id"],
                                       neutron_router["admin_state_up"],
                                       ip_allocation_info)
    except h_exc.PreliminaryOperationsFailed as ex:
        raise h_exc.BrokenInterface(err_msg=str(ex))

    state = api.extract_dva_state(dva)
    return state


@handler(p_con.Events.UPDATE_ROUTER, handlers)
def _update_dva_and_assign_address(api, tenant_id, neutron_router,
                                   utif_info=None, ip_allocation_info=None,
                                   routes_info=[]):
    name = neutron_router["name"]
    up = neutron_router["admin_state_up"]
    r_id = neutron_router["id"]
    if ip_allocation_info or routes_info:
        up = True
    dva = api.update_dva(tenant_id=tenant_id, router_id=r_id, name=name,
                         up=up, utif_info=utif_info)
    if ip_allocation_info:
        api.allocate_address(r_id, up, ip_allocation_info)

    if routes_info:
        api.delete_extra_routes(r_id, up)
        api.set_extra_routes(r_id, neutron_router["admin_state_up"],
                             routes_info)

    return api.extract_dva_state(dva)


@handler(p_con.Events.DELETE_ROUTER, handlers)
def _delete_dva(api, tenant_id, neutron_router):
    try:
        api.delete_dva(tenant_id, neutron_router["id"])
    except h_exc.DvaNotFound:
        LOG.warning(_LW("The router %s had no physical representation, "
                        "likely already deleted"), neutron_router["id"])
    return p_con.Status.DELETED


@handler(p_con.Events.GROW_ROUTER_IF, handlers)
def _grow_dva_iface_and_assign_address(api, tenant_id, neutron_router,
                                       utif_info=None,
                                       ip_allocation_info=None):
    try:
        dva = api.grow_interface(utif_info, neutron_router["admin_state_up"],
                                 tenant_id, neutron_router["id"])
        if ip_allocation_info:
            dva = api.allocate_address(neutron_router["id"],
                                       neutron_router["admin_state_up"],
                                       ip_allocation_info)
    except h_exc.PreliminaryOperationsFailed as ex:
        raise h_exc.BrokenInterface(err_msg=str(ex))

    state = api.extract_dva_state(dva)
    return state


@handler(p_con.Events.SHRINK_ROUTER_IF, handlers)
def _shrink_dva_iface(api, tenant_id, neutron_router, port_id):
    try:
        dva = api.shrink_interface(tenant_id, neutron_router["id"],
                                   neutron_router["admin_state_up"], port_id)
    except h_exc.InterfaceNotFound:
        LOG.warning(_LW("Interface %s not found in the heleos back-end, "
                        "likely already deleted"), port_id)
        return (p_con.Status.ACTIVE if neutron_router["admin_state_up"] else
                p_con.Status.READY)
    except h_exc.PreliminaryOperationsFailed as ex:
        raise h_exc.BrokenInterface(err_msg=str(ex))
    state = api.extract_dva_state(dva)
    return state


@handler(p_con.Events.SET_NAT_RULE, handlers)
def _create_nat_rule(api, tenant_id, neutron_router, nat_info=None):

    dva = api.create_nat_entry(neutron_router["id"],
                               neutron_router["admin_state_up"], nat_info)

    state = api.extract_dva_state(dva)
    return state


@handler(p_con.Events.RESET_NAT_RULE, handlers)
def _delete_nat_rule(api, tenant_id, neutron_router, floating_ip_id):

    dva = api.remove_nat_entry(neutron_router["id"],
                               neutron_router["admin_state_up"],
                               floating_ip_id)

    state = api.extract_dva_state(dva)
    return state
