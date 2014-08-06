# Copyright 2014 Embrane, Inc.
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

from neutron.openstack.common import log as logging
from neutron.services.loadbalancer import constants as lcon
from neutron.services.loadbalancer.drivers.embrane import constants as econ

LOG = logging.getLogger(__name__)
handlers = {}


def handler(event, handler):
    def wrap(f):
        if event not in handler.keys():
            handler[event] = [f]
        else:
            handler[event].append(f)

        @functools.wraps(f)
        def wrapped_f(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapped_f

    return wrap


@handler(econ.Events.CREATE_VIP, handlers)
def _provision_load_balancer(driver, context, vip, flavor,
                             vip_utif_info, vip_ip_allocation_info,
                             pool_utif_info=None,
                             pool_ip_allocation_info=None,
                             pool=None, members=None,
                             monitors=None):
    api = driver._heleos_api
    tenant_id = context.tenant_id
    admin_state = vip["admin_state_up"]
    # Architectural configuration
    api.create_load_balancer(tenant_id=tenant_id,
                             router_id=vip["id"],
                             name=vip["name"],
                             flavor=flavor,
                             up=False)
    api.grow_interface(vip_utif_info, False, tenant_id, vip["id"])
    if pool:
        api.grow_interface(pool_utif_info, False, tenant_id,
                           vip["id"])

    # Logical configuration
    api.allocate_address(vip["id"], True, vip_ip_allocation_info)
    if pool:
        api.allocate_address(vip["id"], True, pool_ip_allocation_info)
    dva = api.configure_load_balancer(vip["id"], admin_state,
                                      vip, pool,
                                      monitors, members)
    return api.extract_dva_state(dva)


@handler(econ.Events.UPDATE_VIP, handlers)
def _update_load_balancer(driver, context, vip,
                          old_pool_id=None, old_port_id=None,
                          removed_ip=None, pool_utif_info=None,
                          pool_ip_allocation_info=None,
                          new_pool=None, members=None,
                          monitors=None):
    api = driver._heleos_api
    tenant_id = context.tenant_id
    admin_state = vip["admin_state_up"]

    if old_pool_id:
        # Architectural Changes
        api.de_allocate_address(vip['id'], False, old_port_id, removed_ip)
        api.shrink_interface(tenant_id, vip["id"], False, old_port_id)
        api.grow_interface(pool_utif_info, False, tenant_id, vip["id"])
        # Configuration Changes
        api.allocate_address(vip["id"], True, pool_ip_allocation_info)
        api.replace_pool(vip["id"], True, vip, old_pool_id,
                         new_pool, monitors, members)

    api.update_vservice(vip["id"], True, vip)
    # Dva update
    dva = api.update_dva(tenant_id, vip["id"], vip["name"],
                         admin_state, description=vip["description"])

    return api.extract_dva_state(dva)


@handler(econ.Events.DELETE_VIP, handlers)
def _delete_load_balancer(driver, context, vip):
    try:
        driver._heleos_api.delete_dva(context.tenant_id, vip['id'])
    except h_exc.DvaNotFound:
        LOG.warning(_('The load balancer %s had no physical representation, '
                      'likely already deleted'), vip['id'])
    return econ.DELETED


@handler(econ.Events.UPDATE_POOL, handlers)
def _update_server_pool(driver, context, vip, pool,
                        monitors=None):
    api = driver._heleos_api
    cookie = ((vip.get('session_persistence') or {}).get('type') ==
              lcon.SESSION_PERSISTENCE_HTTP_COOKIE)
    return api.extract_dva_state(api.update_pool(vip['id'],
                                                 vip['admin_state_up'],
                                                 pool, cookie, monitors))


@handler(econ.Events.ADD_OR_UPDATE_MEMBER, handlers)
def _add_or_update_pool_member(driver, context, vip, member, protocol):
    api = driver._heleos_api
    return api.extract_dva_state(api.update_backend_server(
        vip['id'], vip['admin_state_up'], member, protocol))


@handler(econ.Events.REMOVE_MEMBER, handlers)
def _remove_member_from_pool(driver, context, vip, member):
    api = driver._heleos_api
    return api.extract_dva_state(api.remove_pool_member(vip['id'],
                                                        vip['admin_state_up'],
                                                        member))


@handler(econ.Events.DELETE_MEMBER, handlers)
def _delete_member(driver, context, vip, member):
    with context.session.begin(subtransactions=True):
        api = driver._heleos_api
        dva = api.delete_backend_server(vip['id'], vip['admin_state_up'],
                                        member)
        driver._delete_member(context, member)
        return api.extract_dva_state(dva)


@handler(econ.Events.ADD_POOL_HM, handlers)
def _create_pool_hm(driver, context, vip, hm, pool_id):
    api = driver._heleos_api
    return api.extract_dva_state(api.add_pool_monitor(
        vip['id'], vip['admin_state_up'], hm, pool_id))


@handler(econ.Events.UPDATE_POOL_HM, handlers)
def _update_pool_hm(driver, context, vip, hm, pool_id):
    api = driver._heleos_api
    return api.extract_dva_state(api.update_pool_monitor(
        vip['id'], vip['admin_state_up'], hm, pool_id))


@handler(econ.Events.DELETE_POOL_HM, handlers)
def _delete_pool_hm(driver, context, vip, hm, pool_id):
    with context.session.begin(subtransactions=True):
        api = driver._heleos_api
        dva = api.add_pool_monitor(vip['id'], vip['admin_state_up'],
                                   hm, pool_id)
        driver._delete_pool_hm(context, hm, pool_id)
        return api.extract_dva_state(dva)


@handler(econ.Events.POLL_GRAPH, handlers)
def _poll_graph(driver, context, vip):
    api = driver._heleos_api
    return api.extract_dva_state(api.get_dva(vip['id']))
