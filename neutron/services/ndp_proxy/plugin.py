# Copyright 2022 Troila
# All rights reserved.
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

import netaddr
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_ndp_proxy
from neutron_lib.api.definitions import l3_ndp_proxy as np_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_consts
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as lib_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.conf.db import l3_ndpproxy_db
from neutron.db import db_base_plugin_common
from neutron.db.models import ndp_proxy as ndp_proxy_models
from neutron.extensions import l3_ndp_proxy
from neutron.objects import base as base_obj
from neutron.objects import ndp_proxy as np
from neutron.services.ndp_proxy import exceptions as exc

l3_ndpproxy_db.register_db_l3_ndpproxy_opts()
LOG = logging.getLogger(__name__)
V6 = lib_consts.IP_VERSION_6


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class NDPProxyPlugin(l3_ndp_proxy.NDPProxyBase):
    """Implementation of the NDP proxy for ipv6

    The class implements a NDP proxy plugin.
    """

    supported_extension_aliases = [np_apidef.ALIAS,
                                   l3_ext_ndp_proxy.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(NDPProxyPlugin, self).__init__()
        self.push_api = resources_rpc.ResourcesPushRpcApi()
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.core_plugin = directory.get_plugin()
        LOG.info("The router's 'enable_ndp_proxy' parameter's default value "
                 "is %s", cfg.CONF.enable_ndp_proxy_by_default)

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict(result_dict, router_db):
        # If the router has no external gateway, the enable_ndp_proxy
        # parameter is always False.
        enable_ndp_proxy = False
        if result_dict.get(l3_apidef.EXTERNAL_GW_INFO, None):
            if router_db.ndp_proxy_state:
                enable_ndp_proxy = router_db.ndp_proxy_state.enable_ndp_proxy
        result_dict[l3_ext_ndp_proxy.ENABLE_NDP_PROXY] = enable_ndp_proxy

    @registry.receives(resources.ROUTER_GATEWAY, [events.BEFORE_DELETE])
    def _check_delete_router_gw(self, resource, event, trigger, payload):
        router_db = payload.states[0]
        request_body = payload.request_body if payload.request_body else {}
        context = payload.context
        if np.NDPProxy.get_objects(context, **{'router_id': router_db.id}):
            raise exc.RouterGatewayInUseByNDPProxy(router_id=router_db.id)

        # When user unset gateway and enable ndp proxy in same time we shoule
        # raise exception.
        ndp_proxy_state = request_body.get(
            l3_ext_ndp_proxy.ENABLE_NDP_PROXY, None)
        if ndp_proxy_state:
            reason = _("The router's external gateway will be unset")
            raise exc.RouterGatewayNotValid(
                router_id=router_db.id, reason=reason)

        if router_db.ndp_proxy_state:
            context.session.delete(router_db.ndp_proxy_state)

    @registry.receives(resources.ROUTER_GATEWAY, [events.BEFORE_UPDATE])
    def _check_update_router_gw(self, resource, event, trigger, payload):
        # If the router's enable_ndp_proxy is true, we need ensure the external
        # gateway has IPv6 address.
        router_db = payload.states[0]
        if not (router_db.ndp_proxy_state and
                router_db.ndp_proxy_state.enable_ndp_proxy):
            return
        context = payload.context
        request_body = payload.request_body
        ext_gw = request_body[l3_apidef.EXTERNAL_GW_INFO]
        ext_ips = ext_gw.get('external_fixed_ips', None)
        if not ext_ips:
            return
        if [f['ip_address'] for f in ext_ips if
                (f.get('ip_address') and
                 netaddr.IPNetwork(f['ip_address']).version == V6)]:
            return
        subnet_ids = set(f['subnet_id'] for f in ext_ips
                         if f.get('subnet_id'))
        for subnet_id in subnet_ids:
            if self.core_plugin.get_subnet(
                    context, subnet_id)['ip_version'] == V6:
                return
        raise exc.RouterIPv6GatewayInUse(
            router_id=router_db.id)

    def _ensure_router_ndp_proxy_state_model(self, context, router_db, state):
        if not router_db['ndp_proxy_state']:
            if state is lib_consts.ATTR_NOT_SPECIFIED:
                state = cfg.CONF.enable_ndp_proxy_by_default
            kwargs = {'router_id': router_db.id,
                      'enable_ndp_proxy': state}
            new = ndp_proxy_models.RouterNDPProxyState(**kwargs)
            context.session.add(new)
            router_db['ndp_proxy_state'] = new
            self.l3_plugin._get_router(context, router_db['id'])
        else:
            router_db['ndp_proxy_state'].update(
                {'enable_ndp_proxy': state})

    def _gateway_is_valid(self, context, gw_port_id):
        if not gw_port_id:
            return False
        port_dict = self.core_plugin.get_port(context.elevated(), gw_port_id)
        if not self._check_ext_gw_network(context, port_dict['network_id']):
            return False
        v6_fixed_ips = [
            fixed_ip for fixed_ip in port_dict['fixed_ips']
            if (netaddr.IPNetwork(fixed_ip['ip_address']).version == V6)]
        # If the router's external gateway port user LLA address, The
        # external network needn't IPv6 subnet.
        if v6_fixed_ips:
            return True
        return False

    def _check_ext_gw_network(self, context, network_id):
        network = self.core_plugin.get_network(context, network_id)
        if not network.get('ipv6_address_scope'):
            return False
        ext_subnets = self.core_plugin.get_subnets(
            context.elevated(), filters={'network_id': network_id})
        has_ipv6_subnet = False
        for subnet in ext_subnets:
            if subnet['ip_version'] == V6:
                has_ipv6_subnet = True
        if has_ipv6_subnet:
            return True
        return False

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_ndp_proxy_state_for_create_router(
            self, resource, event, trigger, payload):
        context = payload.context
        router_db = payload.metadata['router_db']
        request_body = payload.states[0]
        ndp_proxy_state = request_body.get(
            l3_ext_ndp_proxy.ENABLE_NDP_PROXY, lib_consts.ATTR_NOT_SPECIFIED)
        ext_gw_info = request_body.get('external_gateway_info')

        if not ext_gw_info and ndp_proxy_state is True:
            reason = _("The request body not contain external "
                       "gateway information")
            raise exc.RouterGatewayNotValid(
                router_id=router_db.id, reason=reason)
        if (ndp_proxy_state == lib_consts.ATTR_NOT_SPECIFIED and not
                ext_gw_info) or (ext_gw_info and ndp_proxy_state is False):
            return

        if ndp_proxy_state in (True, lib_consts.ATTR_NOT_SPECIFIED):
            ext_ips = ext_gw_info.get(
                'external_fixed_ips', []) if ext_gw_info else []
            network_id = self.l3_plugin._validate_gw_info(
                context, ext_gw_info, ext_ips, router_db)
            ext_gw_support_ndp = self._check_ext_gw_network(
                context, network_id)
            if not ext_gw_support_ndp and ndp_proxy_state is True:
                reason = _("The external network %s don't support "
                           "IPv6 ndp proxy, the network has no IPv6 "
                           "subnets or has no IPv6 address scope") % network_id
                raise exc.RouterGatewayNotValid(
                    router_id=router_db.id, reason=reason)
            if ndp_proxy_state == lib_consts.ATTR_NOT_SPECIFIED:
                ndp_proxy_state = (
                    ext_gw_support_ndp and
                    cfg.CONF.enable_ndp_proxy_by_default)

        self._ensure_router_ndp_proxy_state_model(
            context, router_db, ndp_proxy_state)

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_UPDATE])
    def _process_ndp_proxy_state_for_update_router(self, resource, event,
                                                   trigger, payload=None):
        request_body = payload.request_body
        context = payload.context
        router_db = payload.desired_state
        ndp_proxy_state = request_body.get(
            l3_ext_ndp_proxy.ENABLE_NDP_PROXY,
            lib_consts.ATTR_NOT_SPECIFIED)
        gw_support_ndp = self._gateway_is_valid(
            context, router_db['gw_port_id'])
        if ndp_proxy_state is True and not gw_support_ndp:
            reason = _("The router has no external gateway or the external "
                       "gateway port has no IPv6 address or IPv6 address "
                       "scope")
            raise exc.RouterGatewayNotValid(
                router_id=router_db.id, reason=reason)
        if ndp_proxy_state == lib_consts.ATTR_NOT_SPECIFIED:
            self._ensure_router_ndp_proxy_state_model(
                context, router_db, gw_support_ndp)
        else:
            self._ensure_router_ndp_proxy_state_model(
                context, router_db, ndp_proxy_state)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _check_router_remove_subnet_request(self, resource, event,
                                            trigger, payload):
        context = payload.context
        np_objs = np.NDPProxy.get_objects(
            context, **{'router_id': payload.resource_id})
        if not np_objs:
            return
        for proxy in np_objs:
            port_dict = self.core_plugin.get_port(
                payload.context, proxy['port_id'])
            v6_fixed_ips = [
                fixed_ip for fixed_ip in port_dict['fixed_ips']
                if (netaddr.IPNetwork(fixed_ip['ip_address']
                                      ).version == V6)]
            if not v6_fixed_ips:
                continue
            if self._get_internal_ip_subnet(
                    proxy['ip_address'],
                    v6_fixed_ips) == payload.metadata['subnet_id']:
                raise exc.RouterInterfaceInUseByNDPProxy(
                    router_id=payload.resource_id,
                    subnet_id=payload.metadata['subnet_id'])

    def _get_internal_ip_subnet(self, request_ip, fixed_ips):
        request_ip = netaddr.IPNetwork(request_ip)
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']) == request_ip:
                return fixed_ip['subnet_id']

    def _check_port(self, context, port_dict, ndp_proxy, router_ports):
        ip_address = ndp_proxy.get('ip_address', None)

        def _get_port_v6_fixedips(port_dicts):
            v6_fixed_ips = []
            for port_dict in port_dicts:
                for fixed_ip in port_dict['fixed_ips']:
                    if netaddr.IPNetwork(
                            fixed_ip['ip_address']).version == V6:
                        v6_fixed_ips.append(fixed_ip)
            return v6_fixed_ips

        port_fixedips = _get_port_v6_fixedips([port_dict])
        if not port_fixedips:
            # The ndp proxy works with ipv6 addresses, if there is no ipv6
            # address, we need to raise exception.
            message = _("Requested port %s must allocate one IPv6 address at "
                        "least") % port_dict['id']
            raise lib_exc.BadRequest(resource=np_apidef.RESOURCE_NAME,
                                     msg=message)

        router_fixedips = _get_port_v6_fixedips(router_ports)
        router_subnets = [fixedip['subnet_id'] for fixedip in router_fixedips]
        # If user not specify IPv6 address, we will auto select a valid address
        if not ip_address:
            for fixedip in port_fixedips:
                if fixedip['subnet_id'] in router_subnets:
                    ndp_proxy['ip_address'] = fixedip['ip_address']
                    break
            else:
                raise exc.PortUnreachableRouter(
                    port_id=port_dict['id'],
                    router_id=ndp_proxy['router_id'])
        else:
            # Check whether the ip_address is valid if user specified a
            # IPv6 address
            subnet_id = self._get_internal_ip_subnet(ip_address, port_fixedips)
            if not subnet_id:
                msg = _("This address not belong to the "
                        "port %s") % port_dict['id']
                raise exc.InvalidAddress(address=ip_address, reason=msg)
            if subnet_id not in router_subnets:
                msg = _("This address cannot reach the "
                        "router %s") % ndp_proxy['router_id']
                raise exc.InvalidAddress(address=ip_address, reason=msg)
        network_dict = self.core_plugin.get_network(
                context, port_dict['network_id'])
        return network_dict.get('ipv6_address_scope', None)

    @db_base_plugin_common.convert_result_to_dict
    def create_ndp_proxy(self, context, ndp_proxy):
        ndp_proxy = ndp_proxy.get(np_apidef.RESOURCE_NAME)
        router_id = ndp_proxy['router_id']
        port_id = ndp_proxy['port_id']
        port_dict = self.core_plugin.get_port(context, port_id)
        router_ports = self.core_plugin.get_ports(
            context, filters={'device_id': [router_id],
                              'network_id': [port_dict['network_id']]})
        if not router_ports:
            raise exc.PortUnreachableRouter(
                router_id=router_id, port_id=port_id)
        router_dict = self.l3_plugin.get_router(context, router_id)
        if not router_dict.get('enable_ndp_proxy', None):
            raise exc.RouterNDPProxyNotEnable(router_id=router_dict['id'])
        extrnal_gw_info = router_dict[l3_apidef.EXTERNAL_GW_INFO]
        gw_network_dict = self.core_plugin.get_network(
                context, extrnal_gw_info['network_id'])
        ext_address_scope = gw_network_dict.get('ipv6_address_scope', None)
        internal_address_scope = self._check_port(
            context, port_dict, ndp_proxy, router_ports)
        # If the external network and internal network not belong to same
        # address scope, the packets can't be forwarded by route. So, in
        # this case we should forbid to create ndp proxy entry.
        if ext_address_scope != internal_address_scope:
            raise exc.AddressScopeConflict(
                ext_address_scope=ext_address_scope,
                internal_address_scope=internal_address_scope)

        tenant_id = ndp_proxy.pop('tenant_id', None)
        if not ndp_proxy.get('project_id', None):
            ndp_proxy['project_id'] = tenant_id

        with db_api.CONTEXT_WRITER.using(context):
            np_obj = np.NDPProxy(context, **ndp_proxy)
            np_obj.create()

        LOG.debug("Notify l3-agent to create ndp proxy rules for "
                  "ndp proxy: %s", np_obj.to_dict())
        self.push_api.push(context, [np_obj], rpc_events.CREATED)
        return np_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_ndp_proxy(self, context, id, ndp_proxy):
        ndp_proxy = ndp_proxy.get(np_apidef.RESOURCE_NAME)
        with db_api.CONTEXT_WRITER.using(context):
            obj = np.NDPProxy.get_object(context, id=id)
            if not obj:
                raise exc.NDPProxyNotFound(id=id)
            obj.update_fields(ndp_proxy, reset_changes=True)
            obj.update()
        return obj

    @db_base_plugin_common.convert_result_to_dict
    def get_ndp_proxy(self, context, id, fields=None):
        obj = np.NDPProxy.get_object(context, id=id)
        if not obj:
            raise exc.NDPProxyNotFound(id=id)
        return obj

    @db_base_plugin_common.convert_result_to_dict
    def get_ndp_proxies(self, context, filters=None,
                        fields=None, sorts=None, limit=None, marker=None,
                        page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        return np.NDPProxy.get_objects(
            context, _pager=pager, **filters)

    def delete_ndp_proxy(self, context, id):
        with db_api.CONTEXT_WRITER.using(context):
            np_obj = np.NDPProxy.get_object(context, id=id)
            if not np_obj:
                raise exc.NDPProxyNotFound(id=id)
            np_obj.delete()

        LOG.debug("Notify l3-agent to delete ndp proxy rules for "
                  "ndp proxy: %s", np_obj.to_dict())
        self.push_api.push(context, [np_obj], rpc_events.DELETED)
