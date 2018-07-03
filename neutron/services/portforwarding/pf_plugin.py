# Copyright (c) 2018 OpenStack Foundation
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

import collections
import functools

import netaddr
from neutron_lib.api.definitions import floating_ip_port_forwarding as apidef
from neutron_lib.callbacks import registry
from neutron_lib import constants as lib_consts
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import l3 as lib_l3_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db import db_base_plugin_common
from neutron.extensions import floating_ip_port_forwarding as fip_pf
from neutron.objects import base as base_obj
from neutron.objects import port_forwarding as pf
from neutron.objects import router
from neutron.services.portforwarding.common import exceptions as pf_exc


def make_result_with_fields(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        fields = kwargs.get('fields')
        result = f(*args, **kwargs)
        if fields is None:
            return result
        elif isinstance(result, list):
            return [db_utils.resource_fields(r, fields) for r in result]
        else:
            return db_utils.resource_fields(result, fields)

    return inner


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class PortForwardingPlugin(fip_pf.PortForwardingPluginBase):
    """Implementation of the Neutron Port Forwarding Service Plugin.

    This class implements a Port Forwarding plugin.
    """

    supported_extension_aliases = ['floating-ip-port-forwarding']

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super(PortForwardingPlugin, self).__init__()
        self.push_api = resources_rpc.ResourcesPushRpcApi()
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.core_plugin = directory.get_plugin()

    def _get_internal_ip_subnet(self, request_ip, fixed_ips):
        request_ip = netaddr.IPNetwork(request_ip)
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']) == request_ip:
                return fixed_ip['subnet_id']

    def _find_a_router_for_fip_port_forwarding(
            self, context, pf_dict, fip_obj):
        internal_port_id = pf_dict['internal_port_id']
        internal_port = self.core_plugin.get_port(context, internal_port_id)
        v4_fixed_ips = [fixed_ip for fixed_ip in internal_port['fixed_ips']
                        if (netaddr.IPNetwork(fixed_ip['ip_address']
                                              ).version ==
                            lib_consts.IP_VERSION_4)]
        if not v4_fixed_ips:
            # As port forwarding works with ipv4 addresses,
            # if there is no ipv4 address, we need to raise.
            message = _("Requested internal port %s must allocate "
                        "an IPv4 address at least.") % internal_port_id
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)

        # Get the internal ip address, if not specified, choose the first ipv4
        # address.
        internal_ip_address = pf_dict.get('internal_ip_address')
        if not internal_ip_address:
            internal_ip_address = v4_fixed_ips[0]['ip_address']
            pf_dict['internal_ip_address'] = internal_ip_address
            internal_subnet_id = v4_fixed_ips[0]['subnet_id']
        else:
            # check the matched fixed ip
            internal_subnet_id = self._get_internal_ip_subnet(
                internal_ip_address, v4_fixed_ips)
            if not internal_subnet_id:
                message = _(
                    "Requested internal IP address %(internal_ip_address)s is "
                    "not suitable for internal neutron port "
                    "%(internal_port_id)s, as its fixed_ips are "
                    "%(fixed_ips)s") % {
                    'internal_ip_address': internal_ip_address,
                    'internal_port_id': internal_port['id'],
                    'fixed_ips': v4_fixed_ips}
                raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                         msg=message)

        internal_subnet = self.core_plugin.get_subnet(
            context, internal_subnet_id)
        external_network_id = fip_obj.floating_network_id
        try:
            return self.l3_plugin.get_router_for_floatingip(
                context, internal_port, internal_subnet, external_network_id)
        except lib_l3_exc.ExternalGatewayForFloatingIPNotFound:
            message = _(
                "External network %(external_net_id)s is not reachable from "
                "subnet %(internal_subnet_id)s. Cannot set "
                "Port forwarding for port %(internal_port_id)s with "
                "Floating IP %(port_forwarding_id)s") % {
                'external_net_id': external_network_id,
                'internal_subnet_id': internal_subnet_id,
                'internal_port_id': internal_port_id,
                'port_forwarding_id': fip_obj.id}
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)

    @db_base_plugin_common.convert_result_to_dict
    def create_floatingip_port_forwarding(self, context, floatingip_id,
                                          port_forwarding):
        port_forwarding = port_forwarding.get(apidef.RESOURCE_NAME)
        port_forwarding['floatingip_id'] = floatingip_id
        pf_obj = pf.PortForwarding(context, **port_forwarding)

        try:
            with db_api.context_manager.writer.using(context):
                fip_obj = self._get_fip_obj(context, floatingip_id)

                router_id = self._find_a_router_for_fip_port_forwarding(
                    context, port_forwarding, fip_obj)
                # If this func does not raise an exception, means the
                # router_id matched.
                # case1: fip_obj.router_id = None
                # case2: fip_obj.router_id is the same with we selected.
                self._check_router_match(context, fip_obj,
                                         router_id, port_forwarding)
                if not fip_obj.router_id:
                    fip_obj.router_id = router_id
                    fip_obj.update()
                pf_obj.create()
        except obj_exc.NeutronDbObjectDuplicateEntry:
            (__, conflict_params) = self._find_existing_port_forwarding(
                context, floatingip_id, port_forwarding)
            message = _("A duplicate port forwarding entry with same "
                        "attributes already exists, conflicting values "
                        "are %s") % conflict_params
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        self.push_api.push(context, [pf_obj], rpc_events.CREATED)
        return pf_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_floatingip_port_forwarding(self, context, id, floatingip_id,
                                          port_forwarding):
        port_forwarding = port_forwarding.get(apidef.RESOURCE_NAME)
        new_internal_port_id = None
        if port_forwarding and port_forwarding.get('internal_port_id'):
            new_internal_port_id = port_forwarding.get('internal_port_id')
        try:
            with db_api.context_manager.writer.using(context):
                fip_obj = self._get_fip_obj(context, floatingip_id)
                pf_obj = pf.PortForwarding.get_object(context, id=id)
                if not pf_obj:
                    raise pf_exc.PortForwardingNotFound(id=id)
                ori_internal_port_id = pf_obj.internal_port_id
                if new_internal_port_id and (new_internal_port_id !=
                                             ori_internal_port_id):
                    router_id = self._find_a_router_for_fip_port_forwarding(
                        context, port_forwarding, fip_obj)
                    self._check_router_match(context, fip_obj,
                                             router_id, port_forwarding)

                # As the socket will update when dict contains
                # internal_ip_address and internal_port.
                internal_ip_address = port_forwarding.get(
                    'internal_ip_address')
                internal_port = port_forwarding.get('internal_port')
                if any([internal_ip_address, internal_port]):
                    port_forwarding.update({
                        'internal_ip_address': internal_ip_address
                        if internal_ip_address else
                        str(pf_obj.internal_ip_address),
                        'internal_port': internal_port if internal_port else
                        pf_obj.internal_port
                    })
                pf_obj.update_fields(port_forwarding, reset_changes=True)
                pf_obj.update()
        except obj_exc.NeutronDbObjectDuplicateEntry:
            (__, conflict_params) = self._find_existing_port_forwarding(
                context, floatingip_id, pf_obj.to_dict())
            message = _("A duplicate port forwarding entry with same "
                        "attributes already exists, conflicting values "
                        "are %s") % conflict_params
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        self.push_api.push(context, [pf_obj], rpc_events.UPDATED)
        return pf_obj

    def _check_router_match(self, context, fip_obj, router_id, pf_dict):
        internal_port_id = pf_dict['internal_port_id']
        if fip_obj.router_id and fip_obj.router_id != router_id:
            objs = pf.PortForwarding.get_objects(
                context, floatingip_id=fip_obj.id,
                internal_ip_address=pf_dict['internal_ip_address'],
                internal_port=pf_dict['internal_port'])
            if objs:
                message = _("Floating IP %(floatingip_id)s with params: "
                            "internal_ip_address: %(internal_ip_address)s, "
                            "internal_port: %(internal_port)s "
                            "already exists") % {
                    'floatingip_id': fip_obj.id,
                    'internal_ip_address': pf_dict['internal_ip_address'],
                    'internal_port': pf_dict['internal_port']}
            else:
                message = _("The Floating IP %(floatingip_id)s had been set "
                            "on router %(router_id)s, the internal Neutron "
                            "port %(internal_port_id)s can not reach it") % {
                    'floatingip_id': fip_obj.id,
                    'router_id': fip_obj.router_id,
                    'internal_port_id': internal_port_id}
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)

    def _find_existing_port_forwarding(self, context, floatingip_id,
                                       port_forwarding, specify_params=None):
        # Because the session had been flushed by NeutronDbObjectDuplicateEntry
        # so if we want to use the context to get another db queries, we need
        # to rollback first.
        context.session.rollback()
        if not specify_params:
            specify_params = [
                {'floatingip_id': floatingip_id,
                 'external_port': port_forwarding['external_port']},
                {'internal_port_id': port_forwarding['internal_port_id'],
                 'internal_ip_address': port_forwarding['internal_ip_address'],
                 'internal_port': port_forwarding['internal_port']}]
        for param in specify_params:
            objs = pf.PortForwarding.get_objects(context, **param)
            if objs:
                return (objs[0], param)

    def _get_fip_obj(self, context, fip_id):
        fip_obj = router.FloatingIP.get_object(context, id=fip_id)
        if not fip_obj:
            raise lib_l3_exc.FloatingIPNotFound(floatingip_id=fip_id)
        return fip_obj

    @make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_floatingip_port_forwarding(self, context, id, floatingip_id,
                                       fields=None):
        self._get_fip_obj(context, floatingip_id)
        obj = pf.PortForwarding.get_object(context, id=id)
        if not obj:
            raise pf_exc.PortForwardingNotFound(id=id)
        return obj

    def _validate_filter_for_port_forwarding(self, request_filter):
        if not request_filter:
            return
        for filter_member_key in request_filter.keys():
            if filter_member_key in pf.FIELDS_NOT_SUPPORT_FILTER:
                raise pf_exc.PortForwardingNotSupportFilterField(
                    filter=filter_member_key)

    @make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_floatingip_port_forwardings(self, context, floatingip_id=None,
                                        filters=None, fields=None, sorts=None,
                                        limit=None, marker=None,
                                        page_reverse=False):
        self._get_fip_obj(context, floatingip_id)
        filters = filters or {}
        self._validate_filter_for_port_forwarding(filters)
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        return pf.PortForwarding.get_objects(
            context, _pager=pager, floatingip_id=floatingip_id, **filters)

    def delete_floatingip_port_forwarding(self, context, id, floatingip_id):
        pf_obj = pf.PortForwarding.get_object(context, id=id)

        if not pf_obj or pf_obj.floatingip_id != floatingip_id:
            raise pf_exc.PortForwardingNotFound(id=id)
        with db_api.context_manager.writer.using(context):
            fip_obj = self._get_fip_obj(context, pf_obj.floatingip_id)
            pf_objs = pf.PortForwarding.get_objects(
                context, floatingip_id=pf_obj.floatingip_id)
            if len(pf_objs) == 1 and pf_objs[0].id == pf_obj.id:
                fip_obj.update_fields({'router_id': None})
                fip_obj.update()
            pf_obj.delete()
        self.push_api.push(context, [pf_obj], rpc_events.DELETED)

    def sync_port_forwarding_fip(self, context, routers):
        if not routers:
            return

        router_ids = [router.get('id') for router in routers]
        router_pf_fip_set = collections.defaultdict(set)
        fip_pfs = collections.defaultdict(set)
        router_fip = collections.defaultdict(set)
        item_pf_fields = pf.PortForwarding.get_port_forwarding_obj_by_routers(
            context, router_ids)

        for router_id, fip_addr, pf_id, fip_id in item_pf_fields:
            router_pf_fip_set[router_id].add(utils.ip_to_cidr(fip_addr, 32))
            fip_pfs[fip_id].add(pf_id)
            router_fip[router_id].add(fip_id)

        for router in routers:
            if router['id'] in router_fip:
                router['port_forwardings_fip_set'] = router_pf_fip_set[
                    router['id']]
                router['fip_managed_by_port_forwardings'] = router_fip[
                    router['id']]
