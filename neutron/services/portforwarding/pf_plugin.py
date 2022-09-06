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
import copy

import netaddr
from neutron_lib.api.definitions import expose_port_forwarding_in_fip
from neutron_lib.api.definitions import fip_pf_description
from neutron_lib.api.definitions import fip_pf_port_range
from neutron_lib.api.definitions import floating_ip_port_forwarding as apidef
from neutron_lib.api.definitions import l3
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_consts
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import l3 as lib_l3_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as oslo_db_exc
from oslo_log import log as logging

from neutron._i18n import _
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import utils
from neutron.db import db_base_plugin_common
from neutron.db import l3_dvr_db
from neutron.extensions import floating_ip_port_forwarding as fip_pf
from neutron.objects import base as base_obj
from neutron.objects import port_forwarding as pf
from neutron.objects import router as l3_obj
from neutron.services.portforwarding.common import exceptions as pf_exc
from neutron.services.portforwarding import constants as pf_consts

LOG = logging.getLogger(__name__)

# Move to neutron-lib someday.
PORT_FORWARDING_FLOATINGIP_KEY = '_pf_floatingips'


def _required_service_plugins():
    SvcPlugin = collections.namedtuple('SvcPlugin', 'plugin uses_rpc')
    l3_router = SvcPlugin(l3.ROUTER, True)
    supported_svc_plugins = [
        l3_router,
        SvcPlugin('ovn-router', False),
        SvcPlugin('neutron.services.ovn_l3.plugin.OVNL3RouterPlugin', False)]
    plugins = []
    rpc_required = False
    try:
        for svc in supported_svc_plugins:
            if svc.plugin in cfg.CONF.service_plugins:
                plugins.append(svc.plugin)
                rpc_required |= svc.uses_rpc
    except cfg.NoSuchOptError:
        pass
    if plugins:
        return plugins, rpc_required
    # Use l3_router as required service plugin if no other was provided.
    return [l3_router.plugin], l3_router.uses_rpc


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class PortForwardingPlugin(fip_pf.PortForwardingPluginBase):
    """Implementation of the Neutron Port Forwarding Service Plugin.

    This class implements a Port Forwarding plugin.
    """

    required_service_plugins, _rpc_notifications_required = \
        _required_service_plugins()

    supported_extension_aliases = [apidef.ALIAS,
                                   expose_port_forwarding_in_fip.ALIAS,
                                   fip_pf_description.ALIAS,
                                   fip_pf_port_range.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(PortForwardingPlugin, self).__init__()
        self.push_api = resources_rpc.ResourcesPushRpcApi() \
            if self._rpc_notifications_required else None
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.core_plugin = directory.get_plugin()
        registry.publish(pf_consts.PORT_FORWARDING_PLUGIN, events.AFTER_INIT,
                         self)

    @staticmethod
    @resource_extend.extends([l3.FLOATINGIPS])
    def _extend_floatingip_dict(result_dict, db):
        fields = [apidef.ID, apidef.INTERNAL_IP_ADDRESS, apidef.PROTOCOL,
                  apidef.INTERNAL_PORT, apidef.EXTERNAL_PORT,
                  apidef.INTERNAL_PORT_ID]
        result_dict[apidef.COLLECTION_NAME] = []
        if db.port_forwardings:
            port_forwarding_result = []
            for port_forwarding in db.port_forwardings:
                pf_dict = pf.PortForwarding.modify_fields_from_db(
                    port_forwarding)
                for key in list(pf_dict.keys()):
                    if key not in fields:
                        pf_dict.pop(key)
                    elif key == apidef.INTERNAL_IP_ADDRESS:
                        pf_dict[key] = str(pf_dict[key])
                port_forwarding_result.append(pf_dict)
            result_dict[apidef.COLLECTION_NAME] = port_forwarding_result
        return result_dict

    @registry.receives(resources.FLOATING_IP, [events.BEFORE_CREATE,
                                               events.BEFORE_UPDATE])
    def _check_port_has_port_forwarding(self, resource, event,
                                        trigger, payload=None):
        port_id = payload.request_body['floatingip'].get('port_id')
        if not port_id:
            return

        pf_objs = pf.PortForwarding.get_objects(
            payload.context, internal_port_id=port_id)
        if not pf_objs:
            return
        # Port may not bind to host yet, or port may migrate from one
        # dvr_no_external host to one dvr host. So we just do not allow
        # all dvr router's floating IP to be binded to a port which
        # already has port forwarding.
        router = self.l3_plugin.get_router(payload.context.elevated(),
                                           pf_objs[0].router_id)
        if l3_dvr_db.is_distributed_router(router):
            raise pf_exc.PortHasPortForwarding(port_id=port_id)

    @registry.receives(resources.FLOATING_IP, [events.PRECOMMIT_UPDATE,
                                               events.PRECOMMIT_DELETE])
    def _check_floatingip_request(self, resource, event, trigger, payload):
        # We only support the "free" floatingip to be associated with
        # port forwarding resources. And in the PUT request of floatingip,
        # the request body must contain a "port_id" field which is not
        # allowed in port forwarding functionality.
        context = payload.context
        floatingip_id = None
        if event == events.PRECOMMIT_UPDATE:
            floatingip = payload.states[-1]
            fip_db = payload.desired_state
            floatingip_id = fip_db.id
            # Here the key-value must contain a floatingip param, and the value
            # must a dict with key 'floatingip'.
            if not floatingip['floatingip'].get('port_id'):
                # Only care about the associate floatingip cases.
                # The port_id field is a must-option. But if a floatingip
                # disassociate a internal port, the port_id should be null.
                LOG.debug('Skip check for floatingip %s, as the update '
                          'request does not contain port_id.', floatingip_id)
                return
        elif event == events.PRECOMMIT_DELETE:
            port = payload.states[-1]
            floatingip_id = port.get('device_id')
        if not floatingip_id:
            return

        if pf.PortForwarding.objects_exist(context,
                                           floatingip_id=floatingip_id):
            raise pf_exc.FipInUseByPortForwarding(id=floatingip_id)

    @registry.receives(resources.PORT, [events.AFTER_UPDATE,
                                        events.PRECOMMIT_DELETE])
    def _process_port_request_handler(self, resource, event, trigger,
                                      payload):

        return self._process_port_request(event, payload.context,
                                          payload.latest_state)

    @db_api.retry_if_session_inactive()
    def _process_port_request(self, event, context, port):
        # Deleting floatingip will receive port resource with precommit_delete
        # event, so just return, then check the request in
        # _check_floatingip_request callback.
        if port['device_owner'].startswith(
                lib_consts.DEVICE_OWNER_FLOATINGIP):
            return

        # This block is used for checking if there are some fixed ips updates.
        # Whatever the event is AFTER_UPDATE/PRECOMMIT_DELETE,
        # we will use the update_ip_set for checking if the possible associated
        # port forwarding resources need to be deleted for port's AFTER_UPDATE
        # event. Or get all affected ip addresses for port's PRECOMMIT_DELETE
        # event.
        port_id = port['id']
        update_fixed_ips = port['fixed_ips']
        update_ip_set = set()
        for update_fixed_ip in update_fixed_ips:
            if (netaddr.IPNetwork(update_fixed_ip.get('ip_address')).version ==
                    lib_consts.IP_VERSION_4):
                update_ip_set.add(update_fixed_ip.get('ip_address'))
        if not update_ip_set:
            return

        # If the port owner wants to update or delete port, we must elevate the
        # context to check if the floatingip or port forwarding resources
        # are owned by other tenants.
        if not context.is_admin:
            context = context.elevated()
        # If the logic arrives here, that means we have got update_ip_set and
        # its value is not None. So we need to get all port forwarding
        # resources based on the request port_id for preparing the next
        # process, such as deleting them.
        pf_resources = pf.PortForwarding.get_objects(
            context, internal_port_id=port_id)
        if not pf_resources:
            return

        # If the logic arrives here, that means we have got pf_resources and
        # its value is not None either. Then we collect all ip addresses
        # which are used by port forwarding resources to generate used_ip_set,
        # and we default to set remove_ip_set as used_ip_set which means we
        # want to delete all port forwarding resources when event is
        # PRECOMMIT_DELETE. And when event is AFTER_UPDATE, we get the
        # different part.
        used_ip_set = set()
        for pf_resource in pf_resources:
            used_ip_set.add(str(pf_resource.internal_ip_address))
        remove_ip_set = used_ip_set
        if event == events.AFTER_UPDATE:
            remove_ip_set = used_ip_set - update_ip_set
            if not remove_ip_set:
                return

        # Here, we get the remove_ip_set, the following block will delete the
        # port forwarding resources based on remove_ip_set. Just need to note
        # here, if event is AFTER_UPDATE, and remove_ip_set is empty, the
        # following block won't be processed.
        remove_port_forwarding_list = []
        with db_api.CONTEXT_WRITER.using(context):
            for pf_resource in pf_resources:
                if str(pf_resource.internal_ip_address) in remove_ip_set:
                    pf_objs = pf.PortForwarding.get_objects(
                        context, floatingip_id=pf_resource.floatingip_id)
                    if len(pf_objs) == 1 and pf_objs[0].id == pf_resource.id:
                        fip_obj = l3_obj.FloatingIP.get_object(
                            context, id=pf_resource.floatingip_id)
                        fip_obj.update_fields({'router_id': None})
                        fip_obj.update()
                    pf_resource.delete()
                    remove_port_forwarding_list.append(pf_resource)

        if self._rpc_notifications_required:
            self.push_api.push(context, remove_port_forwarding_list,
                               rpc_events.DELETED)
        for pf_obj in remove_port_forwarding_list:
            payload = events.DBEventPayload(context, states=(pf_obj,))
            registry.publish(pf_consts.PORT_FORWARDING,
                             events.AFTER_DELETE,
                             self,
                             payload=payload)

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

    def _check_port_has_binding_floating_ip(self, context, port_forwarding):
        port_id = port_forwarding['internal_port_id']
        floatingip_objs = l3_obj.FloatingIP.get_objects(
            context.elevated(),
            fixed_port_id=port_id)
        if floatingip_objs:
            floating_ip_address = floatingip_objs[0].floating_ip_address
            raise pf_exc.PortHasBindingFloatingIP(
                floating_ip_address=floating_ip_address,
                fip_id=floatingip_objs[0].id,
                port_id=port_id,
                fixed_ip=port_forwarding['internal_ip_address'])

    @db_base_plugin_common.convert_result_to_dict
    def create_floatingip_port_forwarding(self, context, floatingip_id,
                                          port_forwarding):
        port_forwarding = port_forwarding.get(apidef.RESOURCE_NAME)
        port_forwarding['floatingip_id'] = floatingip_id

        self._check_port_collisions(context, floatingip_id, port_forwarding)
        self._check_port_has_binding_floating_ip(context, port_forwarding)
        with db_api.CONTEXT_WRITER.using(context):
            fip_obj = self._get_fip_obj(context, floatingip_id)
            if fip_obj.fixed_port_id:
                raise lib_l3_exc.FloatingIPPortAlreadyAssociated(
                    port_id=port_forwarding['internal_port_id'],
                    fip_id=fip_obj.id,
                    floating_ip_address=fip_obj.floating_ip_address,
                    fixed_ip=str(port_forwarding['internal_ip_address']),
                    net_id=fip_obj.floating_network_id)
            router_id = self._find_a_router_for_fip_port_forwarding(
                context, port_forwarding, fip_obj)
            pf_obj = pf.PortForwarding(context, **port_forwarding)

            # If this func does not raise an exception, means the
            # router_id matched.
            # case1: fip_obj.router_id = None
            # case2: fip_obj.router_id is the same with we selected.
            self._check_router_match(context, fip_obj,
                                     router_id, port_forwarding)

            if not fip_obj.router_id:
                values = {'router_id': router_id, 'fixed_port_id': None}
                l3_obj.FloatingIP.update_objects(
                    context, values, id=floatingip_id)
            try:
                pf_obj.create()
            except obj_exc.NeutronDbObjectDuplicateEntry:
                (__,
                 conflict_params) = self._find_existing_port_forwarding(
                    context, floatingip_id, port_forwarding)
                message = _("A duplicate port forwarding entry with same "
                            "attributes already exists, conflicting "
                            "values are %s") % conflict_params
                raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                         msg=message)

        registry.publish(pf_consts.PORT_FORWARDING, events.AFTER_CREATE,
                         self,
                         payload=events.DBEventPayload(context,
                                                       states=(pf_obj,)))

        if self._rpc_notifications_required:
            self.push_api.push(context, [pf_obj], rpc_events.CREATED)

        return pf_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_floatingip_port_forwarding(self, context, id, floatingip_id,
                                          port_forwarding):
        port_forwarding = port_forwarding.get(apidef.RESOURCE_NAME)
        new_internal_port_id = None
        if port_forwarding and port_forwarding.get('internal_port_id'):
            new_internal_port_id = port_forwarding.get('internal_port_id')
            self._check_port_has_binding_floating_ip(context, port_forwarding)

        try:
            with db_api.CONTEXT_WRITER.using(context):
                fip_obj = self._get_fip_obj(context, floatingip_id)
                pf_obj = pf.PortForwarding.get_object(context, id=id)
                if not pf_obj:
                    raise pf_exc.PortForwardingNotFound(id=id)
                original_pf_obj = copy.deepcopy(pf_obj)
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
                self._check_port_forwarding_update(context, pf_obj)

                port_changed_keys = ['internal_port', 'internal_port_range',
                                     'external_port', 'external_port_range']

                if [k for k in port_changed_keys if k in port_forwarding]:
                    self._check_port_collisions(
                        context, floatingip_id, port_forwarding,
                        id, pf_obj.get('internal_port_id'),
                        pf_obj.get('protocol'),
                        pf_obj.get('internal_ip_address'))

                pf_obj.update()
        except oslo_db_exc.DBDuplicateEntry:
            (__, conflict_params) = self._find_existing_port_forwarding(
                context, floatingip_id, pf_obj.to_dict())
            message = _("A duplicate port forwarding entry with same "
                        "attributes already exists, conflicting values "
                        "are %s") % conflict_params
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        if self._rpc_notifications_required:
            self.push_api.push(context, [pf_obj], rpc_events.UPDATED)
        registry.publish(pf_consts.PORT_FORWARDING, events.AFTER_UPDATE,
                         self,
                         payload=events.DBEventPayload(
                             context,
                             states=(original_pf_obj, pf_obj)))
        return pf_obj

    def _check_collision(self, pf_objs, port, port_key, id):
        for port_forwarding_registry in pf_objs:
            if id == port_forwarding_registry['id']:
                continue

            existing_port = port_forwarding_registry.get(port_key)
            err_msg = _("There is a port collision with the %s. The "
                        "following ranges collides: %s and %s")

            if self._range_collides(existing_port, port):
                raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                         msg=err_msg % (
                                             port_key,
                                             existing_port,
                                             port))

    def _check_port_collisions(self, context, floatingip_id, pf_dict,
                               id=None, internal_port_id=None,
                               protocol=None, internal_ip_address=None):
        external_range_pf_dict = pf_dict.get('external_port_range')
        if not external_range_pf_dict and 'external_port' in pf_dict:
            external_range_pf_dict = '%(port)s:%(port)s' % {
                'port': pf_dict.get('external_port')}

        internal_range_pf_dict = pf_dict.get('internal_port_range')
        if not internal_range_pf_dict and 'internal_port' in pf_dict:
            internal_range_pf_dict = '%(port)s:%(port)s' % {
                'port': pf_dict.get('internal_port')}

        internal_port_id = pf_dict.get('internal_port_id') or internal_port_id
        protocol = pf_dict.get('protocol') or protocol
        internal_ip_address = pf_dict.get(
            'internal_ip_address') or internal_ip_address
        self._validate_ranges(
            internal_port_range=internal_range_pf_dict,
            external_port_range=external_range_pf_dict)

        if internal_range_pf_dict:
            pf_same_internal_port = pf.PortForwarding.get_objects(
                context, internal_port_id=internal_port_id,
                protocol=protocol, internal_ip_address=internal_ip_address)
            self._check_collision(pf_same_internal_port,
                                  internal_range_pf_dict,
                                  'internal_port_range',
                                  id)

        if external_range_pf_dict:
            pf_same_fips = pf.PortForwarding.get_objects(
                context, floatingip_id=floatingip_id,
                protocol=protocol)
            self._check_collision(pf_same_fips,
                                  external_range_pf_dict,
                                  'external_port_range',
                                  id)

    def _validate_ranges(self, internal_port_range=None,
                         external_port_range=None):
        err_invalid_relation = _(
            "Invalid ranges of internal and/or external ports. "
            "The relation between internal and external ports "
            "must be N-N or 1-N")

        internal_dif = self._get_port_range(internal_port_range)
        external_dif = self._get_port_range(external_port_range)

        if internal_dif > 0 and internal_dif != external_dif:
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=err_invalid_relation)

    def _get_port_range(self, port_range=None):
        if not port_range:
            return 0

        if ':' in port_range:
            initial_port, final_port = list(map(int,
                                                str(port_range).split(':')))
            return final_port - initial_port

        return 0

    def _range_collides(self, range_a, range_b):
        range_a = list(map(int, str(range_a).split(':')))
        range_b = list(map(int, str(range_b).split(':')))

        invalid_port = next((port for port in (range_a + range_b)
                             if 65535 < port or port < 1), None)

        if invalid_port:
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg="Invalid port value, the "
                                         "port value must be "
                                         "a value between 1 and 65535.")

        initial_intersection = max(range_a[0], range_b[0])
        final_intersection = min(range_a[-1], range_b[-1])
        return initial_intersection <= final_intersection

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

    def _check_port_forwarding_update(self, context, pf_obj):
        def _raise_port_forwarding_update_failed(conflict):
            message = _("Another port forwarding entry with the same "
                        "attributes already exists, conflicting "
                        "values are %s") % conflict
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)

        db_port = self.core_plugin.get_port(context, pf_obj.internal_port_id)
        for fixed_ip in db_port['fixed_ips']:
            if str(pf_obj.internal_ip_address) == fixed_ip['ip_address']:
                break
        else:
            # Reached end of internal_port iteration w/out finding fixed_ip
            message = _("The internal IP does not correspond to an "
                        "address on the internal port, which has "
                        "fixed_ips %s") % db_port['fixed_ips']
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        objs = pf.PortForwarding.get_objects(
            context,
            floatingip_id=pf_obj.floatingip_id,
            protocol=pf_obj.protocol)
        for obj in objs:
            if obj.id == pf_obj.id:
                continue
            # Ensure there are no conflicts on the outside
            if (obj.floating_ip_address == pf_obj.floating_ip_address and
                    obj.external_port == pf_obj.external_port):
                _raise_port_forwarding_update_failed(
                    {'floating_ip_address': str(obj.floating_ip_address),
                     'external_port': obj.external_port})
            # Ensure there are no conflicts in the inside
            # socket: internal_ip_address + internal_port
            if (obj.internal_port_id == pf_obj.internal_port_id and
                    obj.internal_ip_address == pf_obj.internal_ip_address and
                    obj.internal_port == pf_obj.internal_port):
                _raise_port_forwarding_update_failed(
                    {'internal_port_id': obj.internal_port_id,
                     'internal_ip_address': str(obj.internal_ip_address),
                     'internal_port': obj.internal_port})

    def _find_existing_port_forwarding(self, context, floatingip_id,
                                       port_forwarding, specify_params=None):
        # Because the session had been flushed by NeutronDbObjectDuplicateEntry
        # so if we want to use the context to get another db queries, we need
        # to rollback first.
        context.session.rollback()
        if not specify_params:
            specify_params = [
                {'floatingip_id': floatingip_id,
                 'external_port': port_forwarding['external_port'],
                 'protocol': port_forwarding['protocol']},
                {'internal_port_id': port_forwarding['internal_port_id'],
                 'internal_ip_address': port_forwarding['internal_ip_address'],
                 'internal_port': port_forwarding['internal_port'],
                 'protocol': port_forwarding['protocol']}]
        for param in specify_params:
            objs = pf.PortForwarding.get_objects(context, **param)
            if objs:
                return (objs[0], param)

    def _get_fip_obj(self, context, fip_id):
        fip_obj = l3_obj.FloatingIP.get_object(context, id=fip_id)
        if not fip_obj:
            raise lib_l3_exc.FloatingIPNotFound(floatingip_id=fip_id)
        return fip_obj

    @db_base_plugin_common.make_result_with_fields
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

    @db_base_plugin_common.make_result_with_fields
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
        with db_api.CONTEXT_WRITER.using(context):
            fip_obj = self._get_fip_obj(context, pf_obj.floatingip_id)
            pf_objs = pf.PortForwarding.get_objects(
                context, floatingip_id=pf_obj.floatingip_id)
            if len(pf_objs) == 1 and pf_objs[0].id == pf_obj.id:
                fip_obj.update_fields({'router_id': None})
                fip_obj.update()
            pf_obj.delete()
        if self._rpc_notifications_required:
            self.push_api.push(context, [pf_obj], rpc_events.DELETED)
        registry.publish(pf_consts.PORT_FORWARDING, events.AFTER_DELETE,
                         self,
                         payload=events.DBEventPayload(context,
                                                       states=(pf_obj,)))

    def sync_port_forwarding_fip(self, context, routers):
        if not routers:
            return

        router_ids = [router.get('id') for router in routers]
        router_pf_fip_set = collections.defaultdict(set)
        fip_pfs = collections.defaultdict(set)
        router_fip_ids = collections.defaultdict(set)
        item_pf_fields = pf.PortForwarding.get_port_forwarding_obj_by_routers(
            context, router_ids)

        for router_id, fip_addr, pf_id, fip_id in item_pf_fields:
            router_pf_fip_set[router_id].add(utils.ip_to_cidr(fip_addr, 32))
            fip_pfs[fip_id].add(pf_id)
            router_fip_ids[router_id].add(fip_id)

        for router in routers:
            if router['id'] in router_fip_ids:
                router['port_forwardings_fip_set'] = router_pf_fip_set[
                    router['id']]
                router['fip_managed_by_port_forwardings'] = router_fip_ids[
                    router['id']]

                router_pf_fips_info = router.get(
                    PORT_FORWARDING_FLOATINGIP_KEY, [])
                for fip_id in router_fip_ids[router['id']]:
                    fip = self.l3_plugin.get_floatingip(context, fip_id)
                    router_pf_fips_info.append(fip)
                router[PORT_FORWARDING_FLOATINGIP_KEY] = router_pf_fips_info
