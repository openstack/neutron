# Copyright (c) 2023 Canonical Ltd.
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

import copy

import netaddr

from neutron._i18n import _
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_enable_default_route_bfd
from neutron_lib.api.definitions import l3_enable_default_route_ecmp
from neutron_lib.api.definitions import l3_ext_gw_multihoming
from neutron_lib.api import extensions
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.exceptions import l3_ext_gw_multihoming as mh_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory


def format_gateway_info(gw_port):
    return {
        'network_id': gw_port.network_id,
        'external_fixed_ips': [{
            'ip_address': str(alloc.ip_address),
            'subnet_id': alloc.subnet_id,
        } for alloc in gw_port.fixed_ips]
    }


@resource_extend.has_resource_extenders
class ExtraGatewaysDbOnlyMixin(l3_gwmode_db.L3_NAT_dbonly_mixin):
    """A mixin class to expose a router's extra external gateways."""

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict_extra_gateways(router_res, router_db):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        if not extensions.is_extension_supported(
                l3_plugin, l3_ext_gw_multihoming.ALIAS):
            return

        external_gateways = []
        for gw_port in [
                rp.port
                for rp in router_db.attached_ports
                if rp.port.device_owner == constants.DEVICE_OWNER_ROUTER_GW]:
            if gw_port.id == router_db.gw_port_id:
                external_gateways.insert(0, format_gateway_info(gw_port))
            else:
                external_gateways.append(format_gateway_info(gw_port))

        router_res[l3_ext_gw_multihoming.EXTERNAL_GATEWAYS] = external_gateways

    @registry.receives(resources.ROUTER, [events.BEFORE_DELETE])
    def _delete_router_remove_external_gateways(self, resource, event,
                                                trigger, payload):
        self._remove_all_gateways(payload.context, payload.resource_id)

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_bfd_ecmp_request(self, resource, event, trigger, payload):
        router = payload.latest_state
        router_db = payload.metadata['router_db']
        for attr in (l3_enable_default_route_ecmp.ENABLE_DEFAULT_ROUTE_ECMP,
                     l3_enable_default_route_bfd.ENABLE_DEFAULT_ROUTE_BFD):
            value = router.get(attr)
            if value is not None:
                self.set_extra_attr_value(router_db, attr, value)

    def _add_external_gateways(
            self, context, router_id, gw_info_list, payload):
        """Add external gateways to a router."""
        added_gateways = []
        if not gw_info_list:
            return added_gateways

        # If a router already has extra gateways specified then they need to
        # be changed via the update API.
        router_db = self._get_router(context, router_id)

        if any(rp.port.device_owner == constants.DEVICE_OWNER_ROUTER_GW
               for rp in router_db.attached_ports):
            # Matching for gateway ports with the same network_id and set of
            # fixed_ips is not needed since an IP allocation would fail in this
            # case. And if fixed IPs don't overlap or are not specified a new
            # port will simply be created.
            extra_gw_info = gw_info_list
        else:
            compat_gw_info = gw_info_list[0]
            compat_payload = copy.deepcopy(payload)
            compat_payload['router'].pop('external_gateways')
            compat_payload['external_gateway_info'] = compat_gw_info

            # Update the first router gateway since we treat it in a special
            # way for compatibility.
            self._update_router_gw_info(context, router_id, compat_gw_info,
                                        compat_payload)
            added_gateways.append(compat_gw_info)

            extra_gw_info = gw_info_list[1:]

        # Go over extra gateway ports and add them to the router.
        for gw_info in extra_gw_info:
            # The ``_validate_gw_info`` and ``_create_extra_gw_port`` methods
            # need an updated version of the router_db object, both as a
            # result of the ``_update_router_gw_info`` call above, and as
            # ports are added.
            router_db = self._get_router(context, router_id)

            # Here we do not need to check for external gateway port IP changes
            # as there are no ports yet.
            ext_ips = gw_info.get('external_fixed_ips', [])

            network_id = self._validate_gw_info(context, gw_info,
                                                ext_ips, router_db)
            self._create_extra_gw_port(context, router_db,
                                       network_id, ext_ips)
            added_gateways.append(gw_info)

        return added_gateways

    def _create_extra_gw_port(self, context, router_db, new_network_id,
                              ext_ips):
        with db_api.CONTEXT_READER.using(context):
            # This function should only be used when we have a compat port id
            # added using the compat API that expects one gateway only.
            if not router_db.gw_port:
                raise mh_exc.UnableToAddExtraGateways(
                    router_id=router_db.id,
                    reason=_('router does not have a compatibility gateway '
                             'port'))

        if not new_network_id:
            return

        subnets = self._core_plugin.get_subnets_by_network(context,
                                                           new_network_id)
        # TODO(dmitriis): publish an events.BEFORE_CREATE event for a new
        # resource type e.g. resources.ROUTER_EXTRA_GATEWAY. Semantically
        # this is a different resource from resources.ROUTER_GATEWAY.
        self._check_for_dup_router_subnets(
            context, router_db,
            subnets,
            constants.DEVICE_OWNER_ROUTER_GW
        )
        self._create_router_gw_port(context, router_db,
                                    new_network_id, ext_ips,
                                    update_gw_port=False)

        # TODO(dmitriis): publish an events.AFTER_CREATE event for a new
        # resource type e.g. resources.ROUTER_EXTRA_GATEWAY. Semantically
        # this is a different resource from resources.ROUTER_GATEWAY.

    def _check_for_dup_router_subnets(self, context, router_db,
                                      new_subnets, new_device_owner):
        """Check for overlapping subnets on different networks.

        This method overrides the one in the base class so the logic will be
        triggered for both the compatibility code that might alter the state
        of a single gateway port in the presence of multiple gateway ports
        (without an override it could result in overlap errors that are not
        relevant with the code base supporting multiple gateway ports attached
        to the same network).

        It is possible to have multiple gateway ports attached to the same
        external network which will cause subnets of ports to overlap but will
        not cause issues with routing. However, attaching multiple gateway
        ports to different networks with overlapping subnet ranges will cause
        routing issues. This function checks for that kind of overlap in
        addition to the compatibility cases such as an overlap between
        internal and external network subnets. This is done using the
        device owner field of a port that is planned to be created by the
        caller: specifically, based on that this argument the method can
        tell if new subnets are meant to be associated with a gateway port
        or an internal port.

        :param context: neutron API request context
        :type context: neutron_lib.context.Context
        :param router_db: The router db object to do a check for.
        :type router: neutron.db.models.l3.Router
        :param new_subnets: A list of new subnets to be added to the router
        :type new_subnets: list[neutron.db.models_v2.Subnet]
        :param new_device_owner: A device owner field for the port that is
                                 going to be created with new subnets.
        """
        router_subnets = []
        ext_subnets = set()
        for p in (rp.port for rp in router_db.attached_ports):
            for ip in p['fixed_ips']:
                existing_port_owner = p.get('device_owner')
                if existing_port_owner == constants.DEVICE_OWNER_ROUTER_GW:
                    ext_subts = self._core_plugin.get_subnets(
                        context.elevated(),
                        filters={'network_id': [p['network_id']]})
                    for sub in ext_subts:
                        router_subnets.append(sub['id'])
                        ext_subnets.add(sub['id'])
                else:
                    router_subnets.append(ip['subnet_id'])
        if not router_subnets:
            return

        # Ignore temporary Prefix Delegation CIDRs
        new_subnets = [s for s in new_subnets
                       if s['cidr'] != constants.PROVISIONAL_IPV6_PD_PREFIX]
        id_filter = {'id': router_subnets}
        subnets = self._core_plugin.get_subnets(context.elevated(),
                                                filters=id_filter)
        for sub in subnets:
            for new_s in new_subnets:
                # Overlapping subnet ranges are a problem if there is an
                # overlap between subnets on different external networks,
                # between internal and external networks or internal networks
                # (including the case where an attempt to add multiple internal
                # ports on the same subnet is made for the same router).
                if not (new_s['id'] in ext_subnets and
                        new_device_owner == constants.DEVICE_OWNER_ROUTER_GW):
                    self._raise_on_subnets_overlap(sub, new_s)

    def _match_requested_gateway_ports(self, context, router_id,
                                       gw_info_list):
        """Match indirect references to gateway ports to the actual ports.

        Returns 3 parameters:

        1. A dictionary which maps matched gateway port ids to
           external_gateway_info dictionaries as they were passed in
        2. A dict with partial matches on fixed ips
        3. A list of gateway info dictionaries for which there aren't any
           existing gateway ports.
        """
        matched_port_ids = {}
        part_matched_port_ids = {}
        nonexistent_port_info = []
        for gw_info in gw_info_list:
            net_id = gw_info['network_id']
            # Find any gateways that might be attached to the same network.
            gw_ports = port_obj.Port.get_ports_by_router_and_network(
                context, router_id, constants.DEVICE_OWNER_ROUTER_GW, net_id)

            if not gw_ports:
                nonexistent_port_info.append(gw_info)
                continue

            if not gw_info.get('external_fixed_ips'):
                # Allow for one case where external_fixed_ips are not specified
                # in the request but there is only one gateway port attached to
                # particular network on a router - there is no ambiguity about
                # which port do we want to find in this case.
                if len(gw_ports) == 1:
                    gw_port = gw_ports[0]
                    part_matched_port_ids[gw_port['id']] = gw_info
                    continue
                # Matching to specific fixed IPs of gateway ports is done
                # based on the parameters of a request, otherwise it would
                # be unclear which one of the gateway ports to match to.
                raise mh_exc.UnableToMatchGateways(
                    router_id=router_id,
                    reason=_(
                        'multiple gateway ports are attached to the same '
                        'network %s but external_fixed_ips parameter '
                        'is not specified in the request') % net_id)

            for gw_port in gw_ports:
                current_set = set([a.ip_address for a in gw_port['fixed_ips']])
                target_set = set([netaddr.IPAddress(d['ip_address'])
                                  for d in gw_info['external_fixed_ips']])
                # If there is an intersection - it's a partial match.
                if current_set & target_set:
                    part_matched_port_ids[gw_port['id']] = gw_info
                    # It can also be a full match.
                    if current_set == target_set:
                        matched_port_ids[gw_port['id']] = gw_info
                    break
            else:
                raise mh_exc.UnableToMatchGateways(
                    router_id=router_id,
                    reason=_('could not match a gateway port attached to '
                             'network %s based on the specified fixed IPs '
                             '%s') % (net_id,
                                      gw_info['external_fixed_ips']))
        return matched_port_ids, part_matched_port_ids, nonexistent_port_info

    def _replace_compat_gw_port(self, context, router_db, new_gw_port_id):
        with db_api.CONTEXT_WRITER.using(context):
            router_db['gw_port_id'] = new_gw_port_id

    def _remove_external_gateways(self, context, router_id, gw_info_list,
                                  payload):
        """Remove external gateways from a router."""
        removed_gateways = []
        if not gw_info_list:
            return removed_gateways

        gw_ports = l3_obj.RouterPort.get_gw_port_ids_by_router_id(context,
                                                                  router_id)
        if not gw_ports:
            raise mh_exc.UnableToRemoveGateways(
                router_id=router_id,
                reason=_('the router does not have any external gateways'))

        # The `_validate_gw_info` method takes a DB object.
        router_db = self._get_router(context, router_id)

        # Go over extra gateways and validate the specified information.
        for gw_info in gw_info_list:
            ext_ips = gw_info.get(
                'external_fixed_ips', [])
            self._validate_gw_info(context, gw_info, ext_ips, router_db)

        found_gw_port_ids, part_matches, nonexistent_port_info = (
            self._match_requested_gateway_ports(context, router_id,
                                                gw_info_list))
        if nonexistent_port_info:
            raise mh_exc.UnableToMatchGateways(
                router_id=router_id,
                reason=_('could not match gateway port IDs for gateway info '
                         'with networks %s') % (
                             ', '.join(i['network_id']
                                       for i in nonexistent_port_info)))

        # If the compatibility gw_port_id is to be removed, do it after
        # the removal of extra gateway ports but stash up some information.
        compat_gw_port_info = part_matches.pop(router_db['gw_port_id'])

        # Actually remove extra gateways first.
        for extra_gw_port_id in part_matches.keys():
            self._delete_extra_gw_port(context, router_id, extra_gw_port_id)
            removed_gateways.append(part_matches[extra_gw_port_id])

        # If the matched gateway port ID includes the compatibility one, handle
        # its removal in a compatible way.
        if compat_gw_port_info:
            # Removal is done by making an empty update using the
            # compatibility interface. This allows reusing pre-removal checks
            # like the FIP presence check.
            self._update_router_gw_info(context, router_id, {}, {})
            removed_gateways.append(compat_gw_port_info)

        # If there are any ports remaining besides the compatibility one
        # and its removal was done, make sure the remaining port becomes
        # the compatibility port. This is not atomic but the extra GW port
        # should not be removed in the process.
        gw_ports = l3_obj.RouterPort.get_gw_port_ids_by_router_id(context,
                                                                  router_id)
        if not router_db['gw_port_id'] and len(gw_ports) > 0:
            new_gw_port_id = gw_ports[0]
            new_network_id = port_obj.Port.get_object(
                context, id=new_gw_port_id).network_id
            # Replace the gw_port_id on the router object with an existing one.
            self._replace_compat_gw_port(context, router_db, new_gw_port_id)
            # Generate a compatibility payload.
            synthetic_payload = copy.deepcopy(payload)
            synthetic_payload['router'].pop('external_gateways')
            # Here we only need a network_id because the fixed IPs are already
            # assigned and do not need to be changed.
            info = {
                'network_id': new_network_id
            }
            synthetic_payload['router']['external_gateway_info'] = info
            # Finally update the compatibility gateway port.
            self._update_router_gw_info(
                context, router_id, info, synthetic_payload)

        return removed_gateways

    def _router_extra_gw_port_has_floating_ips(self, context, router_id,
                                               gw_port):
        return l3_obj.FloatingIP.count(context, **{
            'router_id': [router_id],
            'floating_network_id': gw_port.network_id,
        })

    def _delete_extra_gw_port(self, context, router_id, gw_port_id):
        admin_ctx = context.elevated()
        gw_port = port_obj.Port.get_object(context, id=gw_port_id)
        fip_count = self._router_extra_gw_port_has_floating_ips(context,
                                                                router_id,
                                                                gw_port)
        if fip_count:
            # Check that there are still other gateway ports attached to the
            # same network, otherwise this gateway port cannot be deleted.
            gw_ports = port_obj.Port.get_ports_by_router_and_network(
                context, router_id, constants.DEVICE_OWNER_ROUTER_GW,
                gw_port.network_id)
            if len(gw_ports) < 2:
                raise l3_exc.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router_id, net_id=gw_port.network_id)

        # TODO(dmitriis): publish an events.BEFORE_DELETE event for a new
        # resource type e.g. resources.ROUTER_EXTRA_GATEWAY. Semantically this
        # is a different resource from resources.ROUTER_GATEWAY.

        if db_api.is_session_active(admin_ctx.session):
            admin_ctx.GUARD_TRANSACTION = False
        self._core_plugin.delete_port(
            admin_ctx, gw_port_id, l3_port_check=False)

        # TODO(dmitriis): publish an events.AFTER_DELETE event for a new
        # resource type e.g. resources.ROUTER_EXTRA_GATEWAY. Semantically this
        # is a different resource from resources.ROUTER_GATEWAY.

    @db_api.retry_if_session_inactive()
    def add_external_gateways(self, context, router_id, body):
        gateways = body['router'].get('external_gateways',
                                      constants.ATTR_NOT_SPECIFIED)
        if gateways == constants.ATTR_NOT_SPECIFIED:
            return self._get_router(context, router_id)

        external_gateways = self._add_external_gateways(
            context, router_id, gateways, body)

        with db_api.CONTEXT_WRITER.using(context):
            router = self.update_router(
                context, router_id, {
                    'router': {
                        'external_gateways': external_gateways}})
            return {'router': router}

    @db_api.retry_if_session_inactive()
    def remove_external_gateways(self, context, router_id, body):
        gateways = body['router'].get('external_gateways',
                                      constants.ATTR_NOT_SPECIFIED)
        if gateways == constants.ATTR_NOT_SPECIFIED:
            return self._get_router(context, router_id)

        external_gateways = self._remove_external_gateways(
            context, router_id, gateways, body)
        with db_api.CONTEXT_WRITER.using(context):
            router = self.update_router(
                context,
                router_id,
                {'router':
                 {'external_gateways': external_gateways}})
            return {'router': router}

    def _remove_all_gateways(self, context, router_id):
        router_db = self._get_router(context, router_id)
        compat_gw_port_id = router_db['gw_port_id']
        gw_ports = l3_obj.RouterPort.get_gw_port_ids_by_router_id(context,
                                                                  router_id)
        for gw_port_id in gw_ports:
            if gw_port_id != compat_gw_port_id:
                self._delete_extra_gw_port(context, router_id, gw_port_id)
        if compat_gw_port_id:
            # Remove the compatibility gw port using the compatibility API
            self._update_router_gw_info(context, router_id, {}, {}, router_db)

    def _update_external_gateways(self, context, router_id, gw_info_list,
                                  payload):
        # An empty list means "remove all gateways".
        if not gw_info_list:
            self._remove_all_gateways(context, router_id)
            return {}

        # The `_validate_gw_info` method takes a DB object.
        router_db = self._get_router(context, router_id)

        # Go over extra gateways and validate the specified information.
        for gw_info in gw_info_list:
            ext_ips = gw_info.get(
                'external_fixed_ips', [])
            self._validate_gw_info(context, gw_info, ext_ips, router_db)

        # Find a match for the first gateway in the list.
        found_gw_port_ids, part_matches, nonexistent_port_info = (
            self._match_requested_gateway_ports(context, router_id,
                                                gw_info_list[:1]))
        # If there is already an existing extra gateway port matching what was
        # requested in the update for the compatibility gw port, simply update
        # the compatibility gw_port_id.
        if part_matches:
            # Replace the gw_port_id on the router object with an existing one.
            self._replace_compat_gw_port(context, router_db,
                                         list(part_matches.keys())[0])

        # The first gw info dict is special as it designates a compat gw. So
        # we simply try to make an update using the compatibility API.
        self._update_router_gw_info(context, router_id, gw_info_list[0], {})

        # Find a match for the rest of the gateway list.
        found_gw_port_ids, part_matches, nonexistent_port_info = (
            self._match_requested_gateway_ports(context, router_id,
                                                gw_info_list[1:]))
        router = l3_obj.Router.get_object(context, id=router_id)

        # For partial matches, we need to update the set of fixed IPs for
        # existing ports.
        for gw_port_id, gw_info in part_matches.items():
            # There can be partial matches without any fixed IPs specified,
            # So we check and skip those.
            fixed_ips = gw_info.get('external_fixed_ips')
            if not fixed_ips:
                continue
            self._core_plugin.update_port(
                context.elevated(),
                gw_port_id,
                {'port': {'fixed_ips': fixed_ips}})

        gw_ports = l3_obj.RouterPort.get_gw_port_ids_by_router_id(context,
                                                                  router_id)
        # Identify the set of ports to remove based on the ones that could not
        # be matched based on the supplied external gateways in the request.
        ports_to_remove = set(gw_ports).difference(
            set(found_gw_port_ids.keys())).difference(set([router.gw_port_id]))

        for gw_port_id in ports_to_remove:
            self._remove_external_gateways(
                context, router_id, [v for k, v in found_gw_port_ids.items()
                                     if k == gw_port_id], {})

        if nonexistent_port_info:
            synthetic_payload = {
                'router': {
                    'external_gateways': nonexistent_port_info}}

            self._add_external_gateways(context, router_id,
                                        nonexistent_port_info,
                                        synthetic_payload)
        return gw_info_list

    @db_api.retry_if_session_inactive()
    def update_external_gateways(self, context, router_id, body):
        gateways = body['router'].get('external_gateways',
                                      constants.ATTR_NOT_SPECIFIED)
        if gateways == constants.ATTR_NOT_SPECIFIED:
            return self._get_router(context, router_id)

        external_gateways = self._update_external_gateways(
            context, router_id, gateways, body)

        with db_api.CONTEXT_WRITER.using(context):
            router = self.update_router(
                context,
                router_id,
                {'router':
                 {'external_gateways': external_gateways}})
            return {'router': router}

    def _update_router_gw_info(self, context, router_id,
                               info, request_body, router=None):
        router_db = super()._update_router_gw_info(context, router_id, info,
                                                   request_body, router)
        # If a compatibility port got removed as a result of a router update
        # (by passing empty info for external_gateway_info) replace it with
        # one of the existing ones.
        gw_ports = l3_obj.RouterPort.get_gw_port_ids_by_router_id(context,
                                                                  router_id)
        if gw_ports and not router_db['gw_port_id']:
            new_gw_port_id = gw_ports[0]
            self._replace_compat_gw_port(context, router_db, new_gw_port_id)
        return router_db


class ExtraGatewaysMixinDbMixin(ExtraGatewaysDbOnlyMixin,
                                l3_db.L3_NAT_db_mixin):
    pass
