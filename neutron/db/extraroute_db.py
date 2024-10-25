# Copyright 2013, Nachi Ueno, NTT MCL, Inc.
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

import copy

import netaddr
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.exceptions import extraroute as xroute_exc
from neutron_lib.utils import helpers
from neutron_lib.utils import net as net_utils
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.conf.db import extraroute_db
from neutron.db import l3_db
from neutron.objects import router as l3_obj


LOG = logging.getLogger(__name__)

extraroute_db.register_db_extraroute_opts()


@resource_extend.has_resource_extenders
class ExtraRoute_dbonly_mixin(l3_db.L3_NAT_dbonly_mixin):
    """Mixin class to support extra route configuration on router."""

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict_extraroute(router_res, router_db):
        router_res['routes'] = (ExtraRoute_dbonly_mixin.
                                _make_extra_route_list(
                                    router_db['route_list']
                                ))

    def update_router(self, context, id, router):
        r = router['router']
        if 'routes' in r:
            with db_api.CONTEXT_WRITER.using(context):
                # check if route exists and have permission to access
                router_db = self._get_router(context, id)
                old_router = self._make_router_dict(router_db)
                routes_added, routes_removed = self._update_extra_routes(
                    context, router_db, r['routes'])
                router_data = copy.deepcopy(r)
                router_data['routes_added'] = routes_added
                router_data['routes_removed'] = routes_removed
                registry.publish(resources.ROUTER, events.PRECOMMIT_UPDATE,
                                 self, payload=events.DBEventPayload(
                                     context, request_body=router_data,
                                     states=(old_router,), resource_id=id,
                                     desired_state=router_db))
        return super().update_router(
            context, id, router)

    def _validate_routes_nexthop(self, cidrs, ips, routes, nexthop):
        # Note(nati): Nexthop should be connected,
        # so we need to check
        # nexthop belongs to one of cidrs of the router ports
        if not netaddr.all_matching_cidrs(nexthop, cidrs):
            raise xroute_exc.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is not connected with router'))
        # Note(nati) nexthop should not be same as fixed_ips
        if nexthop in ips:
            raise xroute_exc.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is used by router'))

    def _validate_routes(self, context, router_id, routes, cidrs=None,
                         ip_addresses=None):
        """Validate a router routes with its interface subnets CIDRs and IPs

        If any route cannot reach any subnet CIDR from any interface or the
        route nethop match any interface IP address, this route is invalid.
        :param context: Neutron request context
        :param router_id: router ID
        :param routes: router routes (list of dictionaries)
        :param cidrs: (optional) list of CIDRs (strings)
        :param ip_addresses: (optional) list of IP addresses (strings)
        """
        if len(routes) > cfg.CONF.max_routes:
            raise xroute_exc.RoutesExhausted(
                router_id=router_id,
                quota=cfg.CONF.max_routes)

        context = context.elevated()
        filters = {'device_id': [router_id]}

        cidrs = cidrs or []
        ip_addresses = ip_addresses or []
        if not (cidrs or ip_addresses):
            ports = self._core_plugin.get_ports(context, filters)
            for port in ports:
                for ip in port['fixed_ips']:
                    cidrs.append(self._core_plugin.get_subnet(
                        context, ip['subnet_id'])['cidr'])
                    ip_addresses.append(ip['ip_address'])

        for route in routes:
            self._validate_routes_nexthop(
                cidrs, ip_addresses, routes, route['nexthop'])

    def _update_extra_routes(self, context, router, routes):
        self._validate_routes(context, router['id'], routes)
        old_routes = self._get_extra_routes_by_router_id(context, router['id'])
        added, removed = helpers.diff_list_of_dict(old_routes, routes)
        LOG.debug('Added routes are %s', added)
        for route in added:
            l3_obj.RouterRoute(
                context,
                router_id=router['id'],
                destination=net_utils.AuthenticIPNetwork(route['destination']),
                nexthop=netaddr.IPAddress(route['nexthop'])).create()

        LOG.debug('Removed routes are %s', removed)
        for route in removed:
            l3_obj.RouterRoute.delete_objects(
                context,
                router_id=router['id'],
                destination=route['destination'],
                nexthop=route['nexthop'])
        return added, removed

    @staticmethod
    def _make_extra_route_list(extra_routes):
        # NOTE(yamamoto): the extra_routes argument is either object or db row
        return [{'destination': str(route['destination']),
                 'nexthop': str(route['nexthop'])}
                for route in extra_routes]

    def _get_extra_routes_by_router_id(self, context, id):
        router_objs = l3_obj.RouterRoute.get_objects(context, router_id=id)
        return self._make_extra_route_list(router_objs)

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet):
        super()._confirm_router_interface_not_in_use(
                  context, router_id, subnet)
        subnet_cidr = netaddr.IPNetwork(subnet['cidr'])
        extra_routes = self._get_extra_routes_by_router_id(context, router_id)
        for route in extra_routes:
            if netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr]):
                raise xroute_exc.RouterInterfaceInUseByRoute(
                    router_id=router_id, subnet_id=subnet['id'])

    @staticmethod
    def _add_extra_routes(old, add):
        """Add two lists of extra routes.

        Exact duplicates (both destination and nexthop) in old and add are
        merged into one item.
        Same destinations with different nexthops are accepted and all of
        them are returned.
        Overlapping destinations are accepted and all of them are returned.
        """
        routes_dict = {}  # its values are sets of nexthops
        for r in old + add:
            dst = r['destination']
            nexthop = r['nexthop']
            if dst not in routes_dict:
                routes_dict[dst] = set()
            routes_dict[dst].add(nexthop)
        routes_list = []
        for dst, nexthops in routes_dict.items():
            for nexthop in nexthops:
                routes_list.append({'destination': dst, 'nexthop': nexthop})
        return routes_list

    @staticmethod
    def _remove_extra_routes(old, remove):
        """Remove the 2nd list of extra routes from the first.

        Since we care about the end state if an extra route to be removed
        is already missing from old, that's not an error, but accepted.
        """
        routes_dict = {}  # its values are sets of nexthops
        for r in old:
            dst = r['destination']
            nexthop = r['nexthop']
            if dst not in routes_dict:
                routes_dict[dst] = set()
            routes_dict[dst].add(nexthop)
        for r in remove:
            dst = r['destination']
            nexthop = r['nexthop']
            if dst in routes_dict:
                routes_dict[dst].discard(nexthop)
        routes_list = []
        for dst, nexthops in routes_dict.items():
            for nexthop in nexthops:
                routes_list.append({'destination': dst, 'nexthop': nexthop})
        return routes_list

    @db_api.retry_if_session_inactive()
    def add_extraroutes(self, context, router_id, body=None):
        # NOTE(bence romsics): The input validation is delayed until
        # update_router() validates the whole set of routes. Until then
        # do not trust 'routes'.
        routes = body['router']['routes']
        with db_api.CONTEXT_WRITER.using(context):
            old_routes = self._get_extra_routes_by_router_id(
                context, router_id)
            router = self.update_router(
                context,
                router_id,
                {'router':
                 {'routes':
                  self._add_extra_routes(old_routes, routes)}})
            return {'router': router}

    @db_api.retry_if_session_inactive()
    def remove_extraroutes(self, context, router_id, body=None):
        # NOTE(bence romsics): The input validation is delayed until
        # update_router() validates the whole set of routes. Until then
        # do not trust 'routes'.
        routes = body['router']['routes']
        with db_api.CONTEXT_WRITER.using(context):
            old_routes = self._get_extra_routes_by_router_id(
                context, router_id)
            router = self.update_router(
                context,
                router_id,
                {'router':
                 {'routes':
                  self._remove_extra_routes(old_routes, routes)}})
            return {'router': router}


class ExtraRoute_db_mixin(ExtraRoute_dbonly_mixin, l3_db.L3_NAT_db_mixin):
    """Mixin class to support extra route configuration on router with rpc."""
    pass
