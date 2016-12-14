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

import netaddr
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.common import _deprecate
from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.objects import router as l3_obj

_deprecate._moved_global('RouterRoute', new_module=l3_models)

LOG = logging.getLogger(__name__)

extra_route_opts = [
    #TODO(nati): use quota framework when it support quota for attributes
    cfg.IntOpt('max_routes', default=30,
               help=_("Maximum number of routes per router")),
]

cfg.CONF.register_opts(extra_route_opts)


class ExtraRoute_dbonly_mixin(l3_db.L3_NAT_dbonly_mixin):
    """Mixin class to support extra route configuration on router."""

    def _extend_router_dict_extraroute(self, router_res, router_db):
        router_res['routes'] = (ExtraRoute_dbonly_mixin.
                                _make_extra_route_list(
                                    router_db['route_list']
                                ))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_extraroute'])

    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            #check if route exists and have permission to access
            router_db = self._get_router(context, id)
            if 'routes' in r:
                self._update_extra_routes(context, router_db, r['routes'])
            routes = self._get_extra_routes_by_router_id(context, id)
        router_updated = super(ExtraRoute_dbonly_mixin, self).update_router(
            context, id, router)
        router_updated['routes'] = routes

        return router_updated

    def _get_subnets_by_cidr(self, context, cidr):
        query_subnets = context.session.query(models_v2.Subnet)
        return query_subnets.filter_by(cidr=cidr).all()

    def _validate_routes_nexthop(self, cidrs, ips, routes, nexthop):
        #Note(nati): Nexthop should be connected,
        # so we need to check
        # nexthop belongs to one of cidrs of the router ports
        if not netaddr.all_matching_cidrs(nexthop, cidrs):
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is not connected with router'))
        #Note(nati) nexthop should not be same as fixed_ips
        if nexthop in ips:
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is used by router'))

    def _validate_routes(self, context,
                         router_id, routes):
        if len(routes) > cfg.CONF.max_routes:
            raise extraroute.RoutesExhausted(
                router_id=router_id,
                quota=cfg.CONF.max_routes)

        context = context.elevated()
        filters = {'device_id': [router_id]}
        ports = self._core_plugin.get_ports(context, filters)
        cidrs = []
        ips = []
        for port in ports:
            for ip in port['fixed_ips']:
                cidrs.append(self._core_plugin.get_subnet(
                    context, ip['subnet_id'])['cidr'])
                ips.append(ip['ip_address'])
        for route in routes:
            self._validate_routes_nexthop(
                cidrs, ips, routes, route['nexthop'])

    def _update_extra_routes(self, context, router, routes):
        self._validate_routes(context, router['id'],
                              routes)
        old_routes, routes_dict = self._get_extra_routes_dict_by_router_id(
            context, router['id'])
        added, removed = helpers.diff_list_of_dict(old_routes,
                                                   routes)
        LOG.debug('Added routes are %s', added)
        for route in added:
            l3_obj.RouterRoute(
                context,
                router_id=router['id'],
                destination=utils.AuthenticIPNetwork(route['destination']),
                nexthop=netaddr.IPAddress(route['nexthop'])).create()

        LOG.debug('Removed routes are %s', removed)
        for route in removed:
            l3_obj.RouterRoute.get_object(
                context,
                router_id=router['id'],
                destination=route['destination'],
                nexthop=route['nexthop']).delete()

    @staticmethod
    def _make_extra_route_list(extra_routes):
        # NOTE(yamamoto): the extra_routes argument is either object or db row
        return [{'destination': str(route['destination']),
                 'nexthop': str(route['nexthop'])}
                for route in extra_routes]

    def _get_extra_routes_by_router_id(self, context, id):
        router_objs = l3_obj.RouterRoute.get_objects(context, router_id=id)
        return self._make_extra_route_list(router_objs)

    def _get_extra_routes_dict_by_router_id(self, context, id):
        router_objs = l3_obj.RouterRoute.get_objects(context, router_id=id)
        routes = []
        routes_dict = {}
        for route in router_objs:
            routes.append({'destination': route.destination,
                           'nexthop': route.nexthop})
            routes_dict[(route.destination, route.nexthop)] = route
        return routes, routes_dict

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        super(ExtraRoute_dbonly_mixin,
            self)._confirm_router_interface_not_in_use(
            context, router_id, subnet_id)
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet['cidr'])
        extra_routes = self._get_extra_routes_by_router_id(context, router_id)
        for route in extra_routes:
            if netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr]):
                raise extraroute.RouterInterfaceInUseByRoute(
                    router_id=router_id, subnet_id=subnet_id)


class ExtraRoute_db_mixin(ExtraRoute_dbonly_mixin, l3_db.L3_NAT_db_mixin):
    """Mixin class to support extra route configuration on router with rpc."""
    pass


_deprecate._MovedGlobals()
