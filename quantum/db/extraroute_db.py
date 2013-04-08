# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
from oslo.config import cfg
import sqlalchemy as sa

from quantum.common import utils
from quantum.db import l3_db
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import extraroute
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)

extra_route_opts = [
    #TODO(nati): use quota framework when it support quota for attributes
    cfg.IntOpt('max_routes', default=30,
               help=_("Maximum number of routes")),
]

cfg.CONF.register_opts(extra_route_opts)


class RouterRoute(model_base.BASEV2, models_v2.Route):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


class ExtraRoute_db_mixin(l3_db.L3_NAT_db_mixin):
    """ Mixin class to support extra route configuration on router"""
    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            #check if route exists and have permission to access
            router_db = self._get_router(context, id)
            if 'routes' in r:
                self._update_extra_routes(context,
                                          router_db,
                                          r['routes'])
            router_updated = super(ExtraRoute_db_mixin, self).update_router(
                context, id, router)
            router_updated['routes'] = self._get_extra_routes_by_router_id(
                context, id)

        return router_updated

    def _get_subnets_by_cidr(self, context, cidr):
        query_subnets = context.session.query(models_v2.Subnet)
        return query_subnets.filter_by(cidr=cidr).all()

    def _validate_routes_nexthop(self, context, ports, routes, nexthop):
        #Note(nati): Nexthop should be connected,
        # so we need to check
        # nexthop belongs to one of cidrs of the router ports
        cidrs = []
        for port in ports:
            cidrs += [self._get_subnet(context,
                                       ip['subnet_id'])['cidr']
                      for ip in port['fixed_ips']]
        if not netaddr.all_matching_cidrs(nexthop, cidrs):
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is not connected with router'))
        #Note(nati) nexthop should not be same as fixed_ips
        for port in ports:
            for ip in port['fixed_ips']:
                if nexthop == ip['ip_address']:
                    raise extraroute.InvalidRoutes(
                        routes=routes,
                        reason=_('the nexthop is used by router'))

    def _validate_routes(self, context,
                         router_id, routes):
        if len(routes) > cfg.CONF.max_routes:
            raise extraroute.RoutesExhausted(
                router_id=router_id,
                quota=cfg.CONF.max_routes)

        filters = {'device_id': [router_id]}
        ports = self.get_ports(context, filters)
        for route in routes:
            self._validate_routes_nexthop(
                context, ports, routes, route['nexthop'])

    def _update_extra_routes(self, context, router, routes):
        self._validate_routes(context, router['id'],
                              routes)
        old_routes = self._get_extra_routes_by_router_id(
            context, router['id'])
        added, removed = utils.diff_list_of_dict(old_routes,
                                                 routes)
        LOG.debug('Added routes are %s' % added)
        for route in added:
            router_routes = RouterRoute(
                router_id=router['id'],
                destination=route['destination'],
                nexthop=route['nexthop'])
            context.session.add(router_routes)

        LOG.debug('Removed routes are %s' % removed)
        for route in removed:
            del_context = context.session.query(RouterRoute)
            del_context.filter_by(router_id=router['id'],
                                  destination=route['destination'],
                                  nexthop=route['nexthop']).delete()

    def _make_extra_route_list(self, extra_routes):
        return [{'destination': route['destination'],
                 'nexthop': route['nexthop']}
                for route in extra_routes]

    def _get_extra_routes_by_router_id(self, context, id):
        query = context.session.query(RouterRoute)
        query.filter(RouterRoute.router_id == id)
        extra_routes = query.all()
        return self._make_extra_route_list(extra_routes)

    def get_router(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            router = super(ExtraRoute_db_mixin, self).get_router(
                context, id, fields)
            router['routes'] = self._get_extra_routes_by_router_id(
                context, id)
            return router

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            routers = super(ExtraRoute_db_mixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)
            for router in routers:
                router['routes'] = self._get_extra_routes_by_router_id(
                    context, router['id'])
            return routers

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        super(ExtraRoute_db_mixin, self)._confirm_router_interface_not_in_use(
            context, router_id, subnet_id)
        subnet_db = self._get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet_db['cidr'])
        extra_routes = self._get_extra_routes_by_router_id(context, router_id)
        for route in extra_routes:
            if netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr]):
                raise extraroute.RouterInterfaceInUseByRoute(
                    router_id=router_id, subnet_id=subnet_id)
