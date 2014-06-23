# Copyright 2013, Big Switch Networks
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

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import l3_db
from neutron.db import model_base
from neutron.openstack.common import log as logging
from neutron.plugins.bigswitch.extensions import routerrule


LOG = logging.getLogger(__name__)


class RouterRule(model_base.BASEV2):
    id = sa.Column(sa.Integer, primary_key=True)
    source = sa.Column(sa.String(64), nullable=False)
    destination = sa.Column(sa.String(64), nullable=False)
    nexthops = orm.relationship('NextHop', cascade='all,delete')
    action = sa.Column(sa.String(10), nullable=False)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))


class NextHop(model_base.BASEV2):
    rule_id = sa.Column(sa.Integer,
                        sa.ForeignKey('routerrules.id',
                                      ondelete="CASCADE"),
                        primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


class RouterRule_db_mixin(l3_db.L3_NAT_db_mixin):
    """ Mixin class to support route rule configuration on a router"""
    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if 'router_rules' in r:
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])
            updated = super(RouterRule_db_mixin, self).update_router(
                context, id, router)
            updated['router_rules'] = self._get_router_rules_by_router_id(
                context, id)

        return updated

    def create_router(self, context, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = super(RouterRule_db_mixin, self).create_router(
                context, router)
            if 'router_rules' in r:
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])
            else:
                LOG.debug(_('No rules in router'))
            router_db['router_rules'] = self._get_router_rules_by_router_id(
                context, router_db['id'])

        return router_db

    def _update_router_rules(self, context, router, rules):
        if len(rules) > cfg.CONF.ROUTER.max_router_rules:
            raise routerrule.RulesExhausted(
                router_id=router['id'],
                quota=cfg.CONF.ROUTER.max_router_rules)
        del_context = context.session.query(RouterRule)
        del_context.filter_by(router_id=router['id']).delete()
        context.session.expunge_all()
        LOG.debug(_('Updating router rules to %s'), rules)
        for rule in rules:
            router_rule = RouterRule(
                router_id=router['id'],
                destination=rule['destination'],
                source=rule['source'],
                action=rule['action'])
            router_rule.nexthops = [NextHop(nexthop=hop)
                                    for hop in rule['nexthops']]
            context.session.add(router_rule)
        context.session.flush()

    def _make_router_rule_list(self, router_rules):
        ruleslist = []
        for rule in router_rules:
            hops = [hop['nexthop'] for hop in rule['nexthops']]
            ruleslist.append({'id': rule['id'],
                              'destination': rule['destination'],
                              'source': rule['source'],
                              'action': rule['action'],
                              'nexthops': hops})
        return ruleslist

    def _get_router_rules_by_router_id(self, context, id):
        query = context.session.query(RouterRule)
        router_rules = query.filter_by(router_id=id).all()
        return self._make_router_rule_list(router_rules)

    def get_router(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            router = super(RouterRule_db_mixin, self).get_router(
                context, id, fields)
            router['router_rules'] = self._get_router_rules_by_router_id(
                context, id)
            return router

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
            return routers

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin,
                            self).get_sync_data(context, router_ids,
                                                active=active)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
        return routers
