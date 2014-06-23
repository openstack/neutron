# Copyright 2013 NEC Corporation.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class RouterProvider(models_v2.model_base.BASEV2):
    """Represents a binding of router_id to provider."""
    provider = sa.Column(sa.String(255))
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(l3_db.Router, uselist=False,
                              backref=orm.backref('provider', uselist=False,
                                                  lazy='joined',
                                                  cascade='delete'))


def _get_router_providers_query(query, provider=None, router_ids=None):
    if provider:
        query = query.filter_by(provider=provider)
    if router_ids:
        column = RouterProvider.router_id
        query = query.filter(column.in_(router_ids))
    return query


def get_router_providers(session, provider=None, router_ids=None):
    """Retrieve a list of a pair of router ID and its provider."""
    query = session.query(RouterProvider)
    query = _get_router_providers_query(query, provider, router_ids)
    return [{'provider': router.provider, 'router_id': router.router_id}
            for router in query]


def get_routers_by_provider(session, provider, router_ids=None):
    """Retrieve a list of router IDs with the given provider."""
    query = session.query(RouterProvider.router_id)
    query = _get_router_providers_query(query, provider, router_ids)
    return [router[0] for router in query]


def get_router_count_by_provider(session, provider, tenant_id=None):
    """Return the number of routers with the given provider."""
    query = session.query(RouterProvider).filter_by(provider=provider)
    if tenant_id:
        query = (query.join('router').
                 filter(l3_db.Router.tenant_id == tenant_id))
    return query.count()


def get_provider_by_router(session, router_id):
    """Retrieve a provider of the given router."""
    try:
        binding = (session.query(RouterProvider).
                   filter_by(router_id=router_id).
                   one())
    except sa_exc.NoResultFound:
        return None
    return binding.provider


def add_router_provider_binding(session, provider, router_id):
    """Add a router provider association."""
    LOG.debug(_("Add provider binding "
                "(router=%(router_id)s, provider=%(provider)s)"),
              {'router_id': router_id, 'provider': provider})
    binding = RouterProvider(provider=provider, router_id=router_id)
    session.add(binding)
    return binding
