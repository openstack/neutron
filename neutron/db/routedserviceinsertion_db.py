# Copyright 2013 VMware, Inc.  All rights reserved.
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
from sqlalchemy import event

from neutron.common import exceptions as qexception
from neutron.db import model_base
from neutron.extensions import routedserviceinsertion as rsi


class ServiceRouterBinding(model_base.BASEV2):
    resource_id = sa.Column(sa.String(36),
                            primary_key=True)
    resource_type = sa.Column(sa.String(36),
                              primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id'),
                          nullable=False)


class AttributeException(qexception.NeutronException):
    message = _("Resource type '%(resource_type)s' is longer "
                "than %(maxlen)d characters")


@event.listens_for(ServiceRouterBinding.resource_type, 'set', retval=True)
def validate_resource_type(target, value, oldvalue, initiator):
    """Make sure the resource type fit the resource_type column."""
    maxlen = ServiceRouterBinding.resource_type.property.columns[0].type.length
    if len(value) > maxlen:
        raise AttributeException(resource_type=value, maxlen=maxlen)
    return value


class RoutedServiceInsertionDbMixin(object):
    """Mixin class to add router service insertion."""

    def _process_create_resource_router_id(self, context, resource, model):
        with context.session.begin(subtransactions=True):
            db = ServiceRouterBinding(
                resource_id=resource['id'],
                resource_type=model.__tablename__,
                router_id=resource[rsi.ROUTER_ID])
            context.session.add(db)
        return self._make_resource_router_id_dict(db, model)

    def _extend_resource_router_id_dict(self, context, resource, model):
        binding = self._get_resource_router_id_binding(
            context, resource['resource_id'], model)
        resource[rsi.ROUTER_ID] = binding['router_id']

    def _get_resource_router_id_binding(self, context, model,
                                        resource_id=None,
                                        router_id=None):
        query = self._model_query(context, ServiceRouterBinding)
        query = query.filter(
            ServiceRouterBinding.resource_type == model.__tablename__)
        if resource_id:
            query = query.filter(
                ServiceRouterBinding.resource_id == resource_id)
        if router_id:
            query = query.filter(
                ServiceRouterBinding.router_id == router_id)
        return query.first()

    def _get_resource_router_id_bindings(self, context, model,
                                         resource_ids=None,
                                         router_ids=None):
        query = self._model_query(context, ServiceRouterBinding)
        query = query.filter(
            ServiceRouterBinding.resource_type == model.__tablename__)
        if resource_ids:
            query = query.filter(
                ServiceRouterBinding.resource_id.in_(resource_ids))
        if router_ids:
            query = query.filter(
                ServiceRouterBinding.router_id.in_(router_ids))
        return query.all()

    def _make_resource_router_id_dict(self, resource_router_binding, model,
                                      fields=None):
        resource = {'resource_id': resource_router_binding['resource_id'],
                    'resource_type': model.__tablename__,
                    rsi.ROUTER_ID: resource_router_binding[rsi.ROUTER_ID]}
        return self._fields(resource, fields)

    def _delete_resource_router_id_binding(self, context, resource_id, model):
        with context.session.begin(subtransactions=True):
            binding = self._get_resource_router_id_binding(
                context, model, resource_id=resource_id)
            if binding:
                context.session.delete(binding)
