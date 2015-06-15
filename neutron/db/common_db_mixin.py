# Copyright (c) 2014 OpenStack Foundation.
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

import weakref

import six
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy import sql

from neutron.common import exceptions as n_exc
from neutron.db import sqlalchemyutils


def model_query_scope(context, model):
    # Unless a context has 'admin' or 'advanced-service' rights the
    # query will be scoped to a single tenant_id
    return ((not context.is_admin and hasattr(model, 'tenant_id')) and
            (not context.is_advsvc and hasattr(model, 'tenant_id')))


def model_query(context, model):
    query = context.session.query(model)
    # define basic filter condition for model query
    query_filter = None
    if model_query_scope(context, model):
        query_filter = (model.tenant_id == context.tenant_id)

    if query_filter is not None:
        query = query.filter(query_filter)
    return query


class CommonDbMixin(object):
    """Common methods used in core and service plugins."""
    # Plugins, mixin classes implementing extension will register
    # hooks into the dict below for "augmenting" the "core way" of
    # building a query for retrieving objects from a model class.
    # To this aim, the register_model_query_hook and unregister_query_hook
    # from this class should be invoked
    _model_query_hooks = {}

    # This dictionary will store methods for extending attributes of
    # api resources. Mixins can use this dict for adding their own methods
    # TODO(salvatore-orlando): Avoid using class-level variables
    _dict_extend_functions = {}

    @classmethod
    def register_model_query_hook(cls, model, name, query_hook, filter_hook,
                                  result_filters=None):
        """Register a hook to be invoked when a query is executed.

        Add the hooks to the _model_query_hooks dict. Models are the keys
        of this dict, whereas the value is another dict mapping hook names to
        callables performing the hook.
        Each hook has a "query" component, used to build the query expression
        and a "filter" component, which is used to build the filter expression.

        Query hooks take as input the query being built and return a
        transformed query expression.

        Filter hooks take as input the filter expression being built and return
        a transformed filter expression
        """
        cls._model_query_hooks.setdefault(model, {})[name] = {
            'query': query_hook, 'filter': filter_hook,
            'result_filters': result_filters}

    @classmethod
    def register_dict_extend_funcs(cls, resource, funcs):
        cls._dict_extend_functions.setdefault(resource, []).extend(funcs)

    @property
    def safe_reference(self):
        """Return a weakref to the instance.

        Minimize the potential for the instance persisting
        unnecessarily in memory by returning a weakref proxy that
        won't prevent deallocation.
        """
        return weakref.proxy(self)

    def model_query_scope(self, context, model):
        return model_query_scope(context, model)

    def _model_query(self, context, model):
        query = context.session.query(model)
        # define basic filter condition for model query
        query_filter = None
        if self.model_query_scope(context, model):
            if hasattr(model, 'rbac_entries'):
                rbac_model, join_params = self._get_rbac_query_params(model)
                query = query.outerjoin(*join_params)
                query_filter = (
                    (model.tenant_id == context.tenant_id) |
                    ((rbac_model.action == 'access_as_shared') &
                     ((rbac_model.target_tenant == context.tenant_id) |
                      (rbac_model.target_tenant == '*'))))
            elif hasattr(model, 'shared'):
                query_filter = ((model.tenant_id == context.tenant_id) |
                                (model.shared == sql.true()))
            else:
                query_filter = (model.tenant_id == context.tenant_id)
        # Execute query hooks registered from mixins and plugins
        for _name, hooks in six.iteritems(self._model_query_hooks.get(model,
                                                                      {})):
            query_hook = hooks.get('query')
            if isinstance(query_hook, six.string_types):
                query_hook = getattr(self, query_hook, None)
            if query_hook:
                query = query_hook(context, model, query)

            filter_hook = hooks.get('filter')
            if isinstance(filter_hook, six.string_types):
                filter_hook = getattr(self, filter_hook, None)
            if filter_hook:
                query_filter = filter_hook(context, model, query_filter)

        # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
        # condition, raising an exception
        if query_filter is not None:
            query = query.filter(query_filter)
        return query

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

    def _get_tenant_id_for_create(self, context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = _('Cannot create resource for another tenant')
            raise n_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    def _get_by_id(self, context, model, id):
        query = self._model_query(context, model)
        return query.filter(model.id == id).one()

    @staticmethod
    def _get_rbac_query_params(model):
        """Return the class and join params for the rbac relationship."""
        try:
            cls = model.rbac_entries.property.mapper.class_
            return (cls, (cls, ))
        except AttributeError:
            # an association proxy is being used (e.g. subnets
            # depends on network's rbac entries)
            rbac_model = (model.rbac_entries.target_class.
                          rbac_entries.property.mapper.class_)
            return (rbac_model, model.rbac_entries.attr)

    def _apply_filters_to_query(self, query, model, filters, context=None):
        if filters:
            for key, value in six.iteritems(filters):
                column = getattr(model, key, None)
                # NOTE(kevinbenton): if column is a hybrid property that
                # references another expression, attempting to convert to
                # a boolean will fail so we must compare to None.
                # See "An Important Expression Language Gotcha" in:
                # docs.sqlalchemy.org/en/rel_0_9/changelog/migration_06.html
                if column is not None:
                    if not value:
                        query = query.filter(sql.false())
                        return query
                    query = query.filter(column.in_(value))
                elif key == 'shared' and hasattr(model, 'rbac_entries'):
                    # translate a filter on shared into a query against the
                    # object's rbac entries
                    rbac, join_params = self._get_rbac_query_params(model)
                    query = query.outerjoin(*join_params, aliased=True)
                    matches = [rbac.target_tenant == '*']
                    if context:
                        matches.append(rbac.target_tenant == context.tenant_id)
                    is_shared = and_(
                        ~rbac.object_id.is_(None),
                        rbac.action == 'access_as_shared',
                        or_(*matches)
                    )
                    query = query.filter(is_shared if value[0] else ~is_shared)
            for _nam, hooks in six.iteritems(self._model_query_hooks.get(model,
                                                                         {})):
                result_filter = hooks.get('result_filters', None)
                if isinstance(result_filter, six.string_types):
                    result_filter = getattr(self, result_filter, None)

                if result_filter:
                    query = result_filter(query, filters)
        return query

    def _apply_dict_extend_functions(self, resource_type,
                                     response, db_object):
        for func in self._dict_extend_functions.get(
            resource_type, []):
            args = (response, db_object)
            if isinstance(func, six.string_types):
                func = getattr(self, func, None)
            else:
                # must call unbound method - use self as 1st argument
                args = (self,) + args
            if func:
                func(*args)

    def _get_collection_query(self, context, model, filters=None,
                              sorts=None, limit=None, marker_obj=None,
                              page_reverse=False):
        collection = self._model_query(context, model)
        collection = self._apply_filters_to_query(collection, model, filters,
                                                  context)
        if limit and page_reverse and sorts:
            sorts = [(s[0], not s[1]) for s in sorts]
        collection = sqlalchemyutils.paginate_query(collection, model, limit,
                                                    sorts,
                                                    marker_obj=marker_obj)
        return collection

    def _get_collection(self, context, model, dict_func, filters=None,
                        fields=None, sorts=None, limit=None, marker_obj=None,
                        page_reverse=False):
        query = self._get_collection_query(context, model, filters=filters,
                                           sorts=sorts,
                                           limit=limit,
                                           marker_obj=marker_obj,
                                           page_reverse=page_reverse)
        items = [dict_func(c, fields) for c in query]
        if limit and page_reverse:
            items.reverse()
        return items

    def _get_collection_count(self, context, model, filters=None):
        return self._get_collection_query(context, model, filters).count()

    def _get_marker_obj(self, context, resource, limit, marker):
        if limit and marker:
            return getattr(self, '_get_%s' % resource)(context, marker)
        return None

    def _filter_non_model_columns(self, data, model):
        """Remove all the attributes from data which are not columns of
        the model passed as second parameter.
        """
        columns = [c.name for c in model.__table__.columns]
        return dict((k, v) for (k, v) in
                    six.iteritems(data) if k in columns)
