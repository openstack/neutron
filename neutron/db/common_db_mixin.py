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

from neutron_lib.db import utils as db_utils
from oslo_db.sqlalchemy import utils as sa_utils
import six
from sqlalchemy import and_
from sqlalchemy.ext import associationproxy
from sqlalchemy import or_
from sqlalchemy import sql

from neutron.api.v2 import attributes
from neutron.db import _model_query
from neutron.db import _resource_extend
from neutron.db import _utils as ndb_utils


# TODO(HenryG): Remove these when available in neutron-lib
safe_creation = ndb_utils.safe_creation
model_query_scope = ndb_utils.model_query_scope_is_project
model_query = ndb_utils.model_query
resource_fields = ndb_utils.resource_fields


class CommonDbMixin(object):
    """Common methods used in core and service plugins."""

    @staticmethod
    def register_model_query_hook(model, name, query_hook, filter_hook,
                                  result_filters=None):
        _model_query.register_hook(
            model, name, query_hook, filter_hook,
            result_filters=result_filters)

    @staticmethod
    def register_dict_extend_funcs(resource, funcs):
        _resource_extend.register_funcs(resource, funcs)

    @property
    # TODO(HenryG): Remove; used only by vmware-nsx.
    def safe_reference(self):
        """Return a weakref to the instance.

        Minimize the potential for the instance persisting
        unnecessarily in memory by returning a weakref proxy that
        won't prevent deallocation.
        """
        return weakref.proxy(self)

    # TODO(HenryG): Remove this when available in neutron-lib
    def model_query_scope(self, context, model):
        return ndb_utils.model_query_scope_is_project(context, model)

    def _model_query(self, context, model):
        query = context.session.query(model)
        # define basic filter condition for model query
        query_filter = None
        if ndb_utils.model_query_scope_is_project(context, model):
            if hasattr(model, 'rbac_entries'):
                query = query.outerjoin(model.rbac_entries)
                rbac_model = model.rbac_entries.property.mapper.class_
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
        for hook in _model_query.get_hooks(model):
            query_hook = self._resolve_ref(hook.get('query'))
            if query_hook:
                query = query_hook(context, model, query)

            filter_hook = self._resolve_ref(hook.get('filter'))
            if filter_hook:
                query_filter = filter_hook(context, model, query_filter)

        # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
        # condition, raising an exception
        if query_filter is not None:
            query = query.filter(query_filter)
        return query

    # TODO(HenryG): Remove this when available in neutron-lib
    def _fields(self, resource, fields):
        return ndb_utils.resource_fields(resource, fields)

    def _get_by_id(self, context, model, id):
        query = self._model_query(context, model)
        return query.filter(model.id == id).one()

    def _apply_filters_to_query(self, query, model, filters, context=None):
        if filters:
            for key, value in filters.items():
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
                    if isinstance(column, associationproxy.AssociationProxy):
                        # association proxies don't support in_ so we have to
                        # do multiple equals matches
                        query = query.filter(
                            or_(*[column == v for v in value]))
                    else:
                        query = query.filter(column.in_(value))
                elif key == 'shared' and hasattr(model, 'rbac_entries'):
                    # translate a filter on shared into a query against the
                    # object's rbac entries
                    rbac = model.rbac_entries.property.mapper.class_
                    matches = [rbac.target_tenant == '*']
                    if context:
                        matches.append(rbac.target_tenant == context.tenant_id)
                    # any 'access_as_shared' records that match the
                    # wildcard or requesting tenant
                    is_shared = and_(rbac.action == 'access_as_shared',
                                     or_(*matches))
                    if not value[0]:
                        # NOTE(kevinbenton): we need to find objects that don't
                        # have an entry that matches the criteria above so
                        # we use a subquery to exclude them.
                        # We can't just filter the inverse of the query above
                        # because that will still give us a network shared to
                        # our tenant (or wildcard) if it's shared to another
                        # tenant.
                        # This is the column joining the table to rbac via
                        # the object_id. We can't just use model.id because
                        # subnets join on network.id so we have to inspect the
                        # relationship.
                        join_cols = model.rbac_entries.property.local_columns
                        oid_col = list(join_cols)[0]
                        is_shared = ~oid_col.in_(
                            query.session.query(rbac.object_id).
                            filter(is_shared)
                        )
                    elif (not context or
                          not self.model_query_scope(context, model)):
                        # we only want to join if we aren't using the subquery
                        # and if we aren't already joined because this is a
                        # scoped query
                        query = query.outerjoin(model.rbac_entries)
                    query = query.filter(is_shared)
            for hook in _model_query.get_hooks(model):
                result_filter = self._resolve_ref(
                    hook.get('result_filters', None))

                if result_filter:
                    query = result_filter(query, filters)
        return query

    def _resolve_ref(self, ref):
        """Finds string ref functions, handles dereference of weakref."""
        if isinstance(ref, six.string_types):
            ref = getattr(self, ref, None)
        if isinstance(ref, weakref.ref):
            ref = ref()
        return ref

    def _apply_dict_extend_functions(self, resource_type,
                                     response, db_object):
        for func in _resource_extend.get_funcs(resource_type):
            args = (response, db_object)
            if not isinstance(func, six.string_types):
                # must call unbound method - use self as 1st argument
                args = (self,) + args
            func = self._resolve_ref(func)
            if func:
                func(*args)

    def _get_collection_query(self, context, model, filters=None,
                              sorts=None, limit=None, marker_obj=None,
                              page_reverse=False):
        collection = self._model_query(context, model)
        collection = self._apply_filters_to_query(collection, model, filters,
                                                  context)
        if sorts:
            sort_keys = db_utils.get_and_validate_sort_keys(sorts, model)
            sort_dirs = db_utils.get_sort_dirs(sorts, page_reverse)
            # we always want deterministic results for sorted queries
            # so add unique keys to limit queries when present.
            # (http://docs.sqlalchemy.org/en/latest/orm/
            #  loading_relationships.html#subqueryload-ordering)
            # (http://docs.sqlalchemy.org/en/latest/faq/
            #  ormconfiguration.html#faq-subqueryload-limit-sort)
            for k in self._unique_keys(model, marker_obj):
                if k not in sort_keys:
                    sort_keys.append(k)
                    sort_dirs.append('asc')
            collection = sa_utils.paginate_query(collection, model, limit,
                                                 marker=marker_obj,
                                                 sort_keys=sort_keys,
                                                 sort_dirs=sort_dirs)
        return collection

    def _unique_keys(self, model, marker_obj):
        # just grab first set of unique keys and use them.
        # if model has no unqiue sets, 'paginate_query' will
        # warn if sorting is unstable
        uk_sets = sa_utils.get_unique_keys(model)
        return uk_sets[0] if uk_sets else []

    def _get_collection(self, context, model, dict_func, filters=None,
                        fields=None, sorts=None, limit=None, marker_obj=None,
                        page_reverse=False):
        query = self._get_collection_query(context, model, filters=filters,
                                           sorts=sorts,
                                           limit=limit,
                                           marker_obj=marker_obj,
                                           page_reverse=page_reverse)
        items = [
            attributes.populate_project_info(
                dict_func(c, fields) if dict_func else c)
            for c in query
        ]
        if limit and page_reverse:
            items.reverse()
        return items

    def _get_collection_count(self, context, model, filters=None):
        return self._get_collection_query(context, model, filters).count()

    def _get_marker_obj(self, context, resource, limit, marker):
        if limit and marker:
            return getattr(self, '_get_%s' % resource)(context, marker)
        return None

    # TODO(HenryG): Remove this when available in neutron-lib
    def _filter_non_model_columns(self, data, model):
        return ndb_utils.filter_non_model_columns(data, model)
