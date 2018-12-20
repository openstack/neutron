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


"""
NOTE: This module shall not be used by external projects. It will be moved
      to neutron-lib in due course, and then it can be used from there.
"""

from neutron_lib.api import attributes
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import utils as obj_utils
from neutron_lib.utils import helpers
from oslo_db.sqlalchemy import utils as sa_utils
from sqlalchemy import sql, or_, and_
from sqlalchemy.ext import associationproxy

from neutron._i18n import _


# TODO(boden): remove shims
_model_query_hooks = model_query._model_query_hooks
register_hook = model_query.register_hook
get_hooks = model_query.get_hooks


def query_with_hooks(context, model, field=None):
    if field:
        if hasattr(model, field):
            field = getattr(model, field)
        else:
            msg = _("'%s' is not supported as field") % field
            raise n_exc.InvalidInput(error_message=msg)
        query = context.session.query(field)
    else:
        query = context.session.query(model)
    # define basic filter condition for model query
    query_filter = None
    if db_utils.model_query_scope_is_project(context, model):
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
    for hook in get_hooks(model):
        query_hook = helpers.resolve_ref(hook.get('query'))
        if query_hook:
            query = query_hook(context, model, query)

        filter_hook = helpers.resolve_ref(hook.get('filter'))
        if filter_hook:
            query_filter = filter_hook(context, model, query_filter)

    # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
    # condition, raising an exception
    if query_filter is not None:
        query = query.filter(query_filter)
    return query


def get_by_id(context, model, object_id):
    query = query_with_hooks(context=context, model=model)
    return query.filter(model.id == object_id).one()


def apply_filters(query, model, filters, context=None):
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
                elif isinstance(value, obj_utils.FilterObj):
                    query = query.filter(value.filter(column))
                elif None in value:
                    # in_() operator does not support NULL element so we have
                    # to do multiple equals matches
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
                        query.session.query(rbac.object_id).filter(is_shared)
                    )
                elif (not context or
                      not db_utils.model_query_scope_is_project(
                          context, model)):
                    # we only want to join if we aren't using the subquery
                    # and if we aren't already joined because this is a
                    # scoped query
                    query = query.outerjoin(model.rbac_entries)
                query = query.filter(is_shared)
        for hook in get_hooks(model):
            result_filter = helpers.resolve_ref(
                hook.get('result_filters', None))
            if result_filter:
                query = result_filter(query, filters)
    return query


def get_collection_query(context, model, filters=None, sorts=None, limit=None,
                         marker_obj=None, page_reverse=False):
    collection = query_with_hooks(context, model)
    collection = apply_filters(collection, model, filters, context)
    if sorts:
        sort_keys = db_utils.get_and_validate_sort_keys(sorts, model)
        sort_dirs = db_utils.get_sort_dirs(sorts, page_reverse)
        # we always want deterministic results for sorted queries
        # so add unique keys to limit queries when present.
        # (http://docs.sqlalchemy.org/en/latest/orm/
        #  loading_relationships.html#subqueryload-ordering)
        # (http://docs.sqlalchemy.org/en/latest/faq/
        #  ormconfiguration.html#faq-subqueryload-limit-sort)
        for k in _unique_keys(model):
            if k not in sort_keys:
                sort_keys.append(k)
                sort_dirs.append('asc')
        collection = sa_utils.paginate_query(collection, model, limit,
                                             marker=marker_obj,
                                             sort_keys=sort_keys,
                                             sort_dirs=sort_dirs)
    return collection


def _unique_keys(model):
    # just grab first set of unique keys and use them.
    # if model has no unqiue sets, 'paginate_query' will
    # warn if sorting is unstable
    uk_sets = sa_utils.get_unique_keys(model)
    return uk_sets[0] if uk_sets else []


def get_collection(context, model, dict_func,
                   filters=None, fields=None,
                   sorts=None, limit=None, marker_obj=None,
                   page_reverse=False):
    query = get_collection_query(context, model,
                                 filters=filters, sorts=sorts,
                                 limit=limit, marker_obj=marker_obj,
                                 page_reverse=page_reverse)
    items = [
        attributes.populate_project_info(
            dict_func(c, fields) if dict_func else c)
        for c in query
    ]
    if limit and page_reverse:
        items.reverse()
    return items


def get_values(context, model, field, filters=None):
    query = query_with_hooks(context, model, field=field)
    query = apply_filters(query, model, filters, context)
    return [c[0] for c in query]


def get_collection_count(context, model, filters=None):
    return get_collection_query(context, model, filters).count()
