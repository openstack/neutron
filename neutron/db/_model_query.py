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
from neutron_lib.db import utils as db_utils
from oslo_db.sqlalchemy import utils as sa_utils
from sqlalchemy import sql, or_, and_
from sqlalchemy.ext import associationproxy

from neutron.common import utils
from neutron.db import _utils as ndb_utils
from neutron.objects import utils as obj_utils

# Classes implementing extensions will register hooks into this dictionary
# for "augmenting" the "core way" of building a query for retrieving objects
# from a model class. Hooks are registered by invoking register_hook().
_model_query_hooks = {
    # model1 : {
    #              hook1: {
    #                         'query': query_hook,
    #                         'filter': filter_hook,
    #                         'result_filters': result_filters
    #              },
    #              hook2: {
    #                         'query': query_hook,
    #                         'filter': filter_hook,
    #                         'result_filters': result_filters
    #              },
    #              ...
    #          },
    # model2 : {
    #              hook1: {
    #                         'query': query_hook,
    #                         'filter': filter_hook,
    #                         'result_filters': result_filters
    #              },
    #              hook2: {
    #                         'query': query_hook,
    #                         'filter': filter_hook,
    #                         'result_filters': result_filters
    #              },
    #              ...
    #          },
    # ...
}


def register_hook(model, name, query_hook, filter_hook,
                  result_filters=None):
    """Register a hook to be invoked when a query is executed.

    :param model: The DB Model that the hook applies to.
    :type model: sqlalchemy orm model

    :param name: A name for the hook.
    :type name: str

    :param query_hook: The method to be called to augment the query.
    :type query_hook: callable or None

    :param filter_hook: A method to be called to augment the query filter.
    :type filter_hook: callable or None

    :param result_filters: A Method to be called to filter the query result.
    :type result_filters: callable or None

    Adds the hook components to the _model_query_hooks dict. Models are the
    keys of this dict, whereas the value is another dict mapping hook names
    to callables performing the hook.

    Each hook has three components:
        "query", used to build the query expression
        "filter", used to build the filter expression
        "result_filters", used for final filtering on the query result

    Query hooks take as input the query being built and return a
    transformed query expression.
        def mymodel_query_hook(context, original_model, query):
            augmented_query = ...
            return augmented_query

    Filter hooks take as input the filter expression being built and return
    a transformed filter expression
        def mymodel_filter_hook(context, original_model, filters):
            refined_filters = ...
            return refined_filters

    Result filter hooks take as input the query expression and the filter
    expression, and return a final transformed query expression.
        def mymodel_result_filter_hook(query, filters):
            final_filters = ...
            return query.filter(final_filters)

    """
    if callable(query_hook):
        query_hook = utils.make_weak_ref(query_hook)
    if callable(filter_hook):
        filter_hook = utils.make_weak_ref(filter_hook)
    if callable(result_filters):
        result_filters = utils.make_weak_ref(result_filters)
    _model_query_hooks.setdefault(model, {})[name] = {
        'query': query_hook,
        'filter': filter_hook,
        'result_filters': result_filters
    }


def get_hooks(model):
    """Retrieve the model query hooks for a model.

    :param model: The DB Model to look up for query hooks.
    :type model: sqlalchemy orm model

    :return: list of hooks
    :rtype: list of dict of callable

    """
    return _model_query_hooks.get(model, {}).values()


def query_with_hooks(context, model):
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
    for hook in get_hooks(model):
        query_hook = utils.resolve_ref(hook.get('query'))
        if query_hook:
            query = query_hook(context, model, query)

        filter_hook = utils.resolve_ref(hook.get('filter'))
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
                elif isinstance(value, obj_utils.StringMatchingFilterObj):
                    if value.is_contains:
                        query = query.filter(
                            column.contains(value.contains))
                    elif value.is_starts:
                        query = query.filter(
                            column.startswith(value.starts))
                    elif value.is_ends:
                        query = query.filter(
                            column.endswith(value.ends))
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
                      not ndb_utils.model_query_scope_is_project(context,
                                                                 model)):
                    # we only want to join if we aren't using the subquery
                    # and if we aren't already joined because this is a
                    # scoped query
                    query = query.outerjoin(model.rbac_entries)
                query = query.filter(is_shared)
        for hook in get_hooks(model):
            result_filter = utils.resolve_ref(hook.get('result_filters', None))
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


def get_collection_count(context, model, filters=None):
    return get_collection_query(context, model, filters).count()
