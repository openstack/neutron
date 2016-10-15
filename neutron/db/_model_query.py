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

from neutron.common import utils

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
