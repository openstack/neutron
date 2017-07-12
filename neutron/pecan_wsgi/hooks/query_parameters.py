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

from pecan import hooks

from neutron.api import api_common
from neutron import manager
from neutron.pecan_wsgi.hooks import policy_enforcement
from neutron.pecan_wsgi.hooks import utils


# TODO(blogan): ideally it'd be nice to get the pagination and sorting
# helpers from the controller but since the controllers are
# instantiated at startup and not on request, it would cause race
# conditions because we need a new instantiation of a pagination
# and sorting helper per request/response flow.  As a result, we're forced to
# pass them through the request context.

def _get_pagination_helper(request, controller):
    if 'pagination_helper' in request.context:
        return request.context['pagination_helper']
    if not controller.allow_pagination:
        helper = api_common.NoPaginationHelper(request, controller.primary_key)
    elif controller.native_pagination:
        helper = api_common.PaginationNativeHelper(request,
                                                   controller.primary_key)
    else:
        helper = api_common.PaginationEmulatedHelper(request,
                                                     controller.primary_key)
    request.context['pagination_helper'] = helper
    return helper


def _get_sorting_helper(request, controller):
    if 'sorting_helper' in request.context:
        return request.context['sorting_helper']
    if not controller.allow_sorting:
        helper = api_common.NoSortingHelper(request, controller.resource_info)
    elif controller.native_sorting:
        helper = api_common.SortingNativeHelper(request,
                                                controller.resource_info)
    else:
        helper = api_common.SortingEmulatedHelper(request,
                                                  controller.resource_info)
    request.context['sorting_helper'] = helper
    return helper


def _listify(thing):
    return thing if isinstance(thing, list) else [thing]


def _set_fields(state, controller):
    params = state.request.params.mixed()
    fields = params.get('fields', [])
    # if only one fields query parameter is passed, pecan will not put
    # that parameter in a list, so we need to convert it into a list
    fields = _listify(fields)
    combined_fields, added_fields = controller.build_field_list(fields)
    state.request.context['query_params']['fields'] = combined_fields
    state.request.context['added_fields'] = added_fields
    return combined_fields, added_fields


def _set_filters(state, controller):
    params = state.request.params.mixed()
    filters = api_common.get_filters_from_dict(
        {k: _listify(v) for k, v in params.items()},
        controller.resource_info,
        skips=['fields', 'sort_key', 'sort_dir',
               'limit', 'marker', 'page_reverse'])
    return filters


class QueryParametersHook(hooks.PecanHook):

    # NOTE(blogan): needs to be run after the priority hook.  after methods
    # are run in reverse priority order.
    priority = policy_enforcement.PolicyHook.priority - 1

    def before(self, state):
        self._process_if_match_headers(state)
        state.request.context['query_params'] = {}
        if state.request.method != 'GET':
            return
        collection = state.request.context.get('collection')
        if not collection:
            return
        controller = utils.get_controller(state)
        combined_fields, added_fields = _set_fields(state, controller)
        filters = _set_filters(state, controller)
        query_params = {'fields': combined_fields, 'filters': filters}
        pagination_helper = _get_pagination_helper(state.request, controller)
        sorting_helper = _get_sorting_helper(state.request, controller)
        sorting_helper.update_args(query_params)
        sorting_helper.update_fields(query_params.get('fields', []),
                                     added_fields)
        pagination_helper.update_args(query_params)
        pagination_helper.update_fields(query_params.get('fields', []),
                                        added_fields)
        state.request.context['query_params'] = query_params

    def _process_if_match_headers(self, state):
        collection = state.request.context.get('collection')
        if not collection:
            return
        # add in if-match criterion to the context if present
        revision_number = api_common.check_request_for_revision_constraint(
            state.request)
        if revision_number is None:
            return
        state.request.context['neutron_context'].set_transaction_constraint(
            collection, state.request.context['resource_id'], revision_number)

    def after(self, state):
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        # NOTE(blogan): don't paginate extension list or non-GET requests
        if (not resource or resource == 'extension' or
                state.request.method != 'GET'):
            return
        try:
            data = state.response.json
        except ValueError:
            return
        # Do not attempt to paginate if the body is not a list of entities
        if not data or resource in data or collection not in data:
            return
        controller = manager.NeutronManager.get_controller_for_resource(
            collection)
        sorting_helper = _get_sorting_helper(state.request, controller)
        pagination_helper = _get_pagination_helper(state.request, controller)
        obj_list = sorting_helper.sort(data[collection])
        obj_list = pagination_helper.paginate(obj_list)
        resp_body = {collection: obj_list}
        pagination_links = pagination_helper.get_links(obj_list)
        if pagination_links:
            resp_body['_'.join([collection, 'links'])] = pagination_links
        state.response.json = resp_body
