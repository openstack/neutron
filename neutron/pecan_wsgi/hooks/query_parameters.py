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


def _listify(thing):
    return thing if isinstance(thing, list) else [thing]


def _set_fields(state, controller):
    params = state.request.params.mixed()
    fields = params.get('fields', [])
    # if only one fields query parameter is passed, pecan will not put
    # that parameter in a list, so we need to convert it into a list
    fields = _listify(fields)
    combined_fields = controller.build_field_list(fields)
    return combined_fields


def _set_filters(state, controller):
    params = state.request.params.mixed()
    filters = api_common.get_filters_from_dict(
        {k: _listify(v) for k, v in params.items()},
        controller.resource_info,
        skips=['fields', 'sort_key', 'sort_dir',
               'limit', 'marker', 'page_reverse'])
    return filters


class QueryParametersHook(hooks.PecanHook):

    priority = 145

    def before(self, state):
        state.request.context['query_params'] = {}
        if state.request.method != 'GET':
            return
        collection = state.request.context.get('collection')
        if not collection:
            return
        controller = manager.NeutronManager.get_controller_for_resource(
            collection)
        combined_fields = _set_fields(state, controller)
        filters = _set_filters(state, controller)
        query_params = {'fields': combined_fields, 'filters': filters}
        state.request.context['query_params'] = query_params
