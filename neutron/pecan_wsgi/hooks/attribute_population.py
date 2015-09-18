# Copyright (c) 2015 Mirantis, Inc.
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

from pecan import hooks

from neutron.api.v2 import attributes
from neutron.api.v2 import base as v2base
from neutron import manager


class AttributePopulationHook(hooks.PecanHook):

    priority = 120

    def before(self, state):
        state.request.prepared_data = {}
        state.request.resources = []
        if state.request.method not in ('POST', 'PUT'):
            return
        is_create = state.request.method == 'POST'
        resource = state.request.context.get('resource')
        neutron_context = state.request.context['neutron_context']
        if not resource:
            return
        if state.request.member_action:
            # Neutron currently does not describe request bodies for member
            # actions in meh. prepare_request_body should not be called for
            # member actions, and the body should be passed as it is. The
            # plugin will do the validation (yuck).
            state.request.prepared_data = state.request.json
        else:
            state.request.prepared_data = (
                v2base.Controller.prepare_request_body(
                    neutron_context, state.request.json, is_create,
                    resource, _attributes_for_resource(resource),
                    allow_bulk=True))
            # TODO(kevinbenton): conditional allow_bulk

        state.request.resources = _extract_resources_from_state(state)
        # make the original object available:
        if not is_create and not state.request.member_action:
            obj_id = _pull_id_from_request(state.request, resource)
            attrs = _attributes_for_resource(resource)
            field_list = [name for (name, value) in attrs.items()
                          if (value.get('required_by_policy') or
                              value.get('primary_key') or
                              'default' not in value)]
            plugin = manager.NeutronManager.get_plugin_for_resource(resource)
            getter = getattr(plugin, 'get_%s' % resource)
            # TODO(kevinbenton): the parent_id logic currently in base.py
            obj = getter(neutron_context, obj_id, fields=field_list)
            state.request.original_object = obj


def _attributes_for_resource(resource):
    if resource not in attributes.PLURALS.values():
        return {}
    return attributes.RESOURCE_ATTRIBUTE_MAP.get(
        _plural(resource), {})


def _pull_id_from_request(request, resource):
    # NOTE(kevinbenton): this sucks
    # Converting /v2.0/ports/dbbdae29-82f6-49cf-b05e-3365bcc95b7a.json
    # into dbbdae29-82f6-49cf-b05e-3365bcc95b7a
    resources = _plural(resource)
    jsontrail = request.path_info.replace('/v2.0/%s/' % resources, '')
    obj_id = jsontrail.replace('.json', '')
    return obj_id


def _plural(rtype):
    for plural, single in attributes.PLURALS.items():
        if rtype == single:
            return plural


def _extract_resources_from_state(state):
    resource = state.request.context['resource']
    if not resource:
        return []
    data = state.request.prepared_data
    # single item
    if resource in data:
        state.request.bulk = False
        return [data[resource]]
    # multiple items
    if _plural(resource) in data:
        state.request.bulk = True
        return data[_plural(resource)]

    return []
