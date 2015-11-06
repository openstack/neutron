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

from neutron.api.v2 import attributes as v2_attributes
from neutron.api.v2 import base as v2_base


class BodyValidationHook(hooks.PecanHook):

    priority = 120

    def before(self, state):
        if state.request.method not in ('POST', 'PUT'):
            return
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        neutron_context = state.request.context['neutron_context']
        is_create = state.request.method == 'POST'
        if not resource:
            return
        # Prepare data to be passed to the plugin from request body
        data = v2_base.Controller.prepare_request_body(
            neutron_context,
            state.request.json,
            is_create,
            resource,
            v2_attributes.get_collection_info(collection),
            allow_bulk=is_create)
        if collection in data:
            state.request.context['resources'] = [item[resource] for item in
                                                  data[collection]]
        else:
            state.request.context['resources'] = [data[resource]]
