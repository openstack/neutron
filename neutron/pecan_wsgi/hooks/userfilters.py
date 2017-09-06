# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from pecan import hooks


class UserFilterHook(hooks.PecanHook):

    # we do this at the very end to ensure user-defined filters
    # don't impact things like pagination and notification hooks
    priority = 90

    def after(self, state):
        user_fields = state.request.params.getall('fields')
        if not user_fields:
            return
        try:
            data = state.response.json
        except ValueError:
            return
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        if collection not in data and resource not in data:
            return
        is_single = resource in data
        key = resource if resource in data else collection
        if is_single:
            data[key] = self._filter_item(
                state.response.json[key], user_fields)
        else:
            data[key] = [
                self._filter_item(i, user_fields)
                for i in state.response.json[key]
            ]
        state.response.json = data

    def _filter_item(self, item, fields):
        return {
            field: value
            for field, value in item.items()
            if field in fields
        }
