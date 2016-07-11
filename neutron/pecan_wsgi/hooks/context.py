# Copyright 2012 New Dream Network, LLC (DreamHost)
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

from oslo_middleware import request_id
from pecan import hooks

from neutron import context


class ContextHook(hooks.PecanHook):
    """Configures a request context and attaches it to the request.
    The following HTTP request headers are used:
    X-User-Id or X-User:
        Used for context.user_id.
    X-Project-Id:
        Used for context.tenant_id.
    X-Project-Name:
        Used for context.tenant_name.
    X-Auth-Token:
        Used for context.auth_token.
    X-Roles:
        Used for setting context.is_admin flag to either True or False.
        The flag is set to True, if X-Roles contains either an administrator
        or admin substring. Otherwise it is set to False.
    """

    priority = 95

    def before(self, state):
        user_name = state.request.headers.get('X-User-Name', '')
        tenant_name = state.request.headers.get('X-Project-Name')
        req_id = state.request.headers.get(request_id.ENV_REQUEST_ID)
        # TODO(kevinbenton): is_admin logic
        # Create a context with the authentication data
        ctx = context.Context.from_environ(state.request.environ,
                                           user_name=user_name,
                                           tenant_name=tenant_name,
                                           request_id=req_id)

        # Inject the context...
        state.request.context['neutron_context'] = ctx
