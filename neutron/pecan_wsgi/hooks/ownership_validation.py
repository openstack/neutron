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

from neutron_lib.plugins import directory
from pecan import hooks
import webob

from neutron._i18n import _


class OwnershipValidationHook(hooks.PecanHook):

    priority = 125

    def before(self, state):
        if state.request.method != 'POST':
            return
        for item in state.request.context.get('resources', []):
            self._validate_network_tenant_ownership(state, item)

    def _validate_network_tenant_ownership(self, state, resource_item):
        # TODO(salvatore-orlando): consider whether this check can be folded
        # in the policy engine
        neutron_context = state.request.context.get('neutron_context')
        resource = state.request.context.get('resource')
        if (neutron_context.is_admin or neutron_context.is_service_role or
                resource not in ('port', 'subnet')):
            return
        plugin = directory.get_plugin()
        network = plugin.get_network(neutron_context,
                                     resource_item['network_id'])
        # do not perform the check on shared networks
        if network.get('shared'):
            return

        network_owner = network['tenant_id']

        if network_owner != resource_item['tenant_id']:
            msg = _("Tenant %(tenant_id)s not allowed to "
                    "create %(resource)s on this network")
            raise webob.exc.HTTPForbidden(msg % {
                "tenant_id": resource_item['tenant_id'],
                "resource": resource,
            })
