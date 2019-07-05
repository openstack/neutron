# (c) Copyright 2019 SUSE LLC
#
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

from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api.definitions import subnetpool_prefix_ops \
    as subnetpool_prefix_ops_def
from neutron_lib.api import extensions
import webob.exc

from neutron._i18n import _
from neutron.api.v2 import resource_helper


def get_operation_request_body(body):
    if not isinstance(body, dict):
        msg = _('Request body contains invalid data')
        raise webob.exc.HTTPBadRequest(msg)
    prefixes = body.get('prefixes')
    if not prefixes or not isinstance(prefixes, list):
        msg = _('Request body contains invalid data')
        raise webob.exc.HTTPBadRequest(msg)

    return prefixes


class Subnetpool_prefix_ops(extensions.APIExtensionDescriptor):
    """API extension for subnet onboard."""

    api_definition = subnetpool_prefix_ops_def

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, subnetpool_def.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            subnetpool_def.RESOURCE_ATTRIBUTE_MAP,
            None,
            action_map=subnetpool_prefix_ops_def.ACTION_MAP,
            register_quota=True)
