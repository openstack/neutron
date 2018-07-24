# Copyright 2016 GoDaddy.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from neutron_lib.api.definitions import network_ip_availability as apidef
from neutron_lib.api import extensions as api_extensions

import neutron.api.extensions as extensions
import neutron.api.v2.base as base
import neutron.services.network_ip_availability.plugin as plugin


class Network_ip_availability(api_extensions.APIExtensionDescriptor):
    """Extension class supporting network ip availability information."""
    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        resource_attributes = apidef.RESOURCE_ATTRIBUTE_MAP[
            apidef.RESOURCE_PLURAL]
        # TODO(hongbin): Delete _populate_is_filter_keyword once neutron-lib
        # containing https://review.openstack.org/#/c/583838/ is released.
        cls._populate_is_filter_keyword(resource_attributes)
        controller = base.create_resource(
            apidef.RESOURCE_PLURAL,
            apidef.RESOURCE_NAME,
            plugin.NetworkIPAvailabilityPlugin.get_instance(),
            resource_attributes)
        return [extensions.ResourceExtension(apidef.COLLECTION_NAME,
                                             controller,
                                             attr_map=resource_attributes)]

    @classmethod
    def _populate_is_filter_keyword(cls, params):
        filter_keys = ['network_id', 'network_name', 'tenant_id',
                       'project_id']
        for name in params:
            if name in filter_keys:
                params[name]['is_filter'] = True
        params['ip_version'] = {'allow_post': False, 'allow_put': False,
                                'is_visible': False, 'is_filter': True}
