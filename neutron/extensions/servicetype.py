# Copyright 2013 OpenStack Foundation.
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

from neutron_lib.api.definitions import servicetype as apidef
from neutron_lib.api import extensions as api_extensions

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.db import servicetype_db


class Servicetype(api_extensions.APIExtensionDescriptor):

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        attr_map = apidef.RESOURCE_ATTRIBUTE_MAP[apidef.COLLECTION_NAME]
        collection_name = apidef.COLLECTION_NAME.replace('_', '-')
        controller = base.create_resource(
            collection_name,
            apidef.RESOURCE_NAME,
            servicetype_db.ServiceTypeManager.get_instance(),
            attr_map)
        return [extensions.ResourceExtension(collection_name,
                                             controller,
                                             attr_map=attr_map)]
