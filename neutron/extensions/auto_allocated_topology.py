# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
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

from neutron_lib.api.definitions import auto_allocated_topology
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base


class Auto_allocated_topology(api_extensions.APIExtensionDescriptor):
    api_definition = auto_allocated_topology

    @classmethod
    def get_resources(cls):
        params = auto_allocated_topology.RESOURCE_ATTRIBUTE_MAP.get(
            auto_allocated_topology.COLLECTION_NAME, dict())
        controller = base.create_resource(
            auto_allocated_topology.COLLECTION_NAME,
            auto_allocated_topology.ALIAS,
            directory.get_plugin(auto_allocated_topology.ALIAS),
            params, allow_bulk=False)
        return [extensions.ResourceExtension(
            auto_allocated_topology.ALIAS, controller)]
