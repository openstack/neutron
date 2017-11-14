# Copyright (c) 2012 OpenStack Foundation.
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

from neutron_lib.api import attributes as attrs
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def


# Defining a constant to avoid repeating string literal in several modules
SHARED = 'shared'

# Define constants for base resource name
CORE_RESOURCES = {net_def.RESOURCE_NAME: net_def.COLLECTION_NAME,
                  subnet_def.RESOURCE_NAME: subnet_def.COLLECTION_NAME,
                  subnetpool_def.RESOURCE_NAME: subnetpool_def.COLLECTION_NAME,
                  port_def.RESOURCE_NAME: port_def.COLLECTION_NAME}

RESOURCE_ATTRIBUTE_MAP = attrs.RESOURCES

# Identify the attribute used by a resource to reference another resource

RESOURCE_FOREIGN_KEYS = {
    net_def.COLLECTION_NAME: 'network_id'
}


def get_collection_info(collection):
    """Helper function to retrieve attribute info.

    :param collection: Collection or plural name of the resource
    """
    return RESOURCE_ATTRIBUTE_MAP.get(collection)
