# Copyright (c) 2016 NEC Technologies Ltd.
# All rights reserved.
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

from neutron_lib.api.definitions import l2_adjacency as apidef
from neutron_lib.api import extensions


class L2_adjacency(extensions.APIExtensionDescriptor):
    """Extension class supporting L2 Adjacency for Routed Networks

    The following class is used by neutron's extension framework
    to provide metadata related to the L2 Adjacency for Neutron
    Routed Network, exposing the same to clients.
    No new resources have been defined by this extension.
    """
    api_definition = apidef
