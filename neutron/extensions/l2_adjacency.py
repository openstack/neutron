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

from neutron_lib.api import extensions


L2_ADJACENCY = 'l2_adjacency'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        L2_ADJACENCY: {'allow_post': False,
                       'allow_put': False,
                       'is_visible': True}
    }
}


class L2_adjacency(extensions.ExtensionDescriptor):
    """Extension class supporting L2 Adjacency for Routed Networks

    The following class is used by neutron's extension framework
    to provide metadata related to the L2 Adjacency for Neutron
    Routed Network, exposing the same to clients.
    No new resources have been defined by this extension.
    """

    @classmethod
    def get_name(cls):
        return "L2 Adjacency"

    @classmethod
    def get_alias(cls):
        return "l2_adjacency"

    @classmethod
    def get_description(cls):
        return "Display L2 Adjacency for Neutron Networks."

    @classmethod
    def get_updated(cls):
        return "2016-04-12T16:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
