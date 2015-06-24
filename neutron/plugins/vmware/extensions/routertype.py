# Copyright 2015 VMware, Inc.  All rights reserved.
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

from neutron.api import extensions
from neutron.api.v2 import attributes


ROUTER_TYPE = 'router_type'
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        ROUTER_TYPE: {'allow_post': True, 'allow_put': False,
                      'validate': {'type:values': ['shared', 'exclusive']},
                      'default': attributes.ATTR_NOT_SPECIFIED,
                      'is_visible': True},
    }
}


class Routertype(extensions.ExtensionDescriptor):
    """Extension class supporting router type."""

    @classmethod
    def get_name(cls):
        return "Router Type"

    @classmethod
    def get_alias(cls):
        return "nsxv-router-type"

    @classmethod
    def get_description(cls):
        return "Enables configuration of NSXv router type."

    @classmethod
    def get_updated(cls):
        return "2015-1-12T10:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
