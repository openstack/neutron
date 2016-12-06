# Copyright 2015 HuaWei Technologies.
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

from neutron.db import standard_attr


# Attribute Map
CREATED = 'created_at'
UPDATED = 'updated_at'
TIMESTAMP_BODY = {
    CREATED: {'allow_post': False, 'allow_put': False,
              'is_visible': True, 'default': None
              },
    UPDATED: {'allow_post': False, 'allow_put': False,
              'is_visible': True, 'default': None
              },
}


class Timestamp(extensions.ExtensionDescriptor):
    """Extension class supporting timestamp.

    This class is used by neutron's extension framework for adding timestamp
    to neutron core resources.
    """

    @classmethod
    def get_name(cls):
        return "Resource timestamps"

    @classmethod
    def get_alias(cls):
        return "standard-attr-timestamp"

    @classmethod
    def get_description(cls):
        return ("Adds created_at and updated_at fields to all Neutron "
                "resources that have Neutron standard attributes.")

    @classmethod
    def get_updated(cls):
        return "2016-09-12T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version != "2.0":
            return {}
        rs_map = standard_attr.get_standard_attr_resource_model_map()
        return {resource: TIMESTAMP_BODY for resource in rs_map}
