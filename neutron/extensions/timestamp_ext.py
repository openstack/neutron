# Copyright 2016 HuaWei Technologies.
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
from neutron.extensions import l3
from neutron.extensions import securitygroup as sg

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
EXTENDED_ATTRIBUTES_2_0 = {
    l3.ROUTERS: TIMESTAMP_BODY,
    l3.FLOATINGIPS: TIMESTAMP_BODY,
    sg.SECURITYGROUPS: TIMESTAMP_BODY,
    sg.SECURITYGROUPRULES: TIMESTAMP_BODY,
}


class Timestamp_ext(extensions.ExtensionDescriptor):
    """Extension class supporting timestamp.

    This class is used by neutron's extension framework for adding timestamp
    to neutron extension resources.
    """

    @classmethod
    def get_name(cls):
        return "Standardattr Extension Timestamps"

    @classmethod
    def get_alias(cls):
        return "timestamp_ext"

    @classmethod
    def get_description(cls):
        return ("This extension can be used for recording "
                "create/update timestamps for ext resources "
                "like router, floatingip, security_group, "
                "security_group_rule.")

    @classmethod
    def get_updated(cls):
        return "2016-05-05T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
