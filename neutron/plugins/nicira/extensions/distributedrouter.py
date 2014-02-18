# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron.api.v2 import attributes


def convert_to_boolean_if_not_none(data):
    if data is not None:
        return attributes.convert_to_boolean(data)
    return data


DISTRIBUTED = 'distributed'
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        DISTRIBUTED: {'allow_post': True, 'allow_put': False,
                      'convert_to': convert_to_boolean_if_not_none,
                      'default': attributes.ATTR_NOT_SPECIFIED,
                      'is_visible': True},
    }
}


class Distributedrouter(object):
    """Extension class supporting distributed router."""

    @classmethod
    def get_name(cls):
        return "Distributed Router"

    @classmethod
    def get_alias(cls):
        return "dist-router"

    @classmethod
    def get_description(cls):
        return "Enables configuration of NSX Distributed routers."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/dist-router/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-08-1T10:00:00-00:00"

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
