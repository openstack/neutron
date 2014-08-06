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


ROUTER_ID = 'router_id'
EXTENDED_ATTRIBUTES_2_0 = {
    'vips': {
        ROUTER_ID: {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'default': None, 'is_visible': True},
    },
    'pools': {
        ROUTER_ID: {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'default': None, 'is_visible': True},
    },
    'health_monitors': {
        ROUTER_ID: {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'default': None, 'is_visible': True},
    },

    'firewalls': {
        ROUTER_ID: {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'default': None, 'is_visible': True},
    }
}


class Routedserviceinsertion(object):
    """Extension class supporting routed service type."""

    @classmethod
    def get_name(cls):
        return "Routed Service Insertion"

    @classmethod
    def get_alias(cls):
        return "routed-service-insertion"

    @classmethod
    def get_description(cls):
        return "Provides routed service type"

    @classmethod
    def get_namespace(cls):
        return ""

    @classmethod
    def get_updated(cls):
        return "2013-01-29T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
