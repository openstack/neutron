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
#

from neutron.api import extensions
from neutron.api.v2 import attributes


SERVICE_ROUTER = 'service_router'
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        SERVICE_ROUTER: {'allow_post': True, 'allow_put': False,
                         'convert_to': attributes.convert_to_boolean,
                         'default': False, 'is_visible': True},
    }
}


class Servicerouter(extensions.ExtensionDescriptor):
    """Extension class supporting advanced service router."""

    @classmethod
    def get_name(cls):
        return "Service Router"

    @classmethod
    def get_alias(cls):
        return "service-router"

    @classmethod
    def get_description(cls):
        return "Provides service router."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/service-router/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-08-08T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
