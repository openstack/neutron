# Copyright 2012 Nachi Ueno, NTT MCL, Inc.
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

from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import attributes


LOG = logging.getLogger(__name__)

FLAVOR_NETWORK = 'flavor:network'
FLAVOR_ROUTER = 'flavor:router'

FLAVOR_ATTRIBUTE = {
    'networks': {
        FLAVOR_NETWORK: {'allow_post': True,
                         'allow_put': False,
                         'is_visible': True,
                         'default': attributes.ATTR_NOT_SPECIFIED}
    },
    'routers': {
        FLAVOR_ROUTER: {'allow_post': True,
                        'allow_put': False,
                        'is_visible': True,
                        'default': attributes.ATTR_NOT_SPECIFIED}
    }
}


class Flavor(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "Flavor support for network and router"

    @classmethod
    def get_alias(cls):
        return "flavor"

    @classmethod
    def get_description(cls):
        return "Flavor"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/flavor/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return FLAVOR_ATTRIBUTE
        else:
            return {}
