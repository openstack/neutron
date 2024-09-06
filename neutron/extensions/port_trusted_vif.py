# Copyright (c) 2024 Red Hat, Inc.
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

from neutron_lib.api import converters
from neutron_lib.api.definitions import port
from neutron_lib.api.definitions import portbindings
from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants


# TODO(slaweq): use api definition from neutron-lib once
# https://review.opendev.org/c/openstack/neutron-lib/+/923860
# will be merged and released

ALIAS = 'port-trusted-vif'
NAME = "Port trusted vif"
DESCRIPTION = "Expose port 'trusted' attribute in the API"
UPDATED_TIMESTAMP = "2024-07-10T10:00:00-00:00"
RESOURCE_NAME = port.RESOURCE_NAME
COLLECTION_NAME = port.COLLECTION_NAME
TRUSTED_VIF = 'trusted'

RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        TRUSTED_VIF: {
            'allow_post': True,
            'allow_put': True,
            'convert_to': converters.convert_to_boolean,
            'enforce_policy': True,
            'required_by_policy': False,
            'default': constants.ATTR_NOT_SPECIFIED,
            'is_visible': True,
            'validate': {'type:boolean': None}
        }
    },
}
REQUIRED_EXTENSIONS = [portbindings.ALIAS]
OPTIONAL_EXTENSIONS = []


class Port_trusted_vif(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return NAME

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return DESCRIPTION

    @classmethod
    def get_updated(cls):
        return UPDATED_TIMESTAMP

    def get_required_extensions(self):
        return REQUIRED_EXTENSIONS

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
