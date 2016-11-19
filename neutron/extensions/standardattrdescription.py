# Copyright 2016 OpenStack Foundation
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
from neutron_lib.db import constants as db_const

from neutron.db import standard_attr


DESCRIPTION_BODY = {
    'description': {'allow_post': True, 'allow_put': True,
                    'validate': {
                        'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                    'is_visible': True, 'default': ''}
}


class Standardattrdescription(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "standard-attr-description"

    @classmethod
    def get_alias(cls):
        return "standard-attr-description"

    @classmethod
    def get_description(cls):
        return "Extension to add descriptions to standard attributes"

    @classmethod
    def get_updated(cls):
        return "2016-02-10T10:00:00-00:00"

    def get_optional_extensions(self):
        return ['security-group', 'router']

    def get_extended_resources(self, version):
        if version != "2.0":
            return {}
        rs_map = standard_attr.get_standard_attr_resource_model_map()
        return {resource: DESCRIPTION_BODY for resource in rs_map}
