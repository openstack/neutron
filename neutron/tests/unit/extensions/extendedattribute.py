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

from neutron.api import extensions

EXTENDED_ATTRIBUTE = 'extended_attribute'
EXTENDED_ATTRIBUTES_2_0 = {
    'ext_test_resources': {
        EXTENDED_ATTRIBUTE: {'allow_post': True, 'allow_put': False,
                             'validate': {'type:uuid_or_none': None},
                             'default': None, 'is_visible': True},
    }
}


class Extendedattribute(extensions.ExtensionDescriptor):
    """Extension class supporting extended attribute for router."""

    @classmethod
    def get_name(cls):
        return "Extended Extension Attributes"

    @classmethod
    def get_alias(cls):
        return "extended-ext-attr"

    @classmethod
    def get_description(cls):
        return "Provides extended_attr attribute to router"

    @classmethod
    def get_updated(cls):
        return "2013-02-05T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
