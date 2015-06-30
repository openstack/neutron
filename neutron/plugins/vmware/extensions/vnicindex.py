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

# Attribute Map
VNIC_INDEX = 'vnic_index'


EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        VNIC_INDEX:
        {'allow_post': True,
         'allow_put': True,
         'is_visible': True,
         'default': None,
         'convert_to': attributes.convert_to_int_if_not_none}}}


class Vnicindex(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "VNIC Index"

    @classmethod
    def get_alias(cls):
        return "vnic-index"

    @classmethod
    def get_description(cls):
        return ("Enable a port to be associated with a VNIC index")

    @classmethod
    def get_updated(cls):
        return "2014-09-15T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
