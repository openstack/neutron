# Copyright 2014 Cisco Systems, Inc.
# All Rights Reserved.
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

from networking_cisco.plugins.ml2.drivers.cisco.n1kv import constants

from neutron.api import extensions
from neutron.api.v2 import attributes


PROFILE = constants.N1KV_PROFILE
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {PROFILE: {
        'allow_post': True,
        'allow_put': False,
        'default': attributes.ATTR_NOT_SPECIFIED,
        'is_visible': True}}}


class N1kv(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco Nexus1000V Profile Extension"

    @classmethod
    def get_alias(cls):
        return "n1kv"

    @classmethod
    def get_description(cls):
        return _("Add new policy profile attribute to port resource.")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/n1kv/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2014-11-23T13:33:25-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
