# Copyright (c) 2016 ZTE Inc.
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

from neutron_lib.api import converters

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper


RESOURCE_ATTRIBUTE_MAP = {
    'trunks': {
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'default': '', 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate':
                          {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
        'port_id': {'allow_post': True, 'allow_put': False,
                    'required_by_policy': True,
                    'validate': {'type:uuid': None},
                    'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'sub_ports': {'allow_post': True, 'allow_put': False,
                      'default': [],
                      'convert_list_to': converters.convert_kvp_list_to_dict,
                      'validate': {'type:subports': None},
                      'enforce_policy': True,
                      'is_visible': True},
    },
}


class Trunk(extensions.ExtensionDescriptor):
    """Trunk API extension."""

    @classmethod
    def get_name(cls):
        return "Trunk Extension"

    @classmethod
    def get_alias(cls):
        return "trunk"

    @classmethod
    def get_description(cls):
        return "Provides support for trunk ports"

    @classmethod
    def get_updated(cls):
        return "2016-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {'trunk': {'add_subports': 'PUT',
                                'remove_subports': 'PUT',
                                'get_subports': 'GET'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   'trunk',
                                                   action_map=action_map,
                                                   register_quota=True)

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Trunk, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_required_extensions(self):
        return ["binding"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
