# Copyright 2014 OpenStack Foundation.
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


from neutron.extensions import group_policy as gpolicy


# Extended attributes for Group Policy resource to map to Neutron contructs
EXTENDED_ATTRIBUTES_2_0 = {
    gpolicy.ENDPOINTS: {
        'neutron_port_id': {'allow_post': True, 'allow_put': False,
                            'validate': {'type:uuid_or_none': None},
                            'is_visible': True, 'default': None},
    },
    gpolicy.ENDPOINT_GROUPS: {
        'neutron_network_id': {'allow_post': True, 'allow_put': False,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True, 'default': None},
    }
}


class GroupPolicyMapping(object):

    @classmethod
    def get_name(cls):
        return "Group Policy Abstraction Mapping to Neutron Resources"

    @classmethod
    def get_alias(cls):
        return "group-policy-mapping"

    @classmethod
    def get_description(cls):
        return "Extension for Group Policy Abstraction Mapping"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/gp/v1.0/"

    @classmethod
    def get_updated(cls):
        return "2014-03-03T122:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
