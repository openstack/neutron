# Copyright 2014 Alcatel-Lucent USA Inc.
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


EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        'net_partition': {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'validate': {'type:string_or_none': None}
        },
        'nuage_subnet_template': {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': None,
            'validate': {'type:uuid_or_none': None}
        },
    },
}


class Nuage_subnet(object):
    """Extension class supporting Nuage subnet.
    """

    @classmethod
    def get_name(cls):
        return "Nuage subnet"

    @classmethod
    def get_alias(cls):
        return "nuage-subnet"

    @classmethod
    def get_description(cls):
        return "Nuage subnet"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/subnets/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
