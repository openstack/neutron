# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'v2attrs:something': {'allow_post': False,
                              'allow_put': False,
                              'is_visible': True},
        'v2attrs:something_else': {'allow_post': True,
                                   'allow_put': False,
                                   'is_visible': False},
    }
}


class V2attributes(object):
    def get_name(self):
        return "V2 Extended Attributes Example"

    def get_alias(self):
        return "v2attrs"

    def get_description(self):
        return "Demonstrates extended attributes on V2 core resources"

    def get_namespace(self):
        return "http://docs.openstack.org/ext/examples/v2attributes/api/v1.0"

    def get_updated(self):
        return "2012-07-18T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
