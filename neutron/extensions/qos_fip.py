#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import qos
from neutron_lib.api import extensions
from neutron_lib.services.qos import constants as qos_consts

FIP_QOS_ALIAS = "qos-fip"
EXTENDED_ATTRIBUTES_2_0 = {
    l3.FLOATINGIPS: {
        qos_consts.QOS_POLICY_ID: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'validate': {'type:uuid_or_none': None}}
    }
}
REQUIRED_EXTENSIONS = [l3.ALIAS, qos.ALIAS]


class Qos_fip(extensions.ExtensionDescriptor):
    """Extension class supporting floating IP QoS in all router."""

    @classmethod
    def get_name(cls):
        return "Floating IP QoS"

    @classmethod
    def get_alias(cls):
        return FIP_QOS_ALIAS

    @classmethod
    def get_description(cls):
        return "The floating IP Quality of Service extension"

    @classmethod
    def get_updated(cls):
        return "2017-07-20T00:00:00-00:00"

    def get_required_extensions(self):
        return REQUIRED_EXTENSIONS

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
