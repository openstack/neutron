# Copyright (c) 2017 IBM
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

from neutron_lib.api import converters
from neutron_lib.api import extensions

from neutron.extensions import dns


EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        dns.DNSDOMAIN: {'allow_post': True, 'allow_put': True,
                        'default': '',
                        'convert_to':
                            converters.convert_string_to_case_insensitive,
                        'validate': {'type:dns_domain': dns.FQDN_MAX_LEN},
                        'is_visible': True},
    },
}


class Dns_domain_ports(extensions.ExtensionDescriptor):
    """Extension class supporting dns_domain attribute for ports."""

    @classmethod
    def get_name(cls):
        return "dns_domain for ports"

    @classmethod
    def get_alias(cls):
        return "dns-domain-ports"

    @classmethod
    def get_description(cls):
        return "Allows the DNS domain to be specified for a network port."

    @classmethod
    def get_updated(cls):
        return "2017-06-25T18:00:00-00:00"

    def get_required_extensions(self):
        return ["dns-integration"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
