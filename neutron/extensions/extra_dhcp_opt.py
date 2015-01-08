# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions


# ExtraDHcpOpts Exceptions
class ExtraDhcpOptNotFound(exceptions.NotFound):
    message = _("ExtraDhcpOpt %(id)s could not be found")


class ExtraDhcpOptBadData(exceptions.InvalidInput):
    message = _("Invalid data format for extra-dhcp-opt: %(data)s")


def _validate_list_of_dict_or_none(data, key_specs=None):
    if data is not None:
        if not isinstance(data, list):
            raise ExtraDhcpOptBadData(data=data)
        for d in data:
            msg = attr._validate_dict(d, key_specs)
            if msg:
                raise ExtraDhcpOptBadData(data=msg)


attr.validators['type:list_of_dict_or_none'] = _validate_list_of_dict_or_none

# Attribute Map
EXTRADHCPOPTS = 'extra_dhcp_opts'

# Common definitions for maximum string field length
DHCP_OPT_NAME_MAX_LEN = 64
DHCP_OPT_VALUE_MAX_LEN = 255

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        EXTRADHCPOPTS:
        {'allow_post': True,
         'allow_put': True,
         'is_visible': True,
         'default': None,
         'validate': {
             'type:list_of_dict_or_none': {
                 'id': {'type:uuid': None, 'required': False},
                 'opt_name': {'type:not_empty_string': DHCP_OPT_NAME_MAX_LEN,
                              'required': True},
                 'opt_value': {'type:not_empty_string_or_none':
                               DHCP_OPT_VALUE_MAX_LEN,
                               'required': True},
                 'ip_version': {'convert_to': attr.convert_to_int,
                                'type:values': [4, 6],
                                'required': False}}}}}}


class Extra_dhcp_opt(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "Neutron Extra DHCP opts"

    @classmethod
    def get_alias(cls):
        return "extra_dhcp_opt"

    @classmethod
    def get_description(cls):
        return ("Extra options configuration for DHCP. "
                "For example PXE boot options to DHCP clients can "
                "be specified (e.g. tftp-server, server-ip-address, "
                "bootfile-name)")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/extra_dhcp_opt/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-03-17T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
