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

from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions as nexception
from oslo_config import cfg
import webob.exc

from neutron._i18n import _
from neutron.conf.extensions import allowedaddresspairs as addr_pair

addr_pair.register_allowed_address_pair_opts()


class AllowedAddressPairsMissingIP(nexception.InvalidInput):
    message = _("AllowedAddressPair must contain ip_address")


class AddressPairAndPortSecurityRequired(nexception.Conflict):
    message = _("Port Security must be enabled in order to have allowed "
                "address pairs on a port.")


class DuplicateAddressPairInRequest(nexception.InvalidInput):
    message = _("Request contains duplicate address pair: "
                "mac_address %(mac_address)s ip_address %(ip_address)s.")


class AllowedAddressPairExhausted(nexception.BadRequest):
    message = _("The number of allowed address pair "
                "exceeds the maximum %(quota)s.")


def _validate_allowed_address_pairs(address_pairs, valid_values=None):
    unique_check = {}
    if not isinstance(address_pairs, list):
        raise webob.exc.HTTPBadRequest(
            _("Allowed address pairs must be a list."))
    if len(address_pairs) > cfg.CONF.max_allowed_address_pair:
        raise AllowedAddressPairExhausted(
            quota=cfg.CONF.max_allowed_address_pair)

    for address_pair in address_pairs:
        msg = validators.validate_dict(address_pair)
        if msg:
            return msg
        # mac_address is optional, if not set we use the mac on the port
        if 'mac_address' in address_pair:
            msg = validators.validate_mac_address(address_pair['mac_address'])
            if msg:
                raise webob.exc.HTTPBadRequest(msg)
        if 'ip_address' not in address_pair:
            raise AllowedAddressPairsMissingIP()

        mac = address_pair.get('mac_address')
        ip_address = address_pair['ip_address']
        if (mac, ip_address) not in unique_check:
            unique_check[(mac, ip_address)] = None
        else:
            raise DuplicateAddressPairInRequest(mac_address=mac,
                                                ip_address=ip_address)

        invalid_attrs = set(address_pair.keys()) - set(['mac_address',
                                                        'ip_address'])
        if invalid_attrs:
            msg = (_("Unrecognized attribute(s) '%s'") %
                   ', '.join(set(address_pair.keys()) -
                             set(['mac_address', 'ip_address'])))
            raise webob.exc.HTTPBadRequest(msg)

        if '/' in ip_address:
            msg = validators.validate_subnet(ip_address)
        else:
            msg = validators.validate_ip_address(ip_address)
        if msg:
            raise webob.exc.HTTPBadRequest(msg)

validators.add_validator('validate_allowed_address_pairs',
                         _validate_allowed_address_pairs)

ADDRESS_PAIRS = 'allowed_address_pairs'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        ADDRESS_PAIRS: {'allow_post': True, 'allow_put': True,
                        'convert_to': converters.convert_none_to_empty_list,
                        'convert_list_to':
                        converters.convert_kvp_list_to_dict,
                        'validate': {'type:validate_allowed_address_pairs':
                                     None},
                        'enforce_policy': True,
                        'default': constants.ATTR_NOT_SPECIFIED,
                        'is_visible': True},
    }
}


class Allowedaddresspairs(extensions.ExtensionDescriptor):
    """Extension class supporting allowed address pairs."""

    @classmethod
    def get_name(cls):
        return "Allowed Address Pairs"

    @classmethod
    def get_alias(cls):
        return "allowed-address-pairs"

    @classmethod
    def get_description(cls):
        return "Provides allowed address pairs"

    @classmethod
    def get_updated(cls):
        return "2013-07-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
