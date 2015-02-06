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

import webob.exc

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from oslo_config import cfg

allowed_address_pair_opts = [
    #TODO(limao): use quota framework when it support quota for attributes
    cfg.IntOpt('max_allowed_address_pair', default=10,
               help=_("Maximum number of allowed address pairs")),
]

cfg.CONF.register_opts(allowed_address_pair_opts)


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
    if len(address_pairs) > cfg.CONF.max_allowed_address_pair:
        raise AllowedAddressPairExhausted(
            quota=cfg.CONF.max_allowed_address_pair)

    for address_pair in address_pairs:
        # mac_address is optional, if not set we use the mac on the port
        if 'mac_address' in address_pair:
            msg = attr._validate_mac_address(address_pair['mac_address'])
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
            msg = attr._validate_subnet(ip_address)
        else:
            msg = attr._validate_ip_address(ip_address)
        if msg:
            raise webob.exc.HTTPBadRequest(msg)

attr.validators['type:validate_allowed_address_pairs'] = (
    _validate_allowed_address_pairs)

ADDRESS_PAIRS = 'allowed_address_pairs'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        ADDRESS_PAIRS: {'allow_post': True, 'allow_put': True,
                        'convert_list_to':
                        attr.convert_kvp_list_to_dict,
                        'validate': {'type:validate_allowed_address_pairs':
                                     None},
                        'enforce_policy': True,
                        'default': attr.ATTR_NOT_SPECIFIED,
                        'is_visible': True},
    }
}


class Allowedaddresspairs(object):
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
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/allowedaddresspairs/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2013-07-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            attr.PLURALS.update({'allowed_address_pairs':
                                 'allowed_address_pair'})
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
