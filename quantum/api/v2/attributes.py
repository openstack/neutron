# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the 'License'); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
import re

from quantum.common import exceptions as q_exc
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils


LOG = logging.getLogger(__name__)

ATTR_NOT_SPECIFIED = object()
# Defining a constant to avoid repeating string literal in several modules
SHARED = 'shared'


def _verify_dict_keys(expected_keys, target_dict):
    if not isinstance(target_dict, dict):
        msg = _("Invalid input. %s must be a dictionary.") % target_dict
        return msg

    provided_keys = target_dict.keys()
    if set(expected_keys) != set(provided_keys):
        msg = (_("Expected keys not found. Expected: %(expected_keys)s "
                 "Provided: %(provided_keys)s") % locals())
        return msg


def is_attr_set(attribute):
    return not (attribute is None or attribute is ATTR_NOT_SPECIFIED)


def _validate_values(data, valid_values=None):
    if data not in valid_values:
        msg = _("'%(data)s' is not in %(valid_values)s") % locals()
        LOG.debug("validate_values: %s", msg)
        return msg


def _validate_string(data, max_len=None):
    if not isinstance(data, basestring):
        msg = _("'%s' is not a valid string") % data
        LOG.debug("validate_string: %s", msg)
        return msg

    if max_len is not None and len(data) > max_len:
        msg = _("'%(data)s' exceeds maximum length of %(max_len)s") % locals()
        LOG.debug("validate_string: %s", msg)
        return msg


def _validate_range(data, valid_values=None):
    min_value = valid_values[0]
    max_value = valid_values[1]
    if not min_value <= data <= max_value:
        msg = _("'%(data)s' is not in range %(min_value)s through "
                "%(max_value)s") % locals()
        LOG.debug("validate_range: %s", msg)
        return msg


def _validate_mac_address(data, valid_values=None):
    try:
        netaddr.EUI(data)
    except Exception:
        msg = _("'%s' is not a valid MAC address") % data
        LOG.debug("validate_mac_address: %s", msg)
        return msg


def _validate_ip_address(data, valid_values=None):
    try:
        netaddr.IPAddress(data)
    except Exception:
        msg = _("'%s' is not a valid IP address") % data
        LOG.debug("validate_ip_address: %s", msg)
        return msg


def _validate_ip_pools(data, valid_values=None):
    """Validate that start and end IP addresses are present

    In addition to this the IP addresses will also be validated

    """
    if not isinstance(data, list):
        msg = _("'%s' is not a valid IP pool") % data
        LOG.debug("validate_ip_pools: %s", msg)
        return msg

    expected_keys = ['start', 'end']
    for ip_pool in data:
        msg = _verify_dict_keys(expected_keys, ip_pool)
        if msg:
            LOG.debug("validate_ip_pools: %s", msg)
            return msg
        for k in expected_keys:
            msg = _validate_ip_address(ip_pool[k])
            if msg:
                LOG.debug("validate_ip_pools: %s", msg)
                return msg


def _validate_fixed_ips(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a valid fixed IP") % data
        LOG.debug("validate_fixed_ips: %s", msg)
        return msg

    ips = []
    for fixed_ip in data:
        if 'ip_address' in fixed_ip:
            # Ensure that duplicate entries are not set - just checking IP
            # suffices. Duplicate subnet_id's are legitimate.
            fixed_ip_address = fixed_ip['ip_address']
            if fixed_ip_address in ips:
                msg = _("Duplicate entry %s") % fixed_ip
            else:
                msg = _validate_ip_address(fixed_ip_address)
            if msg:
                LOG.debug("validate_fixed_ips: %s", msg)
                return msg
            ips.append(fixed_ip_address)
        if 'subnet_id' in fixed_ip:
            msg = _validate_uuid(fixed_ip['subnet_id'])
            if msg:
                LOG.debug("validate_fixed_ips: %s", msg)
                return msg


def _validate_nameservers(data, valid_values=None):
    if not hasattr(data, '__iter__'):
        msg = _("'%s' is not a valid nameserver") % data
        LOG.debug("validate_nameservers: %s", msg)
        return msg

    ips = []
    for ip in data:
        msg = _validate_ip_address(ip)
        if msg:
            # This may be a hostname
            msg = _validate_regex(ip, HOSTNAME_PATTERN)
            if msg:
                msg = _("'%s' is not a valid nameserver") % ip
                LOG.debug("validate_nameservers: %s", msg)
                return msg
        if ip in ips:
            msg = _("Duplicate nameserver %s") % ip
            LOG.debug("validate_nameservers: %s", msg)
            return msg
        ips.append(ip)


def _validate_hostroutes(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a valid hostroute") % data
        LOG.debug("validate_hostroutes: %s", msg)
        return msg

    expected_keys = ['destination', 'nexthop']
    hostroutes = []
    for hostroute in data:
        msg = _verify_dict_keys(expected_keys, hostroute)
        if msg:
            LOG.debug("validate_hostroutes: %s", msg)
            return msg
        msg = _validate_subnet(hostroute['destination'])
        if msg:
            LOG.debug("validate_hostroutes: %s", msg)
            return msg
        msg = _validate_ip_address(hostroute['nexthop'])
        if msg:
            LOG.debug("validate_hostroutes: %s", msg)
            return msg
        if hostroute in hostroutes:
            msg = _("Duplicate hostroute %s") % hostroute
            LOG.debug("validate_hostroutes: %s", msg)
            return msg
        hostroutes.append(hostroute)


def _validate_ip_address_or_none(data, valid_values=None):
    if data is None:
        return None
    return _validate_ip_address(data, valid_values)


def _validate_subnet(data, valid_values=None):
    try:
        netaddr.IPNetwork(data)
        if len(data.split('/')) == 2:
            return
    except Exception:
        pass

    msg = _("'%s' is not a valid IP subnet") % data
    LOG.debug("validate_subnet: %s", msg)
    return msg


def _validate_regex(data, valid_values=None):
    try:
        if re.match(valid_values, data):
            return
    except TypeError:
        pass

    msg = _("'%s' is not a valid input") % data
    LOG.debug("validate_regex: %s", msg)
    return msg


def _validate_uuid(data, valid_values=None):
    if not uuidutils.is_uuid_like(data):
        msg = _("'%s' is not a valid UUID") % data
        LOG.debug("validate_uuid: %s", msg)
        return msg


def convert_to_boolean(data):
    if isinstance(data, basestring):
        val = data.lower()
        if val == "true" or val == "1":
            return True
        if val == "false" or val == "0":
            return False
    elif isinstance(data, bool):
        return data
    elif isinstance(data, int):
        if data == 0:
            return False
        elif data == 1:
            return True
    msg = _("'%s' cannot be converted to boolean") % data
    raise q_exc.InvalidInput(error_message=msg)


def convert_to_int(data):
    try:
        return int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not a integer") % data
        raise q_exc.InvalidInput(error_message=msg)


def convert_kvp_str_to_list(data):
    """Convert a value of the form 'key=value' to ['key', 'value'].

    :raises: q_exc.InvalidInput if any of the strings are malformed
                                (e.g. do not contain a key).
    """
    kvp = [x.strip() for x in data.split('=', 1)]
    if len(kvp) == 2 and kvp[0]:
        return kvp
    msg = _("'%s' is not of the form <key>=[value]") % data
    raise q_exc.InvalidInput(error_message=msg)


def convert_kvp_list_to_dict(kvp_list):
    """Convert a list of 'key=value' strings to a dict.

    :raises: q_exc.InvalidInput if any of the strings are malformed
                                (e.g. do not contain a key) or if any
                                of the keys appear more than once.
    """
    if kvp_list == ['True']:
        # No values were provided (i.e. '--flag-name')
        return {}
    kvp_map = {}
    for kvp_str in kvp_list:
        key, value = convert_kvp_str_to_list(kvp_str)
        kvp_map.setdefault(key, set())
        kvp_map[key].add(value)
    return dict((x, list(y)) for x, y in kvp_map.iteritems())


def convert_none_to_empty_list(value):
    return [] if value is None else value


HOSTNAME_PATTERN = ("(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]"
                    "{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)")

HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])
# Note: In order to ensure that the MAC address is unicast the first byte
# must be even.
MAC_PATTERN = "^%s[aceACE02468](:%s{2}){5}$" % (HEX_ELEM, HEX_ELEM)

# Dictionary that maintains a list of validation functions
validators = {'type:fixed_ips': _validate_fixed_ips,
              'type:hostroutes': _validate_hostroutes,
              'type:ip_address': _validate_ip_address,
              'type:ip_address_or_none': _validate_ip_address_or_none,
              'type:ip_pools': _validate_ip_pools,
              'type:mac_address': _validate_mac_address,
              'type:nameservers': _validate_nameservers,
              'type:range': _validate_range,
              'type:regex': _validate_regex,
              'type:string': _validate_string,
              'type:subnet': _validate_subnet,
              'type:uuid': _validate_uuid,
              'type:values': _validate_values}

# Note: a default of ATTR_NOT_SPECIFIED indicates that an
# attribute is not required, but will be generated by the plugin
# if it is not specified.  Particularly, a value of ATTR_NOT_SPECIFIED
# is different from an attribute that has been specified with a value of
# None.  For example, if 'gateway_ip' is ommitted in a request to
# create a subnet, the plugin will receive ATTR_NOT_SPECIFIED
# and the default gateway_ip will be generated.
# However, if gateway_ip is specified as None, this means that
# the subnet does not have a gateway IP.
# The following is a short reference for understanding attribute info:
# default: default value of the attribute (if missing, the attribute
# becomes mandatory.
# allow_post: the attribute can be used on POST requests.
# allow_put: the attribute can be used on PUT requests.
# validate: specifies rules for validating data in the attribute.
# convert_to: transformation to apply to the value before it is returned
# is_visible: the attribute is returned in GET responses.
# required_by_policy: the attribute is required by the policy engine and
# should therefore be filled by the API layer even if not present in
# request body.
# enforce_policy: the attribute is actively part of the policy enforcing
# mechanism, ie: there might be rules which refer to this attribute.

RESOURCE_ATTRIBUTE_MAP = {
    'networks': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'subnets': {'allow_post': False, 'allow_put': False,
                    'default': [],
                    'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        SHARED: {'allow_post': True,
                 'allow_put': True,
                 'default': False,
                 'convert_to': convert_to_boolean,
                 'is_visible': True,
                 'required_by_policy': True,
                 'enforce_policy': True},
    },
    'ports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True, 'default': '',
                 'validate': {'type:string': None},
                 'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {'type:uuid': None},
                       'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': convert_to_boolean,
                           'is_visible': True},
        'mac_address': {'allow_post': True, 'allow_put': False,
                        'default': ATTR_NOT_SPECIFIED,
                        'validate': {'type:mac_address': None},
                        'enforce_policy': True,
                        'is_visible': True},
        'fixed_ips': {'allow_post': True, 'allow_put': True,
                      'default': ATTR_NOT_SPECIFIED,
                      'convert_list_to': convert_kvp_list_to_dict,
                      'validate': {'type:fixed_ips': None},
                      'enforce_policy': True,
                      'is_visible': True},
        'device_id': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:string': None},
                      'default': '',
                      'is_visible': True},
        'device_owner': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'default': '',
                         'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
    },
    'subnets': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True, 'default': '',
                 'validate': {'type:string': None},
                 'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {'type:uuid': None},
                       'is_visible': True},
        'cidr': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:subnet': None},
                 'is_visible': True},
        'gateway_ip': {'allow_post': True, 'allow_put': True,
                       'default': ATTR_NOT_SPECIFIED,
                       'validate': {'type:ip_address_or_none': None},
                       'is_visible': True},
        #TODO(salvatore-orlando): Enable PUT on allocation_pools
        'allocation_pools': {'allow_post': True, 'allow_put': False,
                             'default': ATTR_NOT_SPECIFIED,
                             'validate': {'type:ip_pools': None},
                             'is_visible': True},
        'dns_nameservers': {'allow_post': True, 'allow_put': True,
                            'convert_to': convert_none_to_empty_list,
                            'default': ATTR_NOT_SPECIFIED,
                            'validate': {'type:nameservers': None},
                            'is_visible': True},
        'host_routes': {'allow_post': True, 'allow_put': True,
                        'convert_to': convert_none_to_empty_list,
                        'default': ATTR_NOT_SPECIFIED,
                        'validate': {'type:hostroutes': None},
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'enable_dhcp': {'allow_post': True, 'allow_put': True,
                        'default': True,
                        'convert_to': convert_to_boolean,
                        'is_visible': True},
        SHARED: {'allow_post': False,
                 'allow_put': False,
                 'default': False,
                 'convert_to': convert_to_boolean,
                 'is_visible': False,
                 'required_by_policy': True,
                 'enforce_policy': True},
    }
}

# Associates to each resource its own parent resource
# Resources without parents, such as networks, are not in this list

RESOURCE_HIERARCHY_MAP = {
    'ports': {'parent': 'networks', 'identified_by': 'network_id'},
    'subnets': {'parent': 'networks', 'identified_by': 'network_id'}
}
