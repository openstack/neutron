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

ATTR_NOT_SPECIFIED = object()
# Defining a constant to avoid repeating string literal in several modules
SHARED = 'shared'

import logging
import netaddr
import re

from quantum.common import exceptions as q_exc


LOG = logging.getLogger(__name__)


def is_attr_set(attribute):
    return attribute not in (None, ATTR_NOT_SPECIFIED)


def _validate_boolean(data, valid_values=None):
    if data in [True, False]:
        return
    else:
        msg = _("%s is not boolean") % data
        LOG.debug("validate_boolean: %s", msg)
        return msg


def _validate_values(data, valid_values=None):
    if data in valid_values:
        return
    else:
        msg_dict = dict(data=data, values=valid_values)
        msg = _("%(data)s is not in %(values)s") % msg_dict
        LOG.debug("validate_values: %s", msg)
        return msg


def _validate_range(data, valid_values=None):
    min_value = valid_values[0]
    max_value = valid_values[1]
    if data >= min_value and data <= max_value:
        return
    else:
        msg_dict = dict(data=data, min_value=min_value, max_value=max_value)
        msg = _("%(data)s is not in range %(min_value)s through "
                "%(max_value)s") % msg_dict
        LOG.debug("validate_range: %s", msg)
        return msg


def _validate_mac_address(data, valid_values=None):
    try:
        netaddr.EUI(data)
        return
    except Exception:
        msg = _("%s is not a valid MAC address") % data
        LOG.debug("validate_mac_address: %s", msg)
        return msg


def _validate_ip_address(data, valid_values=None):
    try:
        netaddr.IPAddress(data)
        return
    except Exception:
        msg = _("%s is not a valid IP address") % data
        LOG.debug("validate_ip_address: %s", msg)
        return msg


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

    msg = _("%s is not a valid IP subnet") % data
    LOG.debug("validate_subnet: %s", msg)
    return msg


def _validate_regex(data, valid_values=None):
    match = re.match(valid_values, data)
    if match:
        return
    else:
        msg = _("%s is not valid") % data
        LOG.debug("validate_regex: %s", msg)
        return msg


def convert_to_boolean(data):
    try:
        i = int(data)
        if i in [True, False]:
            # Ensure that the value is True or False
            if i:
                return True
            else:
                return False
    except ValueError, TypeError:
        if (data == "True" or data == "true"):
            return True
        if (data == "False" or data == "false"):
            return False
    msg = _("%s is not boolean") % data
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


HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])
# Note: In order to ensure that the MAC address is unicast the first byte
# must be even.
MAC_PATTERN = "^%s[aceACE02468](:%s{2}){5}$" % (HEX_ELEM, HEX_ELEM)

# Dictionary that maintains a list of validation functions
validators = {'type:boolean': _validate_boolean,
              'type:values': _validate_values,
              'type:range': _validate_range,
              'type:mac_address': _validate_mac_address,
              'type:ip_address': _validate_ip_address,
              'type:ip_address_or_none': _validate_ip_address_or_none,
              'type:subnet': _validate_subnet,
              'type:regex': _validate_regex}

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
               'validate': {'type:regex': UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'default': '', 'is_visible': True},
        'subnets': {'allow_post': False, 'allow_put': False,
                    'default': [],
                    'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': convert_to_boolean,
                           'validate': {'type:boolean': None},
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        SHARED: {'allow_post': True,
                 'allow_put': True,
                 'default': False,
                 'convert_to': convert_to_boolean,
                 'validate': {'type:boolean': None},
                 'is_visible': True,
                 'required_by_policy': True,
                 'enforce_policy': True},
    },
    'ports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True, 'default': '',
                 'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {'type:regex': UUID_PATTERN},
                       'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': convert_to_boolean,
                           'validate': {'type:boolean': None},
                           'is_visible': True},
        'mac_address': {'allow_post': True, 'allow_put': False,
                        'default': ATTR_NOT_SPECIFIED,
                        'validate': {'type:mac_address': None},
                        'enforce_policy': True,
                        'is_visible': True},
        'fixed_ips': {'allow_post': True, 'allow_put': True,
                      'default': ATTR_NOT_SPECIFIED,
                      'convert_list_to': convert_kvp_list_to_dict,
                      'enforce_policy': True,
                      'is_visible': True},
        'device_id': {'allow_post': True, 'allow_put': True,
                      'default': '',
                      'is_visible': True},
        'device_owner': {'allow_post': True, 'allow_put': True,
                         'default': '',
                         'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
    },
    'subnets': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True, 'default': '',
                 'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {'type:regex': UUID_PATTERN},
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
                             'is_visible': True},
        'dns_nameservers': {'allow_post': True, 'allow_put': True,
                            'default': ATTR_NOT_SPECIFIED,
                            'is_visible': True},
        'host_routes': {'allow_post': True, 'allow_put': True,
                        'default': ATTR_NOT_SPECIFIED,
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'enable_dhcp': {'allow_post': True, 'allow_put': True,
                        'default': True,
                        'convert_to': convert_to_boolean,
                        'validate': {'type:boolean': None},
                        'is_visible': True},
        SHARED: {'allow_post': False,
                 'allow_put': False,
                 'default': False,
                 'convert_to': convert_to_boolean,
                 'validate': {'type:boolean': None},
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
