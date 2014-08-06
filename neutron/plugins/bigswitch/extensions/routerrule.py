# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved
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

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as qexception
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


# Router Rules Exceptions
class InvalidRouterRules(qexception.InvalidInput):
    message = _("Invalid format for router rules: %(rule)s, %(reason)s")


class RulesExhausted(qexception.BadRequest):
    message = _("Unable to complete rules update for %(router_id)s. "
                "The number of rules exceeds the maximum %(quota)s.")


def convert_to_valid_router_rules(data):
    """
    Validates and converts router rules to the appropriate data structure
    Example argument = [{'source': 'any', 'destination': 'any',
                         'action':'deny'},
                        {'source': '1.1.1.1/32', 'destination': 'external',
                         'action':'permit',
                         'nexthops': ['1.1.1.254', '1.1.1.253']}
                       ]
    """
    V4ANY = '0.0.0.0/0'
    CIDRALL = ['any', 'external']
    if not isinstance(data, list):
        emsg = _("Invalid data format for router rule: '%s'") % data
        LOG.debug(emsg)
        raise qexception.InvalidInput(error_message=emsg)
    _validate_uniquerules(data)
    rules = []
    expected_keys = ['source', 'destination', 'action']
    for rule in data:
        rule['nexthops'] = rule.get('nexthops', [])
        if not isinstance(rule['nexthops'], list):
            rule['nexthops'] = rule['nexthops'].split('+')

        src = V4ANY if rule['source'] in CIDRALL else rule['source']
        dst = V4ANY if rule['destination'] in CIDRALL else rule['destination']

        errors = [attr._verify_dict_keys(expected_keys, rule, False),
                  attr._validate_subnet(dst),
                  attr._validate_subnet(src),
                  _validate_nexthops(rule['nexthops']),
                  _validate_action(rule['action'])]
        errors = [m for m in errors if m]
        if errors:
            LOG.debug(errors)
            raise qexception.InvalidInput(error_message=errors)
        rules.append(rule)
    return rules


def _validate_nexthops(nexthops):
    seen = []
    for ip in nexthops:
        msg = attr._validate_ip_address(ip)
        if ip in seen:
            msg = _("Duplicate nexthop in rule '%s'") % ip
        seen.append(ip)
        if msg:
            return msg


def _validate_action(action):
    if action not in ['permit', 'deny']:
        return _("Action must be either permit or deny."
                 " '%s' was provided") % action


def _validate_uniquerules(rules):
    pairs = []
    for r in rules:
        if 'source' not in r or 'destination' not in r:
            continue
        pairs.append((r['source'], r['destination']))

    if len(set(pairs)) != len(pairs):
        error = _("Duplicate router rules (src,dst)  found '%s'") % pairs
        LOG.debug(error)
        raise qexception.InvalidInput(error_message=error)


class Routerrule(object):

    @classmethod
    def get_name(cls):
        return "Neutron Router Rule"

    @classmethod
    def get_alias(cls):
        return "router_rules"

    @classmethod
    def get_description(cls):
        return "Router rule configuration for L3 router"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/routerrules/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-05-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'router_rules': {'allow_post': False, 'allow_put': True,
                         'convert_to': convert_to_valid_router_rules,
                         'is_visible': True,
                         'default': attr.ATTR_NOT_SPECIFIED},
    }
}
