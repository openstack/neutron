# Copyright 2013 vArmour Networks Inc.
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

ROUTER_OBJ_PREFIX = 'r-'
OBJ_PREFIX_LEN = 8
TRUST_ZONE = '_z_trust'
UNTRUST_ZONE = '_z_untrust'
SNAT_RULE = '_snat'
DNAT_RULE = '_dnat'
ROUTER_POLICY = '_p'

REST_URL_CONF = '/config'
REST_URL_AUTH = '/auth'
REST_URL_COMMIT = '/commit'
REST_URL_INTF_MAP = '/operation/interface/mapping'

REST_URL_CONF_NAT_RULE = REST_URL_CONF + '/nat/rule'
REST_URL_CONF_ZONE = REST_URL_CONF + '/zone'
REST_URL_CONF_POLICY = REST_URL_CONF + '/policy'
REST_URL_CONF_ADDR = REST_URL_CONF + '/address'
REST_URL_CONF_SERVICE = REST_URL_CONF + '/service'

REST_ZONE_NAME = '/zone/"name:%s"'
REST_INTF_NAME = '/interface/"name:%s"'
REST_LOGIC_NAME = '/logical/"name:%s"'
REST_SERVICE_NAME = '/service/"name:%s"/rule'


def get_router_object_prefix(ri):
    return ROUTER_OBJ_PREFIX + ri.router['id'][:OBJ_PREFIX_LEN]


def get_firewall_object_prefix(ri, fw):
    return get_router_object_prefix(ri) + '-' + fw['id'][:OBJ_PREFIX_LEN]


def get_trusted_zone_name(ri):
    return get_router_object_prefix(ri) + TRUST_ZONE


def get_untrusted_zone_name(ri):
    return get_router_object_prefix(ri) + UNTRUST_ZONE


def get_snat_rule_name(ri):
    return get_router_object_prefix(ri) + SNAT_RULE


def get_dnat_rule_name(ri):
    return get_router_object_prefix(ri) + DNAT_RULE


def get_router_policy_name(ri):
    return get_router_object_prefix(ri) + ROUTER_POLICY


def get_firewall_policy_name(ri, fw, rule):
    return get_firewall_object_prefix(ri, fw) + rule['id'][:OBJ_PREFIX_LEN]
