# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum import quota
from quantum.openstack.common import cfg


quota_packet_filter_opts = [
    cfg.IntOpt('quota_packet_filter',
               default=100,
               help="number of packet_filters allowed per tenant, "
                    "-1 for unlimited")
]
# Register the configuration options
cfg.CONF.register_opts(quota_packet_filter_opts, 'QUOTAS')


PACKET_FILTER_ACTION_REGEX = "(?i)^(allow|accept|drop|deny)$"
PACKET_FILTER_NUMBER_REGEX = "(?i)^(0x[0-9a-fA-F]+|[0-9]+)$"
PACKET_FILTER_PROTOCOL_REGEX = "(?i)^(icmp|tcp|udp|arp|0x[0-9a-fA-F]+|[0-9]+)$"
PACKET_FILTER_ATTR_MAP = {
    'id': {'allow_post': False, 'allow_put': False,
           'validate': {'type:regex': attributes.UUID_PATTERN},
           'is_visible': True},
    'name': {'allow_post': True, 'allow_put': True, 'default': '',
             'is_visible': True},
    'tenant_id': {'allow_post': True, 'allow_put': False,
                  'required_by_policy': True,
                  'is_visible': True},
    'network_id': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:regex': attributes.UUID_PATTERN},
                   'is_visible': True},
    'admin_state_up': {'allow_post': True, 'allow_put': True,
                       'default': True,
                       'convert_to': attributes.convert_to_boolean,
                       'validate': {'type:boolean': None},
                       'is_visible': True},
    'status': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
    'action': {'allow_post': True, 'allow_put': True,
               'validate': {'type:regex': PACKET_FILTER_ACTION_REGEX},
               'is_visible': True},
    'priority': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:regex': PACKET_FILTER_NUMBER_REGEX},
                 'is_visible': True},
    'in_port': {'allow_post': True, 'allow_put': True,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:regex': attributes.UUID_PATTERN},
                'is_visible': True},
    'src_mac': {'allow_post': True, 'allow_put': True,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:mac_address': None},
                'is_visible': True},
    'dst_mac': {'allow_post': True, 'allow_put': True,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:mac_address': None},
                'is_visible': True},
    'eth_type': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:regex': PACKET_FILTER_NUMBER_REGEX},
                 'is_visible': True},
    'src_cidr': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:subnet': None},
                 'is_visible': True},
    'dst_cidr': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:subnet': None},
                 'is_visible': True},
    'protocol': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:regex': PACKET_FILTER_PROTOCOL_REGEX},
                 'is_visible': True},
    'src_port': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:regex': PACKET_FILTER_NUMBER_REGEX},
                 'is_visible': True},
    'dst_port': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:regex': PACKET_FILTER_NUMBER_REGEX},
                 'is_visible': True},
}


class Packetfilter(object):

    def __init__(self):
        pass

    def get_name(self):
        return "PacketFilters"

    def get_alias(self):
        return "PacketFilters"

    def get_description(self):
        return "PacketFilters"

    def get_namespace(self):
        return "http://www.nec.co.jp/api/ext/packet_filter/v2.0"

    def get_updated(self):
        return "2012-07-24T00:00:00+09:00"

    def get_resources(self):
        resource = base.create_resource('packet_filters', 'packet_filter',
                                        QuantumManager.get_plugin(),
                                        PACKET_FILTER_ATTR_MAP)
        qresource = quota.CountableResource('packet_filter',
                                            quota._count_resource,
                                            'quota_packet_filter')
        quota.QUOTAS.register_resource(qresource)
        return [extensions.ResourceExtension('packet_filters', resource)]
