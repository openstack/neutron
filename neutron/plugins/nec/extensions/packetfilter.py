# Copyright 2012-2013 NEC Corporation.
# All rights reserved.
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

from oslo_config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.common import constants
from neutron.common import exceptions
from neutron import manager
from neutron import quota


quota_packet_filter_opts = [
    cfg.IntOpt('quota_packet_filter',
               default=100,
               help=_("Number of packet_filters allowed per tenant, "
                      "-1 for unlimited"))
]
cfg.CONF.register_opts(quota_packet_filter_opts, 'QUOTAS')


class PacketFilterNotFound(exceptions.NotFound):
    message = _("PacketFilter %(id)s could not be found")


class PacketFilterIpVersionNonSupported(exceptions.BadRequest):
    message = _("IP version %(version)s is not supported for %(field)s "
                "(%(value)s is specified)")


class PacketFilterInvalidPriority(exceptions.BadRequest):
    message = _("Packet Filter priority should be %(min)s-%(max)s (included)")


class PacketFilterUpdateNotSupported(exceptions.BadRequest):
    message = _("%(field)s field cannot be updated")


class PacketFilterDuplicatedPriority(exceptions.BadRequest):
    message = _("The backend does not support duplicated priority. "
                "Priority %(priority)s is in use")


class PacketFilterEtherTypeProtocolMismatch(exceptions.Conflict):
    message = _("Ether Type '%(eth_type)s' conflicts with protocol "
                "'%(protocol)s'. Update or clear protocol before "
                "changing ether type.")


def convert_to_int_dec_and_hex(data):
    try:
        return int(data, 0)
    except (ValueError, TypeError):
        pass
    try:
        return int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not a integer") % data
        raise exceptions.InvalidInput(error_message=msg)


def convert_to_int_or_none(data):
    if data is None:
        return
    return convert_to_int_dec_and_hex(data)


PROTO_NAME_ARP = 'arp'
SUPPORTED_PROTOCOLS = [constants.PROTO_NAME_ICMP,
                       constants.PROTO_NAME_TCP,
                       constants.PROTO_NAME_UDP,
                       PROTO_NAME_ARP]
ALLOW_ACTIONS = ['allow', 'accept']
DROP_ACTIONS = ['drop', 'deny']
SUPPORTED_ACTIONS = ALLOW_ACTIONS + DROP_ACTIONS

ALIAS = 'packet-filter'
RESOURCE = 'packet_filter'
COLLECTION = 'packet_filters'
PACKET_FILTER_ACTION_REGEX = '(?i)^(%s)$' % '|'.join(SUPPORTED_ACTIONS)
PACKET_FILTER_PROTOCOL_REGEX = ('(?i)^(%s|0x[0-9a-fA-F]+|[0-9]+|)$' %
                                '|'.join(SUPPORTED_PROTOCOLS))
PACKET_FILTER_ATTR_PARAMS = {
    'id': {'allow_post': False, 'allow_put': False,
           'validate': {'type:uuid': None},
           'is_visible': True},
    'name': {'allow_post': True, 'allow_put': True, 'default': '',
             'validate': {'type:string': attributes.NAME_MAX_LEN},
             'is_visible': True},
    'tenant_id': {'allow_post': True, 'allow_put': False,
                  'validate': {'type:string': attributes.TENANT_ID_MAX_LEN},
                  'required_by_policy': True,
                  'is_visible': True},
    'network_id': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True},
    'admin_state_up': {'allow_post': True, 'allow_put': True,
                       'default': True,
                       'convert_to': attributes.convert_to_boolean,
                       'is_visible': True},
    'status': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
    'action': {'allow_post': True, 'allow_put': True,
               'validate': {'type:regex': PACKET_FILTER_ACTION_REGEX},
               'is_visible': True},
    'priority': {'allow_post': True, 'allow_put': True,
                 'convert_to': convert_to_int_dec_and_hex,
                 'is_visible': True},
    'in_port': {'allow_post': True, 'allow_put': False,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:uuid': None},
                'is_visible': True},
    'src_mac': {'allow_post': True, 'allow_put': True,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:mac_address_or_none': None},
                'is_visible': True},
    'dst_mac': {'allow_post': True, 'allow_put': True,
                'default': attributes.ATTR_NOT_SPECIFIED,
                'validate': {'type:mac_address_or_none': None},
                'is_visible': True},
    'eth_type': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'convert_to': convert_to_int_or_none,
                 'is_visible': True},
    'src_cidr': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:subnet_or_none': None},
                 'is_visible': True},
    'dst_cidr': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:subnet_or_none': None},
                 'is_visible': True},
    'protocol': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'validate': {'type:regex_or_none':
                              PACKET_FILTER_PROTOCOL_REGEX},
                 'is_visible': True},
    'src_port': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'convert_to': convert_to_int_or_none,
                 'is_visible': True},
    'dst_port': {'allow_post': True, 'allow_put': True,
                 'default': attributes.ATTR_NOT_SPECIFIED,
                 'convert_to': convert_to_int_or_none,
                 'is_visible': True},
}
PACKET_FILTER_ATTR_MAP = {COLLECTION: PACKET_FILTER_ATTR_PARAMS}


class Packetfilter(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return ALIAS

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "PacketFilters on OFC"

    @classmethod
    def get_updated(cls):
        return "2013-07-16T00:00:00+09:00"

    @classmethod
    def get_resources(cls):
        qresource = quota.CountableResource(RESOURCE,
                                            quota._count_resource,
                                            'quota_%s' % RESOURCE)
        quota.QUOTAS.register_resource(qresource)

        resource = base.create_resource(COLLECTION, RESOURCE,
                                        manager.NeutronManager.get_plugin(),
                                        PACKET_FILTER_ATTR_PARAMS)
        pf_ext = extensions.ResourceExtension(
            COLLECTION, resource, attr_map=PACKET_FILTER_ATTR_PARAMS)
        return [pf_ext]

    def get_extended_resources(self, version):
        if version == "2.0":
            return PACKET_FILTER_ATTR_MAP
        else:
            return {}
