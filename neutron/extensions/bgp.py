# Copyright 2016 Hewlett Packard Development Coompany LP
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
#

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper as rh
from neutron.common import exceptions
from neutron.services.bgp.common import constants as bgp_consts

BGP_EXT_ALIAS = 'bgp'
BGP_SPEAKER_RESOURCE_NAME = 'bgp-speaker'
BGP_SPEAKER_BODY_KEY_NAME = 'bgp_speaker'
BGP_PEER_BODY_KEY_NAME = 'bgp_peer'


RESOURCE_ATTRIBUTE_MAP = {
    BGP_SPEAKER_RESOURCE_NAME + 's': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'local_as': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:range': (bgp_consts.MIN_ASNUM,
                                                 bgp_consts.MAX_ASNUM)},
                     'is_visible': True, 'default': None,
                     'required_by_policy': False,
                     'enforce_policy': False},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True, 'default': None,
                       'required_by_policy': False,
                       'enforce_policy': False},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': False,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
        'peers': {'allow_post': False, 'allow_put': False,
                  'validate': {'type:uuid_list': None},
                  'is_visible': True, 'default': [],
                  'required_by_policy': False,
                  'enforce_policy': True},
        'networks': {'allow_post': False, 'allow_put': False,
                     'validate': {'type:uuid_list': None},
                     'is_visible': True, 'default': [],
                     'required_by_policy': False,
                     'enforce_policy': True},
        'advertise_floating_ip_host_routes': {
                                      'allow_post': True,
                                      'allow_put': True,
                                      'convert_to': attr.convert_to_boolean,
                                      'validate': {'type:boolean': None},
                                      'is_visible': True, 'default': True,
                                      'required_by_policy': False,
                                      'enforce_policy': True},
        'advertise_tenant_networks': {
                                      'allow_post': True,
                                      'allow_put': True,
                                      'convert_to': attr.convert_to_boolean,
                                      'validate': {'type:boolean': None},
                                      'is_visible': True, 'default': True,
                                      'required_by_policy': False,
                                      'enforce_policy': True},
    },
    'bgp-peers': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'peer_ip': {'allow_post': True, 'allow_put': False,
                    'required_by_policy': True,
                    'validate': {'type:ip_address': None},
                    'is_visible': True},
        'remote_as': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:range': (bgp_consts.MIN_ASNUM,
                                                 bgp_consts.MAX_ASNUM)},
                     'is_visible': True, 'default': None,
                     'required_by_policy': False,
                     'enforce_policy': False},
        'auth_type': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:values':
                                   bgp_consts.SUPPORTED_AUTH_TYPES},
                      'is_visible': True},
        'password': {'allow_post': True, 'allow_put': True,
                     'required_by_policy': True,
                     'validate': {'type:string_or_none': None},
                     'is_visible': False,
                     'default': None},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': False,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True}
    }
}


# Dynamic Routing Exceptions
class BgpSpeakerNotFound(exceptions.NotFound):
    message = _("BGP speaker %(id)s could not be found.")


class BgpPeerNotFound(exceptions.NotFound):
    message = _("BGP peer %(id)s could not be found.")


class BgpPeerNotAuthenticated(exceptions.NotFound):
    message = _("BGP peer %(bgp_peer_id)s not authenticated.")


class BgpSpeakerPeerNotAssociated(exceptions.NotFound):
    message = _("BGP peer %(bgp_peer_id)s is not associated with "
                "BGP speaker %(bgp_speaker_id)s.")


class BgpSpeakerNetworkNotAssociated(exceptions.NotFound):
    message = _("Network %(network_id)s is not associated with "
                "BGP speaker %(bgp_speaker_id)s.")


class BgpSpeakerNetworkBindingError(exceptions.Conflict):
    message = _("Network %(network_id)s is already bound to BgpSpeaker "
                "%(bgp_speaker_id)s.")


class NetworkNotBound(exceptions.NotFound):
    message = _("Network %(network_id)s is not bound to a BgpSpeaker.")


class DuplicateBgpPeerIpException(exceptions.Conflict):
    _message = _("BGP Speaker %(bgp_speaker_id)s is already configured to "
                 "peer with a BGP Peer at %(peer_ip)s, it cannot peer with "
                 "BGP Peer %(bgp_peer_id)s.")


class InvalidBgpPeerMd5Authentication(exceptions.BadRequest):
    message = _("A password must be supplied when using auth_type md5.")


class NetworkNotBoundForIpVersion(NetworkNotBound):
    message = _("Network %(network_id)s is not bound to a IPv%(ip_version)s "
                "BgpSpeaker.")


class Bgp(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron BGP Dynamic Routing Extension"

    @classmethod
    def get_alias(cls):
        return BGP_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return("Discover and advertise routes for Neutron prefixes "
               "dynamically via BGP")

    @classmethod
    def get_updated(cls):
        return "2014-07-01T15:37:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = rh.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {BGP_SPEAKER_RESOURCE_NAME:
                      {'add_bgp_peer': 'PUT',
                       'remove_bgp_peer': 'PUT',
                       'add_gateway_network': 'PUT',
                       'remove_gateway_network': 'PUT',
                       'get_advertised_routes': 'GET'}}
        exts = rh.build_resource_info(plural_mappings,
                                      RESOURCE_ATTRIBUTE_MAP,
                                      BGP_EXT_ALIAS,
                                      action_map=action_map)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}

    def update_attributes_map(self, attributes):
        super(Bgp, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)
