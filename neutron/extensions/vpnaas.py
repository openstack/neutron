# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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
#
# @author: Swaminathan Vasudevan, Hewlett-Packard.

import abc

from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.plugins.common import constants
from neutron import quota
from neutron.services.service_base import ServicePluginBase


class VPNServiceNotFound(qexception.NotFound):
    message = _("VPNService %(vpnservice_id)s could not be found")


class IPsecSiteConnectionNotFound(qexception.NotFound):
    message = _("ipsec_site_connection %(ipsecsite_conn_id)s not found")


class IPsecSiteConnectionDpdIntervalValueError(qexception.InvalidInput):
    message = _("ipsec_site_connection %(attribute_a)s less than dpd_interval")


class IKEPolicyNotFound(qexception.NotFound):
    message = _("IKEPolicy %(ikepolicy_id)s could not be found")


class IPsecPolicyNotFound(qexception.NotFound):
    message = _("IPsecPolicy %(ipsecpolicy_id)s could not be found")


class IKEPolicyInUse(qexception.InUse):
    message = _("IKEPolicy %(ikepolicy_id)s is still in use")


class VPNServiceInUse(qexception.InUse):
    message = _("VPNService %(vpnservice_id)s is still in use")


class VPNStateInvalid(qexception.BadRequest):
    message = _("Invalid state %(state)s of vpnaas resource %(id)s")


class IPsecPolicyInUse(qexception.InUse):
    message = _("IPsecPolicy %(ipsecpolicy_id)s is still in use")


vpn_supported_initiators = ['bi-directional', 'response-only']
vpn_supported_encryption_algorithms = ['3des', 'aes-128',
                                       'aes-192', 'aes-256']
vpn_dpd_supported_actions = [
    'hold', 'clear', 'restart', 'restart-by-peer', 'disabled'
]
vpn_supported_transform_protocols = ['esp', 'ah', 'ah-esp']
vpn_supported_encapsulation_mode = ['tunnel', 'transport']
vpn_supported_lifetime_units = ['seconds', 'kilobytes']
vpn_supported_pfs = ['group2', 'group5', 'group14']
vpn_supported_ike_versions = ['v1', 'v2']
vpn_supported_auth_mode = ['psk']
vpn_supported_auth_algorithms = ['sha1']
vpn_supported_phase1_negotiation_mode = ['main']


RESOURCE_ATTRIBUTE_MAP = {

    'vpnservices': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },

    'ipsec_site_connections': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'peer_address': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'peer_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'peer_cidrs': {'allow_post': True, 'allow_put': True,
                       'convert_to': attr.convert_to_list,
                       'validate': {'type:subnet_list': None},
                       'is_visible': True},
        'route_mode': {'allow_post': False, 'allow_put': False,
                       'default': 'static',
                       'is_visible': True},
        'mtu': {'allow_post': True, 'allow_put': True,
                'default': '1500',
                'validate': {'type:non_negative': None},
                'convert_to': attr.convert_to_int,
                'is_visible': True},
        'initiator': {'allow_post': True, 'allow_put': True,
                      'default': 'bi-directional',
                      'validate': {'type:values': vpn_supported_initiators},
                      'is_visible': True},
        'auth_mode': {'allow_post': False, 'allow_put': False,
                      'default': 'psk',
                      'validate': {'type:values': vpn_supported_auth_mode},
                      'is_visible': True},
        'psk': {'allow_post': True, 'allow_put': True,
                'validate': {'type:string': None},
                'is_visible': True},
        'dpd': {'allow_post': True, 'allow_put': True,
                'convert_to': attr.convert_none_to_empty_dict,
                'is_visible': True,
                'default': {},
                'validate': {
                    'type:dict_or_empty': {
                        'actions': {
                            'type:values': vpn_dpd_supported_actions,
                        },
                        'interval': {
                            'type:non_negative': None
                        },
                        'timeout': {
                            'type:non_negative': None
                        }}}},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'vpnservice_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
        'ikepolicy_id': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:uuid': None},
                         'is_visible': True},
        'ipsecpolicy_id': {'allow_post': True, 'allow_put': False,
                           'validate': {'type:uuid': None},
                           'is_visible': True}
    },

    'ipsecpolicies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'transform_protocol': {
            'allow_post': True,
            'allow_put': True,
            'default': 'esp',
            'validate': {
                'type:values': vpn_supported_transform_protocols},
            'is_visible': True},
        'auth_algorithm': {
            'allow_post': True,
            'allow_put': True,
            'default': 'sha1',
            'validate': {
                'type:values': vpn_supported_auth_algorithms
            },
            'is_visible': True},
        'encryption_algorithm': {
            'allow_post': True,
            'allow_put': True,
            'default': 'aes-128',
            'validate': {
                'type:values': vpn_supported_encryption_algorithms
            },
            'is_visible': True},
        'encapsulation_mode': {
            'allow_post': True,
            'allow_put': True,
            'default': 'tunnel',
            'validate': {
                'type:values': vpn_supported_encapsulation_mode
            },
            'is_visible': True},
        'lifetime': {'allow_post': True, 'allow_put': True,
                     'convert_to': attr.convert_none_to_empty_dict,
                     'default': {},
                     'validate': {
                         'type:dict_or_empty': {
                             'units': {
                                 'type:values': vpn_supported_lifetime_units,
                             },
                             'value': {
                                 'type:non_negative': None}}},
                     'is_visible': True},
        'pfs': {'allow_post': True, 'allow_put': True,
                'default': 'group5',
                'validate': {'type:values': vpn_supported_pfs},
                'is_visible': True}
    },

    'ikepolicies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'auth_algorithm': {'allow_post': True, 'allow_put': True,
                           'default': 'sha1',
                           'validate': {
                               'type:values': vpn_supported_auth_algorithms},
                           'is_visible': True},
        'encryption_algorithm': {
            'allow_post': True, 'allow_put': True,
            'default': 'aes-128',
            'validate': {'type:values': vpn_supported_encryption_algorithms},
            'is_visible': True},
        'phase1_negotiation_mode': {
            'allow_post': True, 'allow_put': True,
            'default': 'main',
            'validate': {
                'type:values': vpn_supported_phase1_negotiation_mode
            },
            'is_visible': True},
        'lifetime': {'allow_post': True, 'allow_put': True,
                     'convert_to': attr.convert_none_to_empty_dict,
                     'default': {},
                     'validate': {
                         'type:dict_or_empty': {
                             'units': {
                                 'type:values': vpn_supported_lifetime_units,
                             },
                             'value': {
                                 'type:non_negative': None,
                             }}},
                     'is_visible': True},
        'ike_version': {'allow_post': True, 'allow_put': True,
                        'default': 'v1',
                        'validate': {
                            'type:values': vpn_supported_ike_versions},
                        'is_visible': True},
        'pfs': {'allow_post': True, 'allow_put': True,
                'default': 'group5',
                'validate': {'type:values': vpn_supported_pfs},
                'is_visible': True}
    }
}


class Vpnaas(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "VPN service"

    @classmethod
    def get_alias(cls):
        return "vpnaas"

    @classmethod
    def get_description(cls):
        return "Extension for VPN service"

    @classmethod
    def get_namespace(cls):
        return "https://wiki.openstack.org/Neutron/VPNaaS"

    @classmethod
    def get_updated(cls):
        return "2013-05-29T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mapping = {
            'ikepolicies': 'ikepolicy',
            'ipsecpolicies': 'ipsecpolicy'
        }
        my_plurals = []
        for plural in RESOURCE_ATTRIBUTE_MAP:
            singular = plural_mapping.get(plural, plural[:-1])
            my_plurals.append((plural, singular))
        my_plurals.append(('peer_cidrs', 'peer_cidr'))
        attr.PLURALS.update(dict(my_plurals))
        resources = []
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.VPN]
        for collection_name in RESOURCE_ATTRIBUTE_MAP:
            resource_name = plural_mapping.get(
                collection_name, collection_name[:-1])
            params = RESOURCE_ATTRIBUTE_MAP[collection_name]
            collection_name = collection_name.replace('_', '-')

            quota.QUOTAS.register_resource_by_name(resource_name)
            controller = base.create_resource(
                collection_name, resource_name, plugin, params,
                allow_pagination=cfg.CONF.allow_pagination,
                allow_sorting=cfg.CONF.allow_sorting)

            resource = extensions.ResourceExtension(
                collection_name,
                controller,
                path_prefix=constants.COMMON_PREFIXES[constants.VPN],
                attr_map=params)
            resources.append(resource)
        return resources

    @classmethod
    def get_plugin_interface(cls):
        return VPNPluginBase

    def update_attributes_map(self, attributes):
        super(Vpnaas, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class VPNPluginBase(ServicePluginBase):
    __metaclass__ = abc.ABCMeta

    def get_plugin_name(self):
        return constants.VPN

    def get_plugin_type(self):
        return constants.VPN

    def get_plugin_description(self):
        return 'VPN service plugin'

    @abc.abstractmethod
    def get_vpnservices(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_vpnservice(self, context, vpnservice_id, fields=None):
        pass

    @abc.abstractmethod
    def create_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        pass

    @abc.abstractmethod
    def delete_vpnservice(self, context, vpnservice_id):
        pass

    @abc.abstractmethod
    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_ipsec_site_connection(self, context,
                                  ipsecsite_conn_id, fields=None):
        pass

    @abc.abstractmethod
    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def update_ipsec_site_connection(self, context,
                                     ipsecsite_conn_id, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def delete_ipsec_site_connection(self, context, ipsecsite_conn_id):
        pass

    @abc.abstractmethod
    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_ikepolicies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ikepolicy(self, context, ikepolicy):
        pass

    @abc.abstractmethod
    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        pass

    @abc.abstractmethod
    def delete_ikepolicy(self, context, ikepolicy_id):
        pass

    @abc.abstractmethod
    def get_ipsecpolicies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    @abc.abstractmethod
    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        pass

    @abc.abstractmethod
    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        pass
