# Copyright 2014 OpenStack Foundation.
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


import abc

from oslo.config import cfg
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as nexception
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import service_base

# TODO(dougw) - stop hard-coding these constants when this extension moves
# to the neutron-lbaas repo
#from neutron.services.loadbalancer import constants as lb_const

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'
SUPPORTED_LB_ALGORITHMS = (LB_METHOD_LEAST_CONNECTIONS, LB_METHOD_ROUND_ROBIN,
                           LB_METHOD_SOURCE_IP)

PROTOCOL_TCP = 'TCP'
PROTOCOL_HTTP = 'HTTP'
PROTOCOL_HTTPS = 'HTTPS'
SUPPORTED_PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_HTTPS, PROTOCOL_HTTP)


HEALTH_MONITOR_PING = 'PING'
HEALTH_MONITOR_TCP = 'TCP'
HEALTH_MONITOR_HTTP = 'HTTP'
HEALTH_MONITOR_HTTPS = 'HTTPS'
SUPPORTED_HEALTH_MONITOR_TYPES = (HEALTH_MONITOR_HTTP, HEALTH_MONITOR_HTTPS,
                                  HEALTH_MONITOR_PING, HEALTH_MONITOR_TCP)


SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'
SUPPORTED_SP_TYPES = (SESSION_PERSISTENCE_SOURCE_IP,
                      SESSION_PERSISTENCE_HTTP_COOKIE,
                      SESSION_PERSISTENCE_APP_COOKIE)


# Loadbalancer Exceptions
# This exception is only for a workaround when having v1 and v2 lbaas extension
# and plugins enabled
class RequiredAttributeNotSpecified(nexception.BadRequest):
    message = _("Required attribute %(attr_name)s not specified")


class EntityNotFound(nexception.NotFound):
    message = _("%(name)s %(id)s could not be found")


class DelayOrTimeoutInvalid(nexception.BadRequest):
    message = _("Delay must be greater than or equal to timeout")


class EntityInUse(nexception.InUse):
    message = _("%(entity_using)s %(id)s is using this %(entity_in_use)s")


class LoadBalancerListenerProtocolPortExists(nexception.Conflict):
    message = _("Load Balancer %(lb_id)s already has a listener with "
                "protocol_port of %(protocol_port)s")


class ListenerPoolProtocolMismatch(nexception.Conflict):
    message = _("Listener protocol %(listener_proto)s and pool protocol "
                "%(pool_proto)s are not compatible.")


class AttributeIDImmutable(nexception.NeutronException):
    message = _("Cannot change %(attribute)s if one already exists")


class StateInvalid(nexception.NeutronException):
    message = _("Invalid state %(state)s of loadbalancer resource %(id)s")


class MemberNotFoundForPool(nexception.NotFound):
    message = _("Member %(member_id)s could not be found in pool %(pool_id)s")


class MemberExists(nexception.Conflict):
    message = _("Member with address %(address)s and protocol_port %(port)s "
                "already present in pool %(pool)s")


class MemberAddressTypeSubnetTypeMismatch(nexception.NeutronException):
    message = _("Member with address %(address)s and subnet %(subnet_id) "
                " have mismatched IP versions")


class DriverError(nexception.NeutronException):
    message = _("An error happened in the driver")


class LBConfigurationUnsupported(nexception.NeutronException):
    message = _("Load balancer %(load_balancer_id)s configuration is not"
                "supported by driver %(driver_name)s")


RESOURCE_ATTRIBUTE_MAP = {
    'loadbalancers': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'vip_subnet_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
        'vip_address': {'allow_post': True, 'allow_put': False,
                        'default': attr.ATTR_NOT_SPECIFIED,
                        'validate': {'type:ip_address_or_none': None},
                        'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },
    'listeners': {
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
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'loadbalancer_id': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:uuid_or_none': None},
                            'default': attr.ATTR_NOT_SPECIFIED,
                            'is_visible': True},
        'default_pool_id': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:uuid_or_none': None},
                            'default': attr.ATTR_NOT_SPECIFIED,
                            'is_visible': True},
        'connection_limit': {'allow_post': True, 'allow_put': True,
                             'default': -1,
                             'convert_to': attr.convert_to_int,
                             'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:values': SUPPORTED_PROTOCOLS},
                     'is_visible': True},
        'protocol_port': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:range': [0, 65535]},
                          'convert_to': attr.convert_to_int,
                          'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },
    'pools': {
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
        'healthmonitor_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:string_or_none': None},
                             'is_visible': True,
                             'default': attr.ATTR_NOT_SPECIFIED},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:values': SUPPORTED_PROTOCOLS},
                     'is_visible': True},
        'lb_algorithm': {'allow_post': True, 'allow_put': True,
                         'validate': {
                             'type:values': SUPPORTED_LB_ALGORITHMS},
                         # TODO(brandon-logan) remove when old API is removed
                         # because this is a required attribute)
                         'default': attr.ATTR_NOT_SPECIFIED,
                         'is_visible': True},
        'session_persistence': {
            'allow_post': True, 'allow_put': True,
            'convert_to': attr.convert_none_to_empty_dict,
            'default': {},
            'validate': {
                'type:dict_or_empty': {
                    'type': {
                        'type:values': SUPPORTED_SP_TYPES,
                        'required': True},
                    'cookie_name': {'type:string': None,
                                    'required': False}}},
            'is_visible': True},
        'members': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },
    'healthmonitors': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'type': {'allow_post': True, 'allow_put': False,
                 'validate': {
                     'type:values': SUPPORTED_HEALTH_MONITOR_TYPES},
                 'is_visible': True},
        'delay': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:non_negative': None},
                  'convert_to': attr.convert_to_int,
                  'is_visible': True},
        'timeout': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:non_negative': None},
                    'convert_to': attr.convert_to_int,
                    'is_visible': True},
        'max_retries': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:range': [1, 10]},
                        'convert_to': attr.convert_to_int,
                        'is_visible': True},
        'http_method': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': 'GET',
                        'is_visible': True},
        'url_path': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'default': '/',
                     'is_visible': True},
        'expected_codes': {
            'allow_post': True,
            'allow_put': True,
            'validate': {
                'type:regex': r'^(\d{3}(\s*,\s*\d{3})*)$|^(\d{3}-\d{3})$'
            },
            'default': '200',
            'is_visible': True
        },
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    }
}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'members': {
        'parent': {'collection_name': 'pools',
                   'member_name': 'pool'},
        'parameters': {
            'id': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True,
                   'primary_key': True},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:string': None},
                          'required_by_policy': True,
                          'is_visible': True},
            'address': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:ip_address': None},
                        'is_visible': True},
            'protocol_port': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:range': [0, 65535]},
                              'convert_to': attr.convert_to_int,
                              'is_visible': True},
            'weight': {'allow_post': True, 'allow_put': True,
                       'default': 1,
                       'validate': {'type:range': [0, 256]},
                       'convert_to': attr.convert_to_int,
                       'is_visible': True},
            'admin_state_up': {'allow_post': True, 'allow_put': True,
                               'default': True,
                               'convert_to': attr.convert_to_boolean,
                               'is_visible': True},
            'status': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
            'subnet_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},

        }
    }
}


lbaasv2_quota_opts = [
    cfg.IntOpt('quota_loadbalancer',
               default=10,
               help=_('Number of LoadBalancers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_listener',
               default=-1,
               help=_('Number of Loadbalancer Listeners allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_pool',
               default=10,
               help=_('Number of pools allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_member',
               default=-1,
               help=_('Number of pool members allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_healthmonitor',
               default=-1,
               help=_('Number of health monitors allowed per tenant. '
                      'A negative value means unlimited.'))
]
cfg.CONF.register_opts(lbaasv2_quota_opts, 'QUOTAS')


class Loadbalancerv2(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "LoadBalancing service v2"

    @classmethod
    def get_alias(cls):
        return "lbaasv2"

    @classmethod
    def get_description(cls):
        return "Extension for LoadBalancing service v2"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/LBaaS/API_2.0"

    @classmethod
    def get_updated(cls):
        return "2014-06-18T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        action_map = {'loadbalancer': {'stats': 'GET'}}
        plural_mappings['members'] = 'member'
        attr.PLURALS.update(plural_mappings)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.LOADBALANCERV2,
            action_map=action_map,
            register_quota=True)
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCERV2]
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent,
                                              allow_pagination=True,
                                              allow_sorting=True)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=constants.COMMON_PREFIXES[
                    constants.LOADBALANCERV2],
                attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return LoadBalancerPluginBaseV2

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Loadbalancerv2, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class LoadBalancerPluginBaseV2(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.LOADBALANCERV2

    def get_plugin_type(self):
        return constants.LOADBALANCERV2

    def get_plugin_description(self):
        return 'LoadBalancer service plugin v2'

    @abc.abstractmethod
    def get_loadbalancers(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_loadbalancer(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_loadbalancer(self, context, loadbalancer):
        pass

    @abc.abstractmethod
    def update_loadbalancer(self, context, id, loadbalancer):
        pass

    @abc.abstractmethod
    def delete_loadbalancer(self, context, id):
        pass

    @abc.abstractmethod
    def create_listener(self, context, listener):
        pass

    @abc.abstractmethod
    def get_listener(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_listeners(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_listener(self, context, id, listener):
        pass

    @abc.abstractmethod
    def delete_listener(self, context, id):
        pass

    @abc.abstractmethod
    def get_pools(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_pool(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_pool(self, context, pool):
        pass

    @abc.abstractmethod
    def update_pool(self, context, id, pool):
        pass

    @abc.abstractmethod
    def delete_pool(self, context, id):
        pass

    @abc.abstractmethod
    def stats(self, context, loadbalancer_id):
        pass

    @abc.abstractmethod
    def get_pool_members(self, context, pool_id,
                         filters=None,
                         fields=None):
        pass

    @abc.abstractmethod
    def get_pool_member(self, context, id, pool_id,
                        fields=None):
        pass

    @abc.abstractmethod
    def create_pool_member(self, context, member,
                           pool_id):
        pass

    @abc.abstractmethod
    def update_pool_member(self, context, member, id,
                           pool_id):
        pass

    @abc.abstractmethod
    def delete_pool_member(self, context, id, pool_id):
        pass

    @abc.abstractmethod
    def get_healthmonitors(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_healthmonitor(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_healthmonitor(self, context, healthmonitor):
        pass

    @abc.abstractmethod
    def update_healthmonitor(self, context, id, healthmonitor):
        pass

    @abc.abstractmethod
    def delete_healthmonitor(self, context, id):
        pass

    @abc.abstractmethod
    def get_members(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_member(self, context, id, fields=None):
        pass
