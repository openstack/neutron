# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 VMware.  All rights reserved.
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

from abc import abstractmethod

from oslo.config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron import manager
from neutron import quota


RESOURCE_NAME = "network_gateway"
# Use dash for alias and collection name
EXT_ALIAS = RESOURCE_NAME.replace('_', '-')
COLLECTION_NAME = "%ss" % EXT_ALIAS
DEVICE_ID_ATTR = 'id'
IFACE_NAME_ATTR = 'interface_name'

# Attribute Map for Network Gateway Resource
# TODO(salvatore-orlando): add admin state as other neutron resources
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'default': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'devices': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:device_list': None},
                    'is_visible': True},
        'ports': {'allow_post': False, 'allow_put': False,
                  'default': [],
                  'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True}
    }
}


def _validate_device_list(data, valid_values=None):
    """Validate the list of service definitions."""
    if not data:
        # Devices must be provided
        msg = _("Cannot create a gateway with an empty device list")
        return msg
    try:
        for device in data:
            key_specs = {DEVICE_ID_ATTR:
                         {'type:regex': attributes.UUID_PATTERN,
                          'required': True},
                         IFACE_NAME_ATTR:
                         {'type:string': None,
                          'required': False}}
            err_msg = attributes._validate_dict(
                device, key_specs=key_specs)
            if err_msg:
                return err_msg
            unexpected_keys = [key for key in device if key not in key_specs]
            if unexpected_keys:
                err_msg = (_("Unexpected keys found in device description:%s")
                           % ",".join(unexpected_keys))
                return err_msg
    except TypeError:
        return (_("%s: provided data are not iterable") %
                _validate_device_list.__name__)

nw_gw_quota_opts = [
    cfg.IntOpt('quota_network_gateway',
               default=5,
               help=_('Number of network gateways allowed per tenant, '
                      '-1 for unlimited'))
]

cfg.CONF.register_opts(nw_gw_quota_opts, 'QUOTAS')

attributes.validators['type:device_list'] = _validate_device_list


class Networkgw(object):
    """API extension for Layer-2 Gateway support.

    The Layer-2 gateway feature allows for connecting neutron networks
    with external networks at the layer-2 level. No assumption is made on
    the location of the external network, which might not even be directly
    reachable from the hosts where the VMs are deployed.

    This is achieved by instantiating 'network gateways', and then connecting
    Neutron network to them.
    """

    @classmethod
    def get_name(cls):
        return "Network Gateway"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Connects Neutron networks with external networks at layer 2."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/network-gateway/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = manager.NeutronManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME, dict())

        member_actions = {'connect_network': 'PUT',
                          'disconnect_network': 'PUT'}

        # register quotas for network gateways
        quota.QUOTAS.register_resource_by_name(RESOURCE_NAME)
        collection_name = COLLECTION_NAME.replace('_', '-')
        controller = base.create_resource(collection_name,
                                          RESOURCE_NAME,
                                          plugin, params,
                                          member_actions=member_actions)
        return [extensions.ResourceExtension(COLLECTION_NAME,
                                             controller,
                                             member_actions=member_actions)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class NetworkGatewayPluginBase(object):

    @abstractmethod
    def create_network_gateway(self, context, network_gateway):
        pass

    @abstractmethod
    def update_network_gateway(self, context, id, network_gateway):
        pass

    @abstractmethod
    def get_network_gateway(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_network_gateway(self, context, id):
        pass

    @abstractmethod
    def get_network_gateways(self, context, filters=None, fields=None):
        pass

    @abstractmethod
    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        pass

    @abstractmethod
    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        pass
