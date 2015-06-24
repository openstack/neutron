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

import abc

from oslo_config import cfg

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import resource_helper

GATEWAY_RESOURCE_NAME = "network_gateway"
DEVICE_RESOURCE_NAME = "gateway_device"
# Use dash for alias and collection name
EXT_ALIAS = GATEWAY_RESOURCE_NAME.replace('_', '-')
NETWORK_GATEWAYS = "%ss" % EXT_ALIAS
GATEWAY_DEVICES = "%ss" % DEVICE_RESOURCE_NAME.replace('_', '-')
DEVICE_ID_ATTR = 'id'
IFACE_NAME_ATTR = 'interface_name'


# TODO(salv-orlando): This type definition is duplicated into
# openstack/vmware-nsx. This temporary duplication should be removed once the
# plugin decomposition is finished.
# Allowed network types for the NSX Plugin
class NetworkTypes(object):
    """Allowed provider network types for the NSX Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'

# Attribute Map for Network Gateway Resource
# TODO(salvatore-orlando): add admin state as other neutron resources
RESOURCE_ATTRIBUTE_MAP = {
    NETWORK_GATEWAYS: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attributes.NAME_MAX_LEN},
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
                      'validate': {'type:string':
                                   attributes.TENANT_ID_MAX_LEN},
                      'required_by_policy': True,
                      'is_visible': True}
    },
    GATEWAY_DEVICES: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attributes.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'client_certificate': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:string': None},
                               'is_visible': True},
        'connector_type': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:connector_type': None},
                           'is_visible': True},
        'connector_ip': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:ip_address': None},
                         'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string':
                                   attributes.TENANT_ID_MAX_LEN},
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
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


def _validate_connector_type(data, valid_values=None):
    if not data:
        # A connector type is compulsory
        msg = _("A connector type is required to create a gateway device")
        return msg
    connector_types = (valid_values if valid_values else
                       [NetworkTypes.GRE,
                        NetworkTypes.STT,
                        NetworkTypes.BRIDGE,
                        'ipsec%s' % NetworkTypes.GRE,
                        'ipsec%s' % NetworkTypes.STT])
    if data not in connector_types:
        msg = _("Unknown connector type: %s") % data
        return msg


nw_gw_quota_opts = [
    cfg.IntOpt('quota_network_gateway',
               default=5,
               help=_('Number of network gateways allowed per tenant, '
                      '-1 for unlimited'))
]

cfg.CONF.register_opts(nw_gw_quota_opts, 'QUOTAS')

attributes.validators['type:device_list'] = _validate_device_list
attributes.validators['type:connector_type'] = _validate_connector_type


class Networkgw(extensions.ExtensionDescriptor):
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
    def get_updated(cls):
        return "2014-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""

        member_actions = {
            GATEWAY_RESOURCE_NAME.replace('_', '-'): {
                'connect_network': 'PUT',
                'disconnect_network': 'PUT'}}

        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)

        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   None,
                                                   action_map=member_actions,
                                                   register_quota=True,
                                                   translate_name=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class NetworkGatewayPluginBase(object):

    @abc.abstractmethod
    def create_network_gateway(self, context, network_gateway):
        pass

    @abc.abstractmethod
    def update_network_gateway(self, context, id, network_gateway):
        pass

    @abc.abstractmethod
    def get_network_gateway(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_network_gateway(self, context, id):
        pass

    @abc.abstractmethod
    def get_network_gateways(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        pass

    @abc.abstractmethod
    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        pass

    @abc.abstractmethod
    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        pass

    @abc.abstractmethod
    def create_gateway_device(self, context, gateway_device):
        pass

    @abc.abstractmethod
    def update_gateway_device(self, context, id, gateway_device):
        pass

    @abc.abstractmethod
    def delete_gateway_device(self, context, id):
        pass

    @abc.abstractmethod
    def get_gateway_device(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_gateway_devices(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        pass
