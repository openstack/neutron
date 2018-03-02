# Copyright 2013 Cisco Systems, Inc.
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

"""
Common utilities and helper functions for OpenStack Networking Plugins.
These utils are private and for neutron internal use only.
"""

from neutron_lib.api import attributes as lib_attrs
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from oslo_config import cfg
import webob.exc


# TODO(boden): remove when consuming I2c0e4ef03425ba0bb2651ae3e68d6c8cde7b8f90

def _fixup_res_dict(context, attr_name, res_dict, check_allow_post=True):
    attr_info = lib_attrs.RESOURCES[attr_name]
    attr_ops = lib_attrs.AttributeInfo(attr_info)
    try:
        attr_ops.populate_project_id(context, res_dict, True)
        lib_attrs.populate_project_info(attr_info)
        attr_ops.verify_attributes(res_dict)
    except webob.exc.HTTPBadRequest as e:
        # convert webob exception into ValueError as these functions are
        # for internal use. webob exception doesn't make sense.
        raise ValueError(e.detail)
    attr_ops.fill_post_defaults(res_dict, check_allow_post=check_allow_post)
    attr_ops.convert_values(res_dict)
    return res_dict


def create_network(core_plugin, context, net, check_allow_post=True):
    net_data = _fixup_res_dict(context, net_def.COLLECTION_NAME,
                               net.get('network', {}),
                               check_allow_post=check_allow_post)
    return core_plugin.create_network(context, {'network': net_data})


def create_subnet(core_plugin, context, subnet, check_allow_post=True):
    subnet_data = _fixup_res_dict(context, subnet_def.COLLECTION_NAME,
                                  subnet.get('subnet', {}),
                                  check_allow_post=check_allow_post)
    return core_plugin.create_subnet(context, {'subnet': subnet_data})


def create_port(core_plugin, context, port, check_allow_post=True):
    port_data = _fixup_res_dict(context, port_def.COLLECTION_NAME,
                                port.get('port', {}),
                                check_allow_post=check_allow_post)
    return core_plugin.create_port(context, {'port': port_data})


# TODO(boden): consume with I73f5e8ad7a1a83392094db846d18964d811b8bb2
def get_deployment_physnet_mtu():
    """Retrieves global physical network MTU setting.

    Plugins should use this function to retrieve the MTU set by the operator
    that is equal to or less than the MTU of their nodes' physical interfaces.
    Note that it is the responsibility of the plugin to deduct the value of
    any encapsulation overhead required before advertising it to VMs.
    """
    return cfg.CONF.global_physnet_mtu
