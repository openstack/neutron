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
"""

import hashlib

from neutron_lib import constants as n_const
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
import webob.exc

from neutron._i18n import _, _LI
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.plugins.common import constants as p_const

INTERFACE_HASH_LEN = 6
LOG = logging.getLogger(__name__)


def get_deployment_physnet_mtu():
    """Retrieves global physical network MTU setting.

    Plugins should use this function to retrieve the MTU set by the operator
    that is equal to or less than the MTU of their nodes' physical interfaces.
    Note that it is the responsibility of the plugin to deduct the value of
    any encapsulation overhead required before advertising it to VMs.
    """
    return cfg.CONF.global_physnet_mtu


def is_valid_vlan_tag(vlan):
    return p_const.MIN_VLAN_TAG <= vlan <= p_const.MAX_VLAN_TAG


def is_valid_gre_id(gre_id):
    return p_const.MIN_GRE_ID <= gre_id <= p_const.MAX_GRE_ID


def is_valid_vxlan_vni(vni):
    return p_const.MIN_VXLAN_VNI <= vni <= p_const.MAX_VXLAN_VNI


def is_valid_geneve_vni(vni):
    return p_const.MIN_GENEVE_VNI <= vni <= p_const.MAX_GENEVE_VNI


def verify_tunnel_range(tunnel_range, tunnel_type):
    """Raise an exception for invalid tunnel range or malformed range."""
    mappings = {p_const.TYPE_GRE: is_valid_gre_id,
                p_const.TYPE_VXLAN: is_valid_vxlan_vni,
                p_const.TYPE_GENEVE: is_valid_geneve_vni}
    if tunnel_type in mappings:
        for ident in tunnel_range:
            if not mappings[tunnel_type](ident):
                raise exceptions.NetworkTunnelRangeError(
                    tunnel_range=tunnel_range,
                    error=_("%(id)s is not a valid %(type)s identifier") %
                    {'id': ident, 'type': tunnel_type})
    if tunnel_range[1] < tunnel_range[0]:
        raise exceptions.NetworkTunnelRangeError(
            tunnel_range=tunnel_range,
            error=_("End of tunnel range is less "
                    "than start of tunnel range"))


def verify_vlan_range(vlan_range):
    """Raise an exception for invalid tags or malformed range."""
    for vlan_tag in vlan_range:
        if not is_valid_vlan_tag(vlan_tag):
            raise n_exc.NetworkVlanRangeError(
                vlan_range=vlan_range,
                error=_("%s is not a valid VLAN tag") % vlan_tag)
    if vlan_range[1] < vlan_range[0]:
        raise n_exc.NetworkVlanRangeError(
            vlan_range=vlan_range,
            error=_("End of VLAN range is less than start of VLAN range"))


def parse_network_vlan_range(network_vlan_range):
    """Interpret a string as network[:vlan_begin:vlan_end]."""
    entry = network_vlan_range.strip()
    if ':' in entry:
        try:
            network, vlan_min, vlan_max = entry.split(':')
            vlan_range = (int(vlan_min), int(vlan_max))
        except ValueError as ex:
            raise n_exc.NetworkVlanRangeError(vlan_range=entry, error=ex)
        if not network:
            raise n_exc.PhysicalNetworkNameError()
        verify_vlan_range(vlan_range)
        return network, vlan_range
    else:
        return entry, None


def parse_network_vlan_ranges(network_vlan_ranges_cfg_entries):
    """Interpret a list of strings as network[:vlan_begin:vlan_end] entries."""
    networks = {}
    for entry in network_vlan_ranges_cfg_entries:
        network, vlan_range = parse_network_vlan_range(entry)
        if vlan_range:
            networks.setdefault(network, []).append(vlan_range)
        else:
            networks.setdefault(network, [])
    return networks


def in_pending_status(status):
    return status in (p_const.PENDING_CREATE,
                      p_const.PENDING_UPDATE,
                      p_const.PENDING_DELETE)


def _fixup_res_dict(context, attr_name, res_dict, check_allow_post=True):
    attr_info = attributes.RESOURCE_ATTRIBUTE_MAP[attr_name]
    try:
        attributes.populate_tenant_id(context, res_dict, attr_info, True)
        attributes.verify_attributes(res_dict, attr_info)
    except webob.exc.HTTPBadRequest as e:
        # convert webob exception into ValueError as these functions are
        # for internal use. webob exception doesn't make sense.
        raise ValueError(e.detail)
    attributes.fill_default_value(attr_info, res_dict,
                                  check_allow_post=check_allow_post)
    attributes.convert_value(attr_info, res_dict)
    return res_dict


def create_network(core_plugin, context, net):
    net_data = _fixup_res_dict(context, attributes.NETWORKS,
                               net.get('network', {}))
    return core_plugin.create_network(context, {'network': net_data})


def create_subnet(core_plugin, context, subnet):
    subnet_data = _fixup_res_dict(context, attributes.SUBNETS,
                                  subnet.get('subnet', {}))
    return core_plugin.create_subnet(context, {'subnet': subnet_data})


def create_port(core_plugin, context, port, check_allow_post=True):
    port_data = _fixup_res_dict(context, attributes.PORTS,
                                port.get('port', {}),
                                check_allow_post=check_allow_post)
    return core_plugin.create_port(context, {'port': port_data})


def get_interface_name(name, prefix='', max_len=n_const.DEVICE_NAME_MAX_LEN):
    """Construct an interface name based on the prefix and name.

    The interface name can not exceed the maximum length passed in. Longer
    names are hashed to help ensure uniqueness.
    """
    requested_name = prefix + name

    if len(requested_name) <= max_len:
        return requested_name

    # We can't just truncate because interfaces may be distinguished
    # by an ident at the end. A hash over the name should be unique.
    # Leave part of the interface name on for easier identification
    if (len(prefix) + INTERFACE_HASH_LEN) > max_len:
        raise ValueError(_("Too long prefix provided. New name would exceed "
                           "given length for an interface name."))

    namelen = max_len - len(prefix) - INTERFACE_HASH_LEN
    hashed_name = hashlib.sha1(encodeutils.to_utf8(name))
    new_name = ('%(prefix)s%(truncated)s%(hash)s' %
                {'prefix': prefix, 'truncated': name[0:namelen],
                 'hash': hashed_name.hexdigest()[0:INTERFACE_HASH_LEN]})
    LOG.info(_LI("The requested interface name %(requested_name)s exceeds the "
                 "%(limit)d character limitation. It was shortened to "
                 "%(new_name)s to fit."),
             {'requested_name': requested_name,
              'limit': max_len, 'new_name': new_name})
    return new_name
