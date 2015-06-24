# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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


from neutron.plugins.common import constants as p_const


FLAT_VLAN_ID = -1
LOCAL_VLAN_ID = -2

# Supported VXLAN features
VXLAN_NONE = 'not_supported'
VXLAN_MCAST = 'multicast_flooding'
VXLAN_UCAST = 'unicast_flooding'


# TODO(rkukura): Eventually remove this function, which provides
# temporary backward compatibility with pre-Havana RPC and DB vlan_id
# encoding.
def interpret_vlan_id(vlan_id):
    """Return (network_type, segmentation_id) tuple for encoded vlan_id."""
    if vlan_id == LOCAL_VLAN_ID:
        return (p_const.TYPE_LOCAL, None)
    elif vlan_id == FLAT_VLAN_ID:
        return (p_const.TYPE_FLAT, None)
    else:
        return (p_const.TYPE_VLAN, vlan_id)
