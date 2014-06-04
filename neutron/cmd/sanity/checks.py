# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2014 OpenStack Foundation.
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

from neutron.agent.linux import ovs_lib
from neutron.common import utils
from neutron.plugins.common import constants as const
from neutron.plugins.openvswitch.common import constants as ovs_const


def vxlan_supported(root_helper, from_ip='192.0.2.1', to_ip='192.0.2.2'):
    name = "vxlantest-" + utils.get_random_string(6)
    with ovs_lib.OVSBridge(name, root_helper) as br:
        port = br.add_tunnel_port(from_ip, to_ip, const.TYPE_VXLAN)
        return port != ovs_const.INVALID_OFPORT


def patch_supported(root_helper):
    seed = utils.get_random_string(6)
    name = "patchtest-" + seed
    peer_name = "peertest0-" + seed
    patch_name = "peertest1-" + seed
    with ovs_lib.OVSBridge(name, root_helper) as br:
        port = br.add_patch_port(patch_name, peer_name)
        return port != ovs_const.INVALID_OFPORT
