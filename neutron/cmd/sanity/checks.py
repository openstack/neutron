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

import netaddr

from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils as agent_utils
from neutron.common import utils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as const
from neutron.plugins.openvswitch.common import constants as ovs_const

LOG = logging.getLogger(__name__)


def vxlan_supported(root_helper, from_ip='192.0.2.1', to_ip='192.0.2.2'):
    name = "vxlantest-" + utils.get_random_string(6)
    with ovs_lib.OVSBridge(name, root_helper) as br:
        port = br.add_tunnel_port(from_ip, to_ip, const.TYPE_VXLAN)
        return port != ovs_lib.INVALID_OFPORT


def patch_supported(root_helper):
    seed = utils.get_random_string(6)
    name = "patchtest-" + seed
    peer_name = "peertest0-" + seed
    patch_name = "peertest1-" + seed
    with ovs_lib.OVSBridge(name, root_helper) as br:
        port = br.add_patch_port(patch_name, peer_name)
        return port != ovs_lib.INVALID_OFPORT


def nova_notify_supported():
    try:
        import neutron.notifiers.nova  # noqa since unused
        return True
    except ImportError:
        return False


def ofctl_arg_supported(root_helper, cmd, **kwargs):
    """Verify if ovs-ofctl binary supports cmd with **kwargs.

    :param root_helper: utility to use when running shell commands.
    :param cmd: ovs-ofctl command to use for test.
    :param **kwargs: arguments to test with the command.
    :returns: a boolean if the supplied arguments are supported.
    """
    br_name = 'br-test-%s' % utils.get_random_string(6)
    with ovs_lib.OVSBridge(br_name, root_helper) as test_br:
        full_args = ["ovs-ofctl", cmd, test_br.br_name,
                     ovs_lib._build_flow_expr_str(kwargs, cmd.split('-')[0])]
        try:
            agent_utils.execute(full_args, root_helper=root_helper)
        except RuntimeError as e:
            LOG.debug("Exception while checking supported feature via "
                      "command %s. Exception: %s" % (full_args, e))
            return False
        except Exception:
            LOG.exception(_("Unexpected exception while checking supported"
                            " feature via command: %s") % full_args)
            return False
        else:
            return True


def arp_responder_supported(root_helper):
    mac = netaddr.EUI('dead:1234:beef', dialect=netaddr.mac_unix)
    ip = netaddr.IPAddress('240.0.0.1')
    actions = ovs_const.ARP_RESPONDER_ACTIONS % {'mac': mac, 'ip': ip}

    return ofctl_arg_supported(root_helper,
                               cmd='add-flow',
                               table=21,
                               priority=1,
                               proto='arp',
                               dl_vlan=42,
                               nw_dst='%s' % ip,
                               actions=actions)
