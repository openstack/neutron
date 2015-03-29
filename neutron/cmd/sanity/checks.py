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

import re

import netaddr
from oslo_log import log as logging
import six

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ip_link_support
from neutron.agent.linux import utils as agent_utils
from neutron.common import utils
from neutron.i18n import _LE
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as const
from neutron.plugins.openvswitch.common import constants as ovs_const

LOG = logging.getLogger(__name__)


MINIMUM_DNSMASQ_VERSION = 2.67


def ovs_vxlan_supported(from_ip='192.0.2.1', to_ip='192.0.2.2'):
    name = "vxlantest-" + utils.get_random_string(6)
    with ovs_lib.OVSBridge(name) as br:
        port = br.add_tunnel_port(from_ip, to_ip, const.TYPE_VXLAN)
        return port != ovs_lib.INVALID_OFPORT


def iproute2_vxlan_supported():
    ip = ip_lib.IPWrapper()
    name = "vxlantest-" + utils.get_random_string(4)
    port = ip.add_vxlan(name, 3000)
    ip.del_veth(name)
    return name == port.name


def patch_supported():
    seed = utils.get_random_string(6)
    name = "patchtest-" + seed
    peer_name = "peertest0-" + seed
    patch_name = "peertest1-" + seed
    with ovs_lib.OVSBridge(name) as br:
        port = br.add_patch_port(patch_name, peer_name)
        return port != ovs_lib.INVALID_OFPORT


def nova_notify_supported():
    try:
        import neutron.notifiers.nova  # noqa since unused
        return True
    except ImportError:
        return False


def ofctl_arg_supported(cmd, **kwargs):
    """Verify if ovs-ofctl binary supports cmd with **kwargs.

    :param cmd: ovs-ofctl command to use for test.
    :param **kwargs: arguments to test with the command.
    :returns: a boolean if the supplied arguments are supported.
    """
    br_name = 'br-test-%s' % utils.get_random_string(6)
    with ovs_lib.OVSBridge(br_name) as test_br:
        full_args = ["ovs-ofctl", cmd, test_br.br_name,
                     ovs_lib._build_flow_expr_str(kwargs, cmd.split('-')[0])]
        try:
            agent_utils.execute(full_args, run_as_root=True)
        except RuntimeError as e:
            LOG.debug("Exception while checking supported feature via "
                      "command %s. Exception: %s", full_args, e)
            return False
        except Exception:
            LOG.exception(_LE("Unexpected exception while checking supported"
                              " feature via command: %s"), full_args)
            return False
        else:
            return True


def arp_responder_supported():
    mac = netaddr.EUI('dead:1234:beef', dialect=netaddr.mac_unix)
    ip = netaddr.IPAddress('240.0.0.1')
    actions = ovs_const.ARP_RESPONDER_ACTIONS % {'mac': mac, 'ip': ip}

    return ofctl_arg_supported(cmd='add-flow',
                               table=21,
                               priority=1,
                               proto='arp',
                               dl_vlan=42,
                               nw_dst='%s' % ip,
                               actions=actions)


def arp_header_match_supported():
    return ofctl_arg_supported(cmd='add-flow',
                               table=24,
                               priority=1,
                               proto='arp',
                               arp_op='0x2',
                               arp_spa='1.1.1.1',
                               actions="NORMAL")


def vf_management_supported():
    try:
        vf_section = ip_link_support.IpLinkSupport.get_vf_mgmt_section()
        if not ip_link_support.IpLinkSupport.vf_mgmt_capability_supported(
                vf_section,
                ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_STATE):
            LOG.debug("ip link command does not support vf capability")
            return False
    except ip_link_support.UnsupportedIpLinkCommand:
        LOG.exception(_LE("Unexpected exception while checking supported "
                          "ip link command"))
        return False
    return True


def netns_read_requires_helper():
    ipw = ip_lib.IPWrapper()
    nsname = "netnsreadtest-" + uuidutils.generate_uuid()
    ipw.netns.add(nsname)
    try:
        # read without root_helper. if exists, not required.
        ipw_nohelp = ip_lib.IPWrapper()
        exists = ipw_nohelp.netns.exists(nsname)
    finally:
        ipw.netns.delete(nsname)
    return not exists


def get_minimal_dnsmasq_version_supported():
    return MINIMUM_DNSMASQ_VERSION


def dnsmasq_version_supported():
    try:
        cmd = ['dnsmasq', '--version']
        env = {'LC_ALL': 'C'}
        out = agent_utils.execute(cmd, addl_env=env)
        m = re.search(r"version (\d+\.\d+)", out)
        ver = float(m.group(1)) if m else 0
        if ver < MINIMUM_DNSMASQ_VERSION:
            return False
    except (OSError, RuntimeError, IndexError, ValueError) as e:
        LOG.debug("Exception while checking minimal dnsmasq version. "
                  "Exception: %s", e)
        return False
    return True


def ovsdb_native_supported():
    # Running the test should ensure we are configured for OVSDB native
    try:
        ovs = ovs_lib.BaseOVS()
        ovs.get_bridges()
        return True
    except ImportError as ex:
        LOG.error(_LE("Failed to import required modules. Ensure that the "
                      "python-openvswitch package is installed. Error: %s"),
                  ex.message)
    except Exception as ex:
        LOG.exception(six.text_type(ex))

    return False
