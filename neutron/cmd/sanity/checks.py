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
import shutil
import tempfile

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import six

from neutron.agent.common import ovs_lib
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import namespaces
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ip_link_support
from neutron.agent.linux import keepalived
from neutron.agent.linux import utils as agent_utils
from neutron.common import constants as n_consts
from neutron.common import utils
from neutron.i18n import _LE
from neutron.plugins.common import constants as const
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_const

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


class KeepalivedIPv6Test(object):
    def __init__(self, ha_port, gw_port, gw_vip, default_gw):
        self.ha_port = ha_port
        self.gw_port = gw_port
        self.gw_vip = gw_vip
        self.default_gw = default_gw
        self.manager = None
        self.config = None
        self.config_path = None
        self.nsname = "keepalivedtest-" + uuidutils.generate_uuid()
        self.pm = external_process.ProcessMonitor(cfg.CONF, 'router')
        self.orig_interval = cfg.CONF.AGENT.check_child_processes_interval

    def configure(self):
        config = keepalived.KeepalivedConf()
        instance1 = keepalived.KeepalivedInstance('MASTER', self.ha_port, 1,
                                                  ['169.254.192.0/18'],
                                                  advert_int=5)
        instance1.track_interfaces.append(self.ha_port)

        # Configure keepalived with an IPv6 address (gw_vip) on gw_port.
        vip_addr1 = keepalived.KeepalivedVipAddress(self.gw_vip, self.gw_port)
        instance1.vips.append(vip_addr1)

        # Configure keepalived with an IPv6 default route on gw_port.
        gateway_route = keepalived.KeepalivedVirtualRoute(n_consts.IPv6_ANY,
                                                          self.default_gw,
                                                          self.gw_port)
        instance1.virtual_routes.gateway_routes = [gateway_route]
        config.add_instance(instance1)
        self.config = config

    def start_keepalived_process(self):
        # Disable process monitoring for Keepalived process.
        cfg.CONF.set_override('check_child_processes_interval', 0, 'AGENT')

        # Create a temp directory to store keepalived configuration.
        self.config_path = tempfile.mkdtemp()

        # Instantiate keepalived manager with the IPv6 configuration.
        self.manager = keepalived.KeepalivedManager('router1', self.config,
            namespace=self.nsname, process_monitor=self.pm,
            conf_path=self.config_path)
        self.manager.spawn()

    def verify_ipv6_address_assignment(self, gw_dev):
        process = self.manager.get_process()
        agent_utils.wait_until_true(lambda: process.active)

        def _gw_vip_assigned():
            iface_ip = gw_dev.addr.list(ip_version=6, scope='global')
            if iface_ip:
                return self.gw_vip == iface_ip[0]['cidr']

        agent_utils.wait_until_true(_gw_vip_assigned)

    def __enter__(self):
        ip_lib.IPWrapper().netns.add(self.nsname)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.pm.stop()
        if self.manager:
            self.manager.disable()
        if self.config_path:
            shutil.rmtree(self.config_path, ignore_errors=True)
        ip_lib.IPWrapper().netns.delete(self.nsname)
        cfg.CONF.set_override('check_child_processes_interval',
                              self.orig_interval, 'AGENT')


def keepalived_ipv6_supported():
    """Check if keepalived supports IPv6 functionality.

    Validation is done as follows.
    1. Create a namespace.
    2. Create OVS bridge with two ports (ha_port and gw_port)
    3. Move the ovs ports to the namespace.
    4. Spawn keepalived process inside the namespace with IPv6 configuration.
    5. Verify if IPv6 address is assigned to gw_port.
    6. Verify if IPv6 default route is configured by keepalived.
    """

    random_str = utils.get_random_string(6)
    br_name = "ka-test-" + random_str
    ha_port = ha_router.HA_DEV_PREFIX + random_str
    gw_port = namespaces.INTERNAL_DEV_PREFIX + random_str
    gw_vip = 'fdf8:f53b:82e4::10/64'
    expected_default_gw = 'fe80:f816::1'

    with ovs_lib.OVSBridge(br_name) as br:
        with KeepalivedIPv6Test(ha_port, gw_port, gw_vip,
                                expected_default_gw) as ka:
            br.add_port(ha_port, ('type', 'internal'))
            br.add_port(gw_port, ('type', 'internal'))

            ha_dev = ip_lib.IPDevice(ha_port)
            gw_dev = ip_lib.IPDevice(gw_port)

            ha_dev.link.set_netns(ka.nsname)
            gw_dev.link.set_netns(ka.nsname)

            ha_dev.link.set_up()
            gw_dev.link.set_up()

            ka.configure()

            ka.start_keepalived_process()

            ka.verify_ipv6_address_assignment(gw_dev)

            default_gw = gw_dev.route.get_gateway(ip_version=6)
            if default_gw:
                default_gw = default_gw['gateway']

    return expected_default_gw == default_gw


def ovsdb_native_supported():
    # Running the test should ensure we are configured for OVSDB native
    try:
        ovs = ovs_lib.BaseOVS()
        ovs.get_bridges()
        return True
    except ImportError as ex:
        LOG.error(_LE("Failed to import required modules. Ensure that the "
                      "python-openvswitch package is installed. Error: %s"),
                  ex)
    except Exception as ex:
        LOG.exception(six.text_type(ex))

    return False


def ebtables_supported():
    try:
        cmd = ['ebtables', '--version']
        agent_utils.execute(cmd)
        return True
    except (OSError, RuntimeError, IndexError, ValueError) as e:
        LOG.debug("Exception while checking for installed ebtables. "
                  "Exception: %s", e)
        return False
