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

import sys

from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent import dhcp_agent
from neutron.cmd.sanity import checks
from neutron.common import config
from neutron.conf.agent import securitygroups_rpc
from neutron.conf.db import l3_hamode_db
from neutron.conf.plugins.ml2 import config as ml2_conf
from neutron.conf.plugins.ml2.drivers import linuxbridge as lb_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf


LOG = logging.getLogger(__name__)


def setup_conf():
    ovs_conf.register_ovs_agent_opts(cfg.CONF)
    lb_conf.register_linuxbridge_opts(cfg.CONF)
    ml2_conf.register_ml2_plugin_opts(cfg.CONF)
    securitygroups_rpc.register_securitygroups_opts(cfg.CONF)
    dhcp_agent.register_options(cfg.CONF)
    l3_hamode_db.register_db_l3_hamode_opts(cfg.CONF)


class BoolOptCallback(cfg.BoolOpt):
    def __init__(self, name, callback, **kwargs):
        if 'default' not in kwargs:
            kwargs['default'] = False
        self.callback = callback
        super(BoolOptCallback, self).__init__(name, **kwargs)


def check_ovs_vxlan():
    result = checks.ovs_vxlan_supported()
    if not result:
        LOG.error('Check for Open vSwitch VXLAN support failed. '
                  'Please ensure that the version of openvswitch '
                  'being used has VXLAN support.')
    return result


def check_ovs_geneve():
    result = checks.ovs_geneve_supported()
    if not result:
        LOG.error('Check for Open vSwitch Geneve support failed. '
                  'Please ensure that the version of openvswitch '
                  'and kernel being used has Geneve support.')
    return result


def check_iproute2_vxlan():
    result = checks.iproute2_vxlan_supported()
    if not result:
        LOG.error('Check for iproute2 VXLAN support failed. Please ensure '
                  'that the iproute2 has VXLAN support.')
    return result


def check_ovs_patch():
    result = checks.patch_supported()
    if not result:
        LOG.error('Check for Open vSwitch patch port support failed. '
                  'Please ensure that the version of openvswitch '
                  'being used has patch port support or disable features '
                  'requiring patch ports (gre/vxlan, etc.).')
    return result


def check_read_netns():
    required = checks.netns_read_requires_helper()
    if not required and cfg.CONF.AGENT.use_helper_for_ns_read:
        LOG.warning("The user that is executing neutron can read the "
                    "namespaces without using the root_helper. Disable "
                    "the use_helper_for_ns_read option to avoid a "
                    "performance impact.")
        # Don't fail because nothing is actually broken. Just not optimal.
        result = True
    elif required and not cfg.CONF.AGENT.use_helper_for_ns_read:
        LOG.error("The user that is executing neutron does not have "
                  "permissions to read the namespaces. Enable the "
                  "use_helper_for_ns_read configuration option.")
        result = False
    else:
        # everything is configured appropriately
        result = True
    return result


# NOTE(ihrachyshka): since the minimal version is currently capped due to
# missing hwaddr matching in dnsmasq < 2.67, a better version of the check
# would actually start dnsmasq server and issue a DHCP request using a IPv6
# DHCP client.
def check_dnsmasq_version():
    result = checks.dnsmasq_version_supported()
    if not result:
        LOG.error('The installed version of dnsmasq is too old. '
                  'Please update to at least version %s.',
                  checks.get_minimal_dnsmasq_version_supported())
    return result


def check_dnsmasq_local_service_supported():
    result = checks.dnsmasq_local_service_supported()
    if not result:
        LOG.error('The installed version of dnsmasq is too old. '
                  'Please update to a version supporting the '
                  '--local-service option.')
    return result


def check_keepalived_ipv6_support():
    result = checks.keepalived_ipv6_supported()
    if not result:
        LOG.error('The installed version of keepalived does not support '
                  'IPv6. Please update to at least version 1.2.10 for '
                  'IPv6 support.')
    return result


def check_dibbler_version():
    result = checks.dibbler_version_supported()
    if not result:
        LOG.error('The installed version of dibbler-client is too old. '
                  'Please update to at least version %s.',
                  checks.get_minimal_dibbler_version_supported())
    return result


def check_nova_notify():
    result = checks.nova_notify_supported()
    if not result:
        LOG.error('Nova notifications are enabled, but novaclient is not '
                  'installed. Either disable nova notifications or '
                  'install python-novaclient.')
    return result


def check_arp_responder():
    result = checks.arp_responder_supported()
    if not result:
        LOG.error('Check for Open vSwitch ARP responder support failed. '
                  'Please ensure that the version of openvswitch '
                  'being used has ARP flows support.')
    return result


def check_arp_header_match():
    result = checks.arp_header_match_supported()
    if not result:
        LOG.error('Check for Open vSwitch support of ARP header matching '
                  'failed. ARP spoofing suppression will not work. A '
                  'newer version of OVS is required.')
    return result


def check_icmpv6_header_match():
    result = checks.icmpv6_header_match_supported()
    if not result:
        LOG.error('Check for Open vSwitch support of ICMPv6 header '
                  'matching failed. ICMPv6 Neighbor Advt spoofing (part '
                  'of arp spoofing) suppression will not work. A newer '
                  'version of OVS is required.')
    return result


def check_ovsdb_native():
    result = checks.ovsdb_native_supported()
    if not result:
        LOG.error('Check for native OVSDB support failed.')
    return result


def check_ovs_conntrack():
    result = checks.ovs_conntrack_supported()
    if not result:
        LOG.error('Check for Open vSwitch support of conntrack support '
                  'failed. OVS/CT firewall will not work. A newer '
                  'version of OVS (2.5+) and linux kernel (4.3+) are '
                  'required. See '
                  'https://github.com/openvswitch/ovs/blob/master/FAQ.md '
                  'for more information.')
    return result


def check_gre_conntrack():
    result = checks.gre_conntrack_supported()
    if not result:
        LOG.warning('Kernel module %s is not loaded. GRE tunnels from '
                    'VM to VM will not work with OVS firewall driver.',
                    checks.CONNTRACK_GRE_MODULE)
    return result


def check_ebtables():
    result = checks.ebtables_supported()
    if not result:
        LOG.error('Cannot run ebtables. Please ensure that it '
                  'is installed.')
    return result


def check_ipset():
    result = checks.ipset_supported()
    if not result:
        LOG.error('Cannot run ipset. Please ensure that it '
                  'is installed.')
    return result


def check_ip6tables():
    result = checks.ip6tables_supported()
    if not result:
        LOG.error('Cannot run ip6tables. Please ensure that it '
                  'is installed.')
    return result


def check_conntrack():
    result = checks.conntrack_supported()
    if not result:
        LOG.error('Cannot run conntrack. Please ensure that it '
                  'is installed.')
    return result


def check_dhcp_release6():
    result = checks.dhcp_release6_supported()
    if not result:
        LOG.error('No dhcp_release6 tool detected. The installed version '
                  'of dnsmasq does not support releasing IPv6 leases. '
                  'Please update to at least version %s if you need this '
                  'feature. If you do not use IPv6 stateful subnets you '
                  'can continue to use this version of dnsmasq, as '
                  'other IPv6 address assignment mechanisms besides '
                  'stateful DHCPv6 should continue to work without '
                  'the dhcp_release6 utility. '
                  'Current version of dnsmasq is ok if other checks '
                  'pass.',
                  checks.get_dnsmasq_version_with_dhcp_release6())
    return result


def check_bridge_firewalling_enabled():
    result = checks.bridge_firewalling_enabled()
    if not result:
        LOG.error('Bridge firewalling is not enabled. It may be the case '
                  'that bridge and/or br_netfilter kernel modules are not '
                  'loaded. Alternatively, corresponding sysctl settings '
                  'may be overridden to disable it by default.')
    return result


def check_ip_nonlocal_bind():
    result = checks.ip_nonlocal_bind()
    if not result:
        LOG.error('This kernel does not isolate ip_nonlocal_bind kernel '
                  'option in namespaces. Please update to kernel '
                  'version > 3.19.')
    return result


# Define CLI opts to test specific features, with a callback for the test
OPTS = [
    BoolOptCallback('ovs_vxlan', check_ovs_vxlan, default=False,
                    help=_('Check for OVS vxlan support')),
    BoolOptCallback('ovs_geneve', check_ovs_geneve, default=False,
                    help=_('Check for OVS Geneve support')),
    BoolOptCallback('iproute2_vxlan', check_iproute2_vxlan, default=False,
                    help=_('Check for iproute2 vxlan support')),
    BoolOptCallback('ovs_patch', check_ovs_patch, default=False,
                    help=_('Check for patch port support')),
    BoolOptCallback('nova_notify', check_nova_notify,
                    help=_('Check for nova notification support')),
    BoolOptCallback('arp_responder', check_arp_responder,
                    help=_('Check for ARP responder support')),
    BoolOptCallback('arp_header_match', check_arp_header_match,
                    help=_('Check for ARP header match support')),
    BoolOptCallback('icmpv6_header_match', check_icmpv6_header_match,
                    help=_('Check for ICMPv6 header match support')),
    BoolOptCallback('read_netns', check_read_netns,
                    help=_('Check netns permission settings')),
    BoolOptCallback('dnsmasq_local_service_supported',
                    check_dnsmasq_local_service_supported,
                    help=_('Check for local-service support in dnsmasq')),
    BoolOptCallback('dnsmasq_version', check_dnsmasq_version,
                    help=_('Check minimal dnsmasq version'),
                    deprecated_for_removal=True,
                    deprecated_since='Pike'),
    BoolOptCallback('ovsdb_native', check_ovsdb_native,
                    help=_('Check ovsdb native interface support')),
    BoolOptCallback('ovs_conntrack', check_ovs_conntrack,
                    help=_('Check ovs conntrack support')),
    BoolOptCallback('gre_conntrack', check_gre_conntrack,
                    help=_('Check if conntrack for gre tunnels traffic is '
                           'supported')),
    BoolOptCallback('ebtables_installed', check_ebtables,
                    help=_('Check ebtables installation')),
    BoolOptCallback('keepalived_ipv6_support', check_keepalived_ipv6_support,
                    help=_('Check keepalived IPv6 support')),
    BoolOptCallback('dibbler_version', check_dibbler_version,
                    help=_('Check minimal dibbler version'),
                    deprecated_for_removal=True,
                    deprecated_since='Pike'),
    BoolOptCallback('ipset_installed', check_ipset,
                    help=_('Check ipset installation')),
    BoolOptCallback('ip6tables_installed', check_ip6tables,
                    help=_('Check ip6tables installation')),
    BoolOptCallback('conntrack_installed', check_conntrack,
                    help=_('Check conntrack installation')),
    BoolOptCallback('dhcp_release6', check_dhcp_release6,
                    help=_('Check dhcp_release6 installation')),
    BoolOptCallback('bridge_firewalling', check_bridge_firewalling_enabled,
                    help=_('Check bridge firewalling'),
                    default=False),
    BoolOptCallback('ip_nonlocal_bind', check_ip_nonlocal_bind,
                    help=_('Check ip_nonlocal_bind kernel option works with '
                           'network namespaces.'),
                    default=False),
]


def enable_tests_from_config():
    """If a test can depend on configuration, use this function to set the
    appropriate CLI option to enable that test. It will then be possible to
    run all necessary tests, just by passing in the appropriate configs.
    """

    cfg.CONF.set_default('arp_header_match', True)
    cfg.CONF.set_default('icmpv6_header_match', True)
    if 'vxlan' in cfg.CONF.AGENT.tunnel_types:
        cfg.CONF.set_default('ovs_vxlan', True)
    if 'geneve' in cfg.CONF.AGENT.tunnel_types:
        cfg.CONF.set_default('ovs_geneve', True)
    if ('vxlan' in cfg.CONF.ml2.type_drivers or
            cfg.CONF.VXLAN.enable_vxlan):
        cfg.CONF.set_default('iproute2_vxlan', True)
    if cfg.CONF.AGENT.tunnel_types:
        cfg.CONF.set_default('ovs_patch', True)
    if not cfg.CONF.OVS.use_veth_interconnection:
        cfg.CONF.set_default('ovs_patch', True)
    if (cfg.CONF.notify_nova_on_port_status_changes or
            cfg.CONF.notify_nova_on_port_data_changes):
        cfg.CONF.set_default('nova_notify', True)
    if cfg.CONF.AGENT.arp_responder:
        cfg.CONF.set_default('arp_responder', True)
    if not cfg.CONF.AGENT.use_helper_for_ns_read:
        cfg.CONF.set_default('read_netns', True)
    if cfg.CONF.dhcp_driver == 'neutron.agent.linux.dhcp.Dnsmasq':
        cfg.CONF.set_default('dnsmasq_local_service_supported', True)
        cfg.CONF.set_default('dnsmasq_version', True)
    if cfg.CONF.l3_ha:
        cfg.CONF.set_default('keepalived_ipv6_support', True)
        cfg.CONF.set_default('ip_nonlocal_bind', True)
    if cfg.CONF.SECURITYGROUP.enable_ipset:
        cfg.CONF.set_default('ipset_installed', True)
    if cfg.CONF.SECURITYGROUP.enable_security_group:
        cfg.CONF.set_default('ip6tables_installed', True)
    if cfg.CONF.SECURITYGROUP.firewall_driver in (
        'iptables',
        'iptables_hybrid',
        ('neutron.agent.linux.iptables_firewall.'
         'IptablesFirewallDriver'),
        ('neutron.agent.linux.iptables_firewall.'
         'OVSHybridIptablesFirewallDriver'),
    ):
        cfg.CONF.set_default('bridge_firewalling', True)


def all_tests_passed():
    return all(opt.callback() for opt in OPTS if cfg.CONF.get(opt.name))


def main():
    setup_conf()
    cfg.CONF.register_cli_opts(OPTS)
    cfg.CONF.set_override('use_stderr', True)
    config.setup_logging()
    config.init(sys.argv[1:], default_config_files=[])

    if cfg.CONF.config_file:
        enable_tests_from_config()

    return 0 if all_tests_passed() else 1
