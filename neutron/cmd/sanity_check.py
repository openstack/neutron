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

from neutron.agent import dhcp_agent
from neutron.cmd.sanity import checks
from neutron.common import config
from neutron.db import l3_hamode_db
from neutron.i18n import _LE, _LW


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'neutron.plugins.ml2.drivers.openvswitch.'
                      'agent.common.config')
cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.'
                      'agent.common.config')
cfg.CONF.import_group('VXLAN', 'neutron.plugins.ml2.drivers.linuxbridge.'
                      'agent.common.config')
cfg.CONF.import_group('ml2', 'neutron.plugins.ml2.config')
cfg.CONF.import_group('ml2_sriov',
                      'neutron.plugins.ml2.drivers.mech_sriov.mech_driver')
dhcp_agent.register_options()
cfg.CONF.register_opts(l3_hamode_db.L3_HA_OPTS)


class BoolOptCallback(cfg.BoolOpt):
    def __init__(self, name, callback, **kwargs):
        if 'default' not in kwargs:
            kwargs['default'] = False
        self.callback = callback
        super(BoolOptCallback, self).__init__(name, **kwargs)


def check_ovs_vxlan():
    result = checks.ovs_vxlan_supported()
    if not result:
        LOG.error(_LE('Check for Open vSwitch VXLAN support failed. '
                      'Please ensure that the version of openvswitch '
                      'being used has VXLAN support.'))
    return result


def check_iproute2_vxlan():
    result = checks.iproute2_vxlan_supported()
    if not result:
        LOG.error(_LE('Check for iproute2 VXLAN support failed. Please ensure '
                      'that the iproute2 has VXLAN support.'))
    return result


def check_ovs_patch():
    result = checks.patch_supported()
    if not result:
        LOG.error(_LE('Check for Open vSwitch patch port support failed. '
                      'Please ensure that the version of openvswitch '
                      'being used has patch port support or disable features '
                      'requiring patch ports (gre/vxlan, etc.).'))
    return result


def check_read_netns():
    required = checks.netns_read_requires_helper()
    if not required and cfg.CONF.AGENT.use_helper_for_ns_read:
        LOG.warning(_LW("The user that is executing neutron can read the "
                        "namespaces without using the root_helper. Disable "
                        "the use_helper_for_ns_read option to avoid a "
                        "performance impact."))
        # Don't fail because nothing is actually broken. Just not optimal.
        result = True
    elif required and not cfg.CONF.AGENT.use_helper_for_ns_read:
        LOG.error(_LE("The user that is executing neutron does not have "
                      "permissions to read the namespaces. Enable the "
                      "use_helper_for_ns_read configuration option."))
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
        LOG.error(_LE('The installed version of dnsmasq is too old. '
                      'Please update to at least version %s.'),
                  checks.get_minimal_dnsmasq_version_supported())
    return result


def check_keepalived_ipv6_support():
    result = checks.keepalived_ipv6_supported()
    if not result:
        LOG.error(_LE('The installed version of keepalived does not support '
                      'IPv6. Please update to at least version 1.2.10 for '
                      'IPv6 support.'))
    return result


def check_nova_notify():
    result = checks.nova_notify_supported()
    if not result:
        LOG.error(_LE('Nova notifications are enabled, but novaclient is not '
                      'installed. Either disable nova notifications or '
                      'install python-novaclient.'))
    return result


def check_arp_responder():
    result = checks.arp_responder_supported()
    if not result:
        LOG.error(_LE('Check for Open vSwitch ARP responder support failed. '
                      'Please ensure that the version of openvswitch '
                      'being used has ARP flows support.'))
    return result


def check_arp_header_match():
    result = checks.arp_header_match_supported()
    if not result:
        LOG.error(_LE('Check for Open vSwitch support of ARP header matching '
                      'failed. ARP spoofing suppression will not work. A '
                      'newer version of OVS is required.'))
    return result


def check_vf_management():
    result = checks.vf_management_supported()
    if not result:
        LOG.error(_LE('Check for VF management support failed. '
                      'Please ensure that the version of ip link '
                      'being used has VF support.'))
    return result


def check_ovsdb_native():
    cfg.CONF.set_override('ovsdb_interface', 'native', group='OVS')
    result = checks.ovsdb_native_supported()
    if not result:
        LOG.error(_LE('Check for native OVSDB support failed.'))
    return result


def check_ebtables():
    result = checks.ebtables_supported()
    if not result:
        LOG.error(_LE('Cannot run ebtables. Please ensure that it '
                      'is installed.'))
    return result


# Define CLI opts to test specific features, with a callback for the test
OPTS = [
    BoolOptCallback('ovs_vxlan', check_ovs_vxlan, default=False,
                    help=_('Check for OVS vxlan support')),
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
    BoolOptCallback('vf_management', check_vf_management,
                    help=_('Check for VF management support')),
    BoolOptCallback('read_netns', check_read_netns,
                    help=_('Check netns permission settings')),
    BoolOptCallback('dnsmasq_version', check_dnsmasq_version,
                    help=_('Check minimal dnsmasq version')),
    BoolOptCallback('ovsdb_native', check_ovsdb_native,
                    help=_('Check ovsdb native interface support')),
    BoolOptCallback('ebtables_installed', check_ebtables,
                    help=_('Check ebtables installation')),
    BoolOptCallback('keepalived_ipv6_support', check_keepalived_ipv6_support,
                    help=_('Check keepalived IPv6 support')),
]


def enable_tests_from_config():
    """If a test can depend on configuration, use this function to set the
    appropriate CLI option to enable that test. It will then be possible to
    run all necessary tests, just by passing in the appropriate configs.
    """

    if 'vxlan' in cfg.CONF.AGENT.tunnel_types:
        cfg.CONF.set_override('ovs_vxlan', True)
    if ('vxlan' in cfg.CONF.ml2.type_drivers or
            cfg.CONF.VXLAN.enable_vxlan):
        cfg.CONF.set_override('iproute2_vxlan', True)
    if cfg.CONF.AGENT.tunnel_types:
        cfg.CONF.set_override('ovs_patch', True)
    if not cfg.CONF.OVS.use_veth_interconnection:
        cfg.CONF.set_override('ovs_patch', True)
    if (cfg.CONF.notify_nova_on_port_status_changes or
            cfg.CONF.notify_nova_on_port_data_changes):
        cfg.CONF.set_override('nova_notify', True)
    if cfg.CONF.AGENT.arp_responder:
        cfg.CONF.set_override('arp_responder', True)
    if cfg.CONF.AGENT.prevent_arp_spoofing:
        cfg.CONF.set_override('arp_header_match', True)
    if cfg.CONF.ml2_sriov.agent_required:
        cfg.CONF.set_override('vf_management', True)
    if not cfg.CONF.AGENT.use_helper_for_ns_read:
        cfg.CONF.set_override('read_netns', True)
    if cfg.CONF.dhcp_driver == 'neutron.agent.linux.dhcp.Dnsmasq':
        cfg.CONF.set_override('dnsmasq_version', True)
    if cfg.CONF.OVS.ovsdb_interface == 'native':
        cfg.CONF.set_override('ovsdb_native', True)
    if cfg.CONF.l3_ha:
        cfg.CONF.set_override('keepalived_ipv6_support', True)


def all_tests_passed():
    return all(opt.callback() for opt in OPTS if cfg.CONF.get(opt.name))


def main():
    cfg.CONF.register_cli_opts(OPTS)
    cfg.CONF.set_override('use_stderr', True)
    config.setup_logging()
    config.init(sys.argv[1:], default_config_files=[])

    if cfg.CONF.config_file:
        enable_tests_from_config()

    return 0 if all_tests_passed() else 1
