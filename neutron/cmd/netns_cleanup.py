# Copyright (c) 2012 OpenStack Foundation.
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
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.agent.common import config as agent_config
from neutron.agent.common import ovs_lib
from neutron.agent.dhcp import config as dhcp_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import dvr
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.api.v2 import attributes
from neutron.common import config
from neutron.i18n import _LE


LOG = logging.getLogger(__name__)
NS_MANGLING_PATTERN = ('(%s|%s|%s|%s)' % (dhcp.NS_PREFIX,
                                          l3_agent.NS_PREFIX,
                                          dvr.SNAT_NS_PREFIX,
                                          dvr_fip_ns.FIP_NS_PREFIX) +
                       attributes.UUID_PATTERN)


class FakeDhcpPlugin(object):
    """Fake RPC plugin to bypass any RPC calls."""
    def __getattribute__(self, name):
        def fake_method(*args):
            pass
        return fake_method


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    cli_opts = [
        cfg.BoolOpt('force',
                    default=False,
                    help=_('Delete the namespace by removing all devices.')),
    ]

    conf = cfg.CONF
    conf.register_cli_opts(cli_opts)
    agent_config.register_interface_driver_opts_helper(conf)
    agent_config.register_use_namespaces_opts_helper(conf)
    conf.register_opts(dhcp_config.DHCP_AGENT_OPTS)
    conf.register_opts(dhcp_config.DHCP_OPTS)
    conf.register_opts(dhcp_config.DNSMASQ_OPTS)
    conf.register_opts(interface.OPTS)
    return conf


def _get_dhcp_process_monitor(config):
    return external_process.ProcessMonitor(config=config,
                                           resource_type='dhcp')


def kill_dhcp(conf, namespace):
    """Disable DHCP for a network if DHCP is still active."""
    network_id = namespace.replace(dhcp.NS_PREFIX, '')

    dhcp_driver = importutils.import_object(
        conf.dhcp_driver,
        conf=conf,
        process_monitor=_get_dhcp_process_monitor(conf),
        network=dhcp.NetModel(conf.use_namespaces, {'id': network_id}),
        plugin=FakeDhcpPlugin())

    if dhcp_driver.active:
        dhcp_driver.disable()


def eligible_for_deletion(conf, namespace, force=False):
    """Determine whether a namespace is eligible for deletion.

    Eligibility is determined by having only the lo device or if force
    is passed as a parameter.
    """

    # filter out namespaces without UUID as the name
    if not re.match(NS_MANGLING_PATTERN, namespace):
        return False

    ip = ip_lib.IPWrapper(namespace=namespace)
    return force or ip.namespace_is_empty()


def unplug_device(conf, device):
    try:
        device.link.delete()
    except RuntimeError:
        # Maybe the device is OVS port, so try to delete
        ovs = ovs_lib.BaseOVS()
        bridge_name = ovs.get_bridge_for_iface(device.name)
        if bridge_name:
            bridge = ovs_lib.OVSBridge(bridge_name)
            bridge.delete_port(device.name)
        else:
            LOG.debug('Unable to find bridge for device: %s', device.name)


def destroy_namespace(conf, namespace, force=False):
    """Destroy a given namespace.

    If force is True, then dhcp (if it exists) will be disabled and all
    devices will be forcibly removed.
    """

    try:
        ip = ip_lib.IPWrapper(namespace=namespace)

        if force:
            kill_dhcp(conf, namespace)
            # NOTE: The dhcp driver will remove the namespace if is it empty,
            # so a second check is required here.
            if ip.netns.exists(namespace):
                for device in ip.get_devices(exclude_loopback=True):
                    unplug_device(conf, device)

        ip.garbage_collect_namespace()
    except Exception:
        LOG.exception(_LE('Error unable to destroy namespace: %s'), namespace)


def cleanup_network_namespaces(conf):
    # Identify namespaces that are candidates for deletion.
    candidates = [ns for ns in
                  ip_lib.IPWrapper.get_namespaces()
                  if eligible_for_deletion(conf, ns, conf.force)]

    if candidates:
        time.sleep(2)

        for namespace in candidates:
            destroy_namespace(conf, namespace, conf.force)


def main():
    """Main method for cleaning up network namespaces.

    This method will make two passes checking for namespaces to delete. The
    process will identify candidates, sleep, and call garbage collect. The
    garbage collection will re-verify that the namespace meets the criteria for
    deletion (ie it is empty). The period of sleep and the 2nd pass allow
    time for the namespace state to settle, so that the check prior deletion
    will re-confirm the namespace is empty.

    The utility is designed to clean-up after the forced or unexpected
    termination of Neutron agents.

    The --force flag should only be used as part of the cleanup of a devstack
    installation as it will blindly purge namespaces and their devices. This
    option also kills any lingering DHCP instances.
    """
    conf = setup_conf()
    conf()
    config.setup_logging()
    cleanup_network_namespaces(conf)
