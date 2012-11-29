# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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
import sys

import eventlet

from quantum.agent import dhcp_agent
from quantum.agent import l3_agent
from quantum.agent.linux import dhcp
from quantum.agent.linux import ip_lib
from quantum.agent.linux import ovs_lib
from quantum.api.v2 import attributes
from quantum.common import config
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)
NS_MANGLING_PATTERN = ('(%s|%s)' % (dhcp_agent.NS_PREFIX, l3_agent.NS_PREFIX) +
                       attributes.UUID_PATTERN)


class NullDelegate(object):
    def __getattribute__(self, name):
        def noop(*args, **kwargs):
            pass
        return noop


class FakeNetwork(object):
    def __init__(self, id):
        self.id = id


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    opts = [
        cfg.StrOpt('root_helper', default='sudo'),
        cfg.StrOpt('dhcp_driver',
                   default='quantum.agent.linux.dhcp.Dnsmasq',
                   help="The driver used to manage the DHCP server."),
        cfg.StrOpt('state_path',
                   default='.',
                   help='Top-level directory for maintaining dhcp state'),
        cfg.BoolOpt('force',
                    default=False,
                    help='Delete the namespace by removing all devices.'),
    ]
    conf = cfg.CommonConfigOpts()
    conf.register_opts(opts)
    conf.register_opts(dhcp.OPTS)
    config.setup_logging(conf)
    return conf


def kill_dhcp(conf, namespace):
    """Disable DHCP for a network if DHCP is still active."""
    network_id = namespace.replace(dhcp_agent.NS_PREFIX, '')

    null_delegate = NullDelegate()
    dhcp_driver = importutils.import_object(
        conf.dhcp_driver,
        conf,
        FakeNetwork(network_id),
        conf.root_helper,
        null_delegate)

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

    ip = ip_lib.IPWrapper(conf.root_helper, namespace)
    return force or ip.namespace_is_empty()


def unplug_device(conf, device):
    try:
        device.link.delete()
    except RuntimeError:
        # Maybe the device is OVS port, so try to delete
        bridge_name = ovs_lib.get_bridge_for_iface(conf.root_helper,
                                                   device.name)
        if bridge_name:
            bridge = ovs_lib.OVSBridge(bridge_name,
                                       conf.root_helper)
            bridge.delete_port(device.name)
        else:
            LOG.debug(_('Unable to find bridge for device: %s') % device.name)


def destroy_namespace(conf, namespace, force=False):
    """Destroy a given namespace.

    If force is True, then dhcp (if it exists) will be disabled and all
    devices will be forcibly removed.
    """

    try:
        ip = ip_lib.IPWrapper(conf.root_helper, namespace)

        if force:
            kill_dhcp(conf, namespace)
            # NOTE: The dhcp driver will remove the namespace if is it empty,
            # so a second check is required here.
            if ip.netns.exists(namespace):
                for device in ip.get_devices(exclude_loopback=True):
                    unplug_device(conf, device)

        ip.garbage_collect_namespace()
    except Exception, e:
        LOG.exception(_('Error unable to destroy namespace: %s') % namespace)


def main():
    """Main method for cleaning up network namespaces.

    This method will make two passes checking for namespaces to delete. The
    process will identify candidates, sleep, and call garbage collect. The
    garbage collection will re-verify that the namespace meets the criteria for
    deletion (ie it is empty). The period of sleep and the 2nd pass allow
    time for the namespace state to settle, so that the check prior deletion
    will re-confirm the namespace is empty.

    The utility is designed to clean-up after the forced or unexpected
    termination of Quantum agents.

    The --force flag should only be used as part of the cleanup of a devstack
    installation as it will blindly purge namespaces and their devices. This
    option also kills any lingering DHCP instances.
    """
    eventlet.monkey_patch()

    conf = setup_conf()
    conf(sys.argv)

    # Identify namespaces that are candidates for deletion.
    candidates = [ns for ns in
                  ip_lib.IPWrapper.get_namespaces(conf.root_helper)
                  if eligible_for_deletion(conf, ns, conf.force)]

    if candidates:
        eventlet.sleep(2)

        for namespace in candidates:
            destroy_namespace(conf, namespace, conf.force)
