# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.
# All Rights Reserved.
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
#
# Extends the linux_net.py kvm/linux network driver in Nova,
# borrows structure and code
# @author: Sumit Naiksatam, Cisco Systems, Inc.
#


"""Extends the linux_net driver when using the Linux Bridge plugin with
QuantumManager"""


from nova import exception
from nova import log as logging
from nova import utils

from nova.network.linux_net import *


LOG = logging.getLogger(__name__)


BRDIGE_NAME_PREFIX = "brq"
GATEWAY_INTERFACE_PREFIX = "gw-"


def _device_exists(device):
    """Check if ethernet device exists."""
    (_out, err) = utils.execute('ip', 'link', 'show', 'dev', device,
                           check_exit_code=False)
    return not err


# plugs interfaces using Linux Bridge when using QuantumManager
class QuantumLibvirtLinuxBridgeDriver(LinuxNetInterfaceDriver):

    def plug(self, network, mac_address, gateway=True):
        LOG.debug(_("inside plug()"))
        dev = self.get_dev(network)
        bridge = self.get_bridge(network)
        if not gateway:
            # If we weren't instructed to act as a gateway then add the
            # appropriate flows to block all non-dhcp traffic.
            # .. and make sure iptbles won't forward it as well.
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--in-interface %s -j DROP' % bridge)
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--out-interface %s -j DROP' % bridge)
            return bridge
        else:
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--in-interface %s -j ACCEPT' % bridge)
            iptables_manager.ipv4['filter'].add_rule('FORWARD',
                    '--out-interface %s -j ACCEPT' % bridge)

        if not _device_exists(dev):
            try:
                # First, try with 'ip'
                utils.execute('ip', 'tuntap', 'add', dev, 'mode', 'tap',
                          run_as_root=True)
            except exception.ProcessExecutionError:
                # Second option: tunctl
                utils.execute('tunctl', '-b', '-t', dev, run_as_root=True)
            utils.execute('ip', 'link', 'set', dev, "address", mac_address,
                          run_as_root=True)
            utils.execute('ip', 'link', 'set', dev, 'up', run_as_root=True)

        if not _device_exists(bridge):
            LOG.debug(_("Starting bridge %s "), bridge)
            utils.execute('brctl', 'addbr', bridge, run_as_root=True)
            utils.execute('brctl', 'setfd', bridge, str(0), run_as_root=True)
            utils.execute('brctl', 'stp', bridge, 'off', run_as_root=True)
            utils.execute('ip', 'link', 'set', bridge, "address", mac_address,
                          run_as_root=True)
            utils.execute('ip', 'link', 'set', bridge, 'up', run_as_root=True)
            LOG.debug(_("Done starting bridge %s"), bridge)

        full_ip = '%s/%s' % (network['dhcp_server'],
                             network['cidr'].rpartition('/')[2])
        utils.execute('ip', 'address', 'add', full_ip, 'dev', bridge,
                run_as_root=True)

        return dev

    def unplug(self, network):
        LOG.debug(_("inside unplug()"))
        dev = self.get_dev(network)
        try:
            utils.execute('ip', 'link', 'delete', dev, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.warning(_("Failed while unplugging gateway interface '%s'"),
                        dev)
            raise
        LOG.debug(_("Unplugged gateway interface '%s'"), dev)
        return dev

    def get_dev(self, network):
        dev = GATEWAY_INTERFACE_PREFIX + str(network['uuid'][0:11])
        return dev

    def get_bridge(self, network):
        bridge = BRDIGE_NAME_PREFIX + str(network['uuid'][0:11])
        return bridge
