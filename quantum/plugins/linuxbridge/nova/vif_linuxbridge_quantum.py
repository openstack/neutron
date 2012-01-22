# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2012 Midokura KK
# Copyright (C) 2012 Nicira, Inc
# Copyright (C) 2012 Cisco Systems, Inc
# Copyright 2012 OpenStack LLC.
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

"""
VIF driver for libvirt when QuantumManager is configured with Linux Bridge
plugin
"""

from nova import flags
from nova import log as logging
from nova.network import linux_net
from nova.virt import netutils
from nova import utils
from nova.virt.vif import VIFDriver
from nova import exception

LOG = logging.getLogger('nova.virt.libvirt.vif_linuxbridge_quantum')

FLAGS = flags.FLAGS


class QuantumLibvirtLinuxBridgeDriver(VIFDriver):
    """VIF driver for Linux Bridge."""

    def get_dev_name(_self, iface_id):
        return "tap" + iface_id[0:11]

    def plug(self, instance, network, mapping):
        iface_id = mapping['vif_uuid']
        dev = self.get_dev_name(iface_id)
        if not linux_net._device_exists(dev):
            try:
                # First, try with 'ip'
                utils.execute('ip', 'tuntap', 'add', dev, 'mode', 'tap',
                          run_as_root=True)
            except exception.ProcessExecutionError:
                # Second option: tunctl
                utils.execute('tunctl', '-b', '-t', dev, run_as_root=True)
            utils.execute('ip', 'link', 'set', dev, 'up', run_as_root=True)

        result = {
            'script': '',
            'name': dev,
            'mac_address': mapping['mac']}
        return result

    def unplug(self, instance, network, mapping):
        """Unplug the VIF from the network by deleting the port from
        the bridge."""
        dev = self.get_dev_name(mapping['vif_uuid'])
        try:
            utils.execute('ip', 'link', 'delete', dev, run_as_root=True)
        except exception.ProcessExecutionError:
            LOG.warning(_("Failed while unplugging vif of instance '%s'"),
                        instance['name'])
            raise
