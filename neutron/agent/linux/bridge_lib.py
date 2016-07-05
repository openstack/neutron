# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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

import os

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils

# NOTE(toabctl): Don't use /sys/devices/virtual/net here because not all tap
# devices are listed here (i.e. when using Xen)
BRIDGE_FS = "/sys/class/net/"
BRIDGE_INTERFACE_FS = BRIDGE_FS + "%(bridge)s/brif/%(interface)s"
BRIDGE_INTERFACES_FS = BRIDGE_FS + "%s/brif/"
BRIDGE_PORT_FS_FOR_DEVICE = BRIDGE_FS + "%s/brport"
BRIDGE_PATH_FOR_DEVICE = BRIDGE_PORT_FS_FOR_DEVICE + '/bridge'


def is_bridged_interface(interface):
    if not interface:
        return False
    else:
        return os.path.exists(BRIDGE_PORT_FS_FOR_DEVICE % interface)


def get_interface_bridged_time(interface):
    try:
        return os.stat(BRIDGE_PORT_FS_FOR_DEVICE % interface).st_mtime
    except OSError:
        pass


def get_bridge_names():
    return os.listdir(BRIDGE_FS)


class BridgeDevice(ip_lib.IPDevice):
    def _brctl(self, cmd):
        cmd = ['brctl'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True)

    @classmethod
    def addbr(cls, name, namespace=None):
        bridge = cls(name, namespace)
        bridge._brctl(['addbr', bridge.name])
        return bridge

    @classmethod
    def get_interface_bridge(cls, interface):
        try:
            path = os.readlink(BRIDGE_PATH_FOR_DEVICE % interface)
        except OSError:
            return None
        else:
            name = path.rpartition('/')[-1]
            return cls(name)

    def delbr(self):
        return self._brctl(['delbr', self.name])

    def addif(self, interface):
        return self._brctl(['addif', self.name, interface])

    def delif(self, interface):
        return self._brctl(['delif', self.name, interface])

    def setfd(self, fd):
        return self._brctl(['setfd', self.name, str(fd)])

    def disable_stp(self):
        return self._brctl(['stp', self.name, 'off'])

    def owns_interface(self, interface):
        return os.path.exists(
            BRIDGE_INTERFACE_FS % {'bridge': self.name,
                                   'interface': interface})

    def get_interfaces(self):
        try:
            return os.listdir(BRIDGE_INTERFACES_FS % self.name)
        except OSError:
            return []


class FdbInterface(object):
    """provide basic functionality to edit the FDB table"""

    @classmethod
    def add(cls, mac, dev):
        return utils.execute(['bridge', 'fdb', 'add', mac, 'dev', dev],
                run_as_root=True)

    @classmethod
    def delete(cls, mac, dev):
        return utils.execute(['bridge', 'fdb', 'delete', mac, 'dev', dev],
                             run_as_root=True)

    @classmethod
    def show(cls, dev=None):
        cmd = ['bridge', 'fdb', 'show']
        if dev:
            cmd += ['dev', dev]
        return utils.execute(cmd, run_as_root=True)
