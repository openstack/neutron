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
BRIDGE_PORT_FS_FOR_DEVICE = BRIDGE_FS + "%s/brport"


def get_interface_bridged_time(interface):
    try:
        return os.stat(BRIDGE_PORT_FS_FOR_DEVICE % interface).st_mtime
    except OSError:
        pass


class BridgeDevice(ip_lib.IPDevice):
    def _brctl(self, cmd, log_fail_as_error=True):
        cmd = ['brctl'] + cmd
        if self.namespace:
            cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        return utils.execute(cmd, run_as_root=True,
                             log_fail_as_error=log_fail_as_error)

    @classmethod
    def addbr(cls, name, namespace=None):
        bridge = cls(name, namespace)
        bridge._brctl(['addbr', bridge.name])
        return bridge

    def delbr(self):
        return self._brctl(['delbr', self.name])

    def addif(self, interface):
        return self._brctl(['addif', self.name, interface])

    def delif(self, interface):
        return self._brctl(['delif', self.name, interface])
