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

import collections
import functools
import os

from pyroute2.netlink import exceptions as netlink_exceptions

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib

# NOTE(toabctl): Don't use /sys/devices/virtual/net here because not all tap
# devices are listed here (i.e. when using Xen)
BRIDGE_FS = "/sys/class/net/"
BRIDGE_INTERFACE_FS = BRIDGE_FS + "%(bridge)s/brif/%(interface)s"
BRIDGE_INTERFACES_FS = BRIDGE_FS + "%s/brif/"
BRIDGE_PORT_FS_FOR_DEVICE = BRIDGE_FS + "%s/brport"
BRIDGE_PATH_FOR_DEVICE = BRIDGE_PORT_FS_FOR_DEVICE + '/bridge'


def catch_exceptions(function):
    """Catch bridge command exceptions

    Returns True if succeeds and False if fails
    """
    @functools.wraps(function)
    def decorated_function(self, *args, **kwargs):
        try:
            function(self, *args, **kwargs)
            return True
        except (RuntimeError, OSError, netlink_exceptions.NetlinkError):
            return False

    return decorated_function


def is_bridged_interface(interface):
    if not interface:
        return False
    return os.path.exists(BRIDGE_PORT_FS_FOR_DEVICE % interface)


def get_interface_ifindex(interface):
    try:
        with open(os.path.join(BRIDGE_FS, interface, 'ifindex')) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        pass


def get_bridge_names():
    return os.listdir(BRIDGE_FS)


class BridgeDevice(ip_lib.IPDevice):

    @classmethod
    def addbr(cls, name, namespace=None):
        bridge = cls(name, namespace, 'bridge')
        try:
            bridge.link.create()
        except priv_ip_lib.InterfaceAlreadyExists:
            pass
        return bridge

    @classmethod
    def get_interface_bridge(cls, interface):
        try:
            path = os.readlink(BRIDGE_PATH_FOR_DEVICE % interface)
        except OSError:
            return None
        name = path.rpartition('/')[-1]
        return cls(name)

    def delbr(self):
        return self.link.delete()

    @catch_exceptions
    def addif(self, interface):
        priv_ip_lib.set_link_bridge_master(interface, self.name,
                                           namespace=self.namespace)

    @catch_exceptions
    def delif(self, interface):
        priv_ip_lib.set_link_bridge_master(interface, None,
                                           namespace=self.namespace)

    @catch_exceptions
    def setfd(self, fd):
        priv_ip_lib.set_link_bridge_forward_delay(self.name, fd,
                                                  namespace=self.namespace)

    @catch_exceptions
    def disable_stp(self):
        priv_ip_lib.set_link_bridge_stp(self.name, 0, namespace=self.namespace)

    @catch_exceptions
    def enable_stp(self):
        priv_ip_lib.set_link_bridge_stp(self.name, 1, namespace=self.namespace)

    def owns_interface(self, interface):
        return os.path.exists(
            BRIDGE_INTERFACE_FS % {'bridge': self.name,
                                   'interface': interface})

    def get_interfaces(self):
        try:
            return os.listdir(BRIDGE_INTERFACES_FS % self.name)
        except OSError:
            return []


class FdbInterface:
    """Provide basic functionality to edit the FDB table"""

    @staticmethod
    @catch_exceptions
    def add(mac, dev, dst_ip=None, namespace=None, **kwargs):
        priv_ip_lib.add_bridge_fdb(mac, dev, dst_ip=dst_ip,
                                   namespace=namespace, **kwargs)

    @staticmethod
    @catch_exceptions
    def append(mac, dev, dst_ip=None, namespace=None, **kwargs):
        priv_ip_lib.append_bridge_fdb(mac, dev, dst_ip=dst_ip,
                                      namespace=namespace, **kwargs)

    @staticmethod
    @catch_exceptions
    def replace(mac, dev, dst_ip=None, namespace=None, **kwargs):
        try:
            priv_ip_lib.delete_bridge_fdb(mac, dev, namespace=namespace,
                                          **kwargs)
        except (RuntimeError, OSError, netlink_exceptions.NetlinkError):
            pass
        priv_ip_lib.add_bridge_fdb(mac, dev, dst_ip=dst_ip,
                                   namespace=namespace, **kwargs)

    @staticmethod
    @catch_exceptions
    def delete(mac, dev, dst_ip=None, namespace=None, **kwargs):
        priv_ip_lib.delete_bridge_fdb(mac, dev, dst_ip=dst_ip,
                                      namespace=namespace, **kwargs)

    @staticmethod
    def show(dev=None, namespace=None, **kwargs):
        """List the FDB entries in a namespace

        :parameter dev: device name to filter the query
        :parameter namespace: namespace name
        :returns: a dictionary with the device names and the list of entries
                  per device.
        """

        def find_device_name(ifindex, devices):
            for device in (device for device in devices if
                           device['index'] == ifindex):
                return device['name']

        ret = collections.defaultdict(list)
        fdbs = priv_ip_lib.list_bridge_fdb(namespace=namespace, **kwargs)
        devices = ip_lib.get_devices_info(namespace)
        for fdb in fdbs:
            name = find_device_name(fdb['ifindex'], devices)
            if dev and dev != name:
                continue

            master = find_device_name(linux_utils.get_attr(fdb, 'NDA_MASTER'),
                                      devices)
            fdb_info = {'mac': linux_utils.get_attr(fdb, 'NDA_LLADDR'),
                        'master': master,
                        'vlan': linux_utils.get_attr(fdb, 'NDA_VLAN'),
                        'dst_ip': linux_utils.get_attr(fdb, 'NDA_DST')}
            ret[name].append(fdb_info)

        return ret
