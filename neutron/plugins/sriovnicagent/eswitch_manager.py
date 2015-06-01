# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import glob
import os
import re

from oslo_log import log as logging
import six

from neutron.i18n import _LE, _LW
from neutron.plugins.sriovnicagent.common import exceptions as exc
from neutron.plugins.sriovnicagent import pci_lib

LOG = logging.getLogger(__name__)


class PciOsWrapper(object):
    """OS wrapper for checking virtual functions"""

    DEVICE_PATH = "/sys/class/net/%s/device"
    PCI_PATH = "/sys/class/net/%s/device/virtfn%s/net"
    VIRTFN_FORMAT = r"^virtfn(?P<vf_index>\d+)"
    VIRTFN_REG_EX = re.compile(VIRTFN_FORMAT)
    MAC_VTAP_PREFIX = "upper_macvtap*"

    @classmethod
    def scan_vf_devices(cls, dev_name):
        """Scan os directories to get VF devices

        @param dev_name: pf network device name
        @return: list of virtual functions
        """
        vf_list = []
        dev_path = cls.DEVICE_PATH % dev_name
        if not os.path.isdir(dev_path):
            LOG.error(_LE("Failed to get devices for %s"), dev_name)
            raise exc.InvalidDeviceError(dev_name=dev_name,
                                         reason=_("Device not found"))
        file_list = os.listdir(dev_path)
        for file_name in file_list:
            pattern_match = cls.VIRTFN_REG_EX.match(file_name)
            if pattern_match:
                vf_index = int(pattern_match.group("vf_index"))
                file_path = os.path.join(dev_path, file_name)
                if os.path.islink(file_path):
                    file_link = os.readlink(file_path)
                    pci_slot = os.path.basename(file_link)
                    vf_list.append((pci_slot, vf_index))
        if not vf_list:
            raise exc.InvalidDeviceError(
                dev_name=dev_name,
                reason=_("Device has no virtual functions"))
        return vf_list

    @classmethod
    def is_assigned_vf(cls, dev_name, vf_index):
        """Check if VF is assigned.

        Checks if a given vf index of a given device name is assigned
        by checking the relevant path in the system:
        VF is assigned if:
            Direct VF: PCI_PATH does not exist.
            Macvtap VF: upper_macvtap path exists.
        @param dev_name: pf network device name
        @param vf_index: vf index
        """
        path = cls.PCI_PATH % (dev_name, vf_index)
        if not os.path.isdir(path):
            return True
        upper_macvtap_path = os.path.join(path, "*", cls.MAC_VTAP_PREFIX)
        return bool(glob.glob(upper_macvtap_path))


class EmbSwitch(object):
    """Class to manage logical embedded switch entity.

    Embedded Switch object is logical entity representing all VFs
    connected to  same physical network
    Each physical network is mapped to PF network device interface,
    meaning all its VF, excluding the devices in exclude_device list.
    @ivar pci_slot_map: dictionary for mapping each pci slot to vf index
    @ivar pci_dev_wrapper: pci device wrapper
    """

    def __init__(self, phys_net, dev_name, exclude_devices):
        """Constructor

        @param phys_net: physical network
        @param dev_name: network device name
        @param exclude_devices: list of pci slots to exclude
        """
        self.phys_net = phys_net
        self.dev_name = dev_name
        self.pci_slot_map = {}
        self.pci_dev_wrapper = pci_lib.PciDeviceIPWrapper(dev_name)

        self._load_devices(exclude_devices)

    def _load_devices(self, exclude_devices):
        """Load devices from driver and filter if needed.

        @param exclude_devices: excluded devices mapping device_name: pci slots
        """
        scanned_pci_list = PciOsWrapper.scan_vf_devices(self.dev_name)
        for pci_slot, vf_index in scanned_pci_list:
            if pci_slot not in exclude_devices:
                self.pci_slot_map[pci_slot] = vf_index

    def get_pci_slot_list(self):
        """Get list of VF addresses."""
        return self.pci_slot_map.keys()

    def get_assigned_devices(self):
        """Get assigned Virtual Functions.

        @return: list of VF mac addresses
        """
        vf_list = []
        assigned_macs = []
        for vf_index in self.pci_slot_map.itervalues():
            if not PciOsWrapper.is_assigned_vf(self.dev_name, vf_index):
                continue
            vf_list.append(vf_index)
        if vf_list:
            assigned_macs = self.pci_dev_wrapper.get_assigned_macs(vf_list)
        return assigned_macs

    def get_device_state(self, pci_slot):
        """Get device state.

        @param pci_slot: Virtual Function address
        """
        vf_index = self.pci_slot_map.get(pci_slot)
        if vf_index is None:
            LOG.warning(_LW("Cannot find vf index for pci slot %s"),
                        pci_slot)
            raise exc.InvalidPciSlotError(pci_slot=pci_slot)
        return self.pci_dev_wrapper.get_vf_state(vf_index)

    def set_device_state(self, pci_slot, state):
        """Set device state.

        @param pci_slot: Virtual Function address
        @param state: link state
        """
        vf_index = self.pci_slot_map.get(pci_slot)
        if vf_index is None:
            LOG.warning(_LW("Cannot find vf index for pci slot %s"),
                        pci_slot)
            raise exc.InvalidPciSlotError(pci_slot=pci_slot)
        return self.pci_dev_wrapper.set_vf_state(vf_index, state)

    def get_pci_device(self, pci_slot):
        """Get mac address for given Virtual Function address

        @param pci_slot: pci slot
        @return: MAC address of virtual function
        """
        vf_index = self.pci_slot_map.get(pci_slot)
        mac = None
        if vf_index is not None:
            if PciOsWrapper.is_assigned_vf(self.dev_name, vf_index):
                macs = self.pci_dev_wrapper.get_assigned_macs([vf_index])
                if macs:
                    mac = macs[0]
        return mac


class ESwitchManager(object):
    """Manages logical Embedded Switch entities for physical network."""

    def __init__(self, device_mappings, exclude_devices):
        """Constructor.

        Create Embedded Switch logical entities for all given device mappings,
        using exclude devices.
        """
        self.emb_switches_map = {}
        self.pci_slot_map = {}

        self._discover_devices(device_mappings, exclude_devices)

    def device_exists(self, device_mac, pci_slot):
        """Verify if device exists.

        Check if a device mac exists and matches the given VF pci slot
        @param device_mac: device mac
        @param pci_slot: VF address
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            return True
        return False

    def get_assigned_devices(self, phys_net=None):
        """Get all assigned devices.

        Get all assigned devices belongs to given embedded switch
        @param phys_net: physical network, if none get all assigned devices
        @return: set of assigned VFs mac addresses
        """
        if phys_net:
            embedded_switch = self.emb_switches_map.get(phys_net, None)
            if not embedded_switch:
                return set()
            eswitch_objects = [embedded_switch]
        else:
            eswitch_objects = self.emb_switches_map.values()
        assigned_devices = set()
        for embedded_switch in eswitch_objects:
            for device_mac in embedded_switch.get_assigned_devices():
                assigned_devices.add(device_mac)
        return assigned_devices

    def get_device_state(self, device_mac, pci_slot):
        """Get device state.

        Get the device state (up/True or down/False)
        @param device_mac: device mac
        @param pci_slot: VF pci slot
        @return: device state (True/False) None if failed
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            return embedded_switch.get_device_state(pci_slot)
        return False

    def set_device_state(self, device_mac, pci_slot, admin_state_up):
        """Set device state

        Sets the device state (up or down)
        @param device_mac: device mac
        @param pci_slot: pci slot
        @param admin_state_up: device admin state True/False
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            embedded_switch.set_device_state(pci_slot,
                                             admin_state_up)

    def _discover_devices(self, device_mappings, exclude_devices):
        """Discover which Virtual functions to manage.

        Discover devices, and create embedded switch object for network device
        @param device_mappings: device mapping physical_network:device_name
        @param exclude_devices: excluded devices mapping device_name: pci slots
        """
        if exclude_devices is None:
            exclude_devices = {}
        for phys_net, dev_name in six.iteritems(device_mappings):
            self._create_emb_switch(phys_net, dev_name,
                                    exclude_devices.get(dev_name, set()))

    def _create_emb_switch(self, phys_net, dev_name, exclude_devices):
        embedded_switch = EmbSwitch(phys_net, dev_name, exclude_devices)
        self.emb_switches_map[phys_net] = embedded_switch
        for pci_slot in embedded_switch.get_pci_slot_list():
            self.pci_slot_map[pci_slot] = embedded_switch

    def _get_emb_eswitch(self, device_mac, pci_slot):
        """Get embedded switch.

        Get embedded switch by pci slot and validate pci has device mac
        @param device_mac: device mac
        @param pci_slot: pci slot
        """
        embedded_switch = self.pci_slot_map.get(pci_slot)
        if embedded_switch:
            used_device_mac = embedded_switch.get_pci_device(pci_slot)
            if used_device_mac != device_mac:
                LOG.warning(_LW("device pci mismatch: %(device_mac)s "
                                "- %(pci_slot)s"),
                            {"device_mac": device_mac, "pci_slot": pci_slot})
                embedded_switch = None
        return embedded_switch
