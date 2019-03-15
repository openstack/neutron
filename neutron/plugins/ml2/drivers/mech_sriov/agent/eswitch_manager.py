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

import os
import re

from neutron_lib.utils import helpers
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.linux import ip_link_support
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib

LOG = logging.getLogger(__name__)


class PciOsWrapper(object):
    """OS wrapper for checking virtual functions"""

    DEVICE_PATH = "/sys/class/net/%s/device"
    PCI_PATH = "/sys/class/net/%s/device/virtfn%s/net"
    VIRTFN_FORMAT = r"^virtfn(?P<vf_index>\d+)"
    VIRTFN_REG_EX = re.compile(VIRTFN_FORMAT)

    @classmethod
    def scan_vf_devices(cls, dev_name):
        """Scan os directories to get VF devices

        @param dev_name: pf network device name
        @return: list of virtual functions
        """
        vf_list = []
        dev_path = cls.DEVICE_PATH % dev_name
        if not os.path.isdir(dev_path):
            LOG.error("Failed to get devices for %s", dev_name)
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
        return vf_list

    @classmethod
    def pf_device_exists(cls, dev_name):
        return os.path.isdir(cls.DEVICE_PATH % dev_name)

    @classmethod
    def is_assigned_vf(cls, dev_name, vf_index, ip_link_show_output):
        """Check if VF is assigned.

        Checks if a given vf index of a given device name is assigned
        by checking the relevant path in the system:
        VF is assigned if:
            Direct VF: PCI_PATH does not exist.
            Macvtap VF: macvtap@<vf interface> interface exists in ip link show
        @param dev_name: pf network device name
        @param vf_index: vf index
        @param ip_link_show_output: 'ip link show' output
        """

        if not cls.pf_device_exists(dev_name):
            # If the root PCI path does not exist, then the VF cannot
            # actually have been allocated and there is no way we can
            # manage it.
            return False

        path = cls.PCI_PATH % (dev_name, vf_index)

        try:
            ifname_list = os.listdir(path)
        except OSError:
            # PCI_PATH does not exist means that the DIRECT VF assigned
            return True

        # Note(moshele) kernel < 3.13 doesn't create symbolic link
        # for macvtap interface. Therefore we workaround it
        # by parsing ip link show and checking if macvtap interface exists
        for ifname in ifname_list:
            if pci_lib.PciDeviceIPWrapper.is_macvtap_assigned(
                    ifname, ip_link_show_output):
                return True
        return False


class EmbSwitch(object):
    """Class to manage logical embedded switch entity.

    Embedded Switch object is logical entity representing all VFs
    connected to  same physical network
    Each physical network is mapped to PF network device interface,
    meaning all its VF, excluding the devices in exclude_device list.
    @ivar pci_slot_map: dictionary for mapping each pci slot to vf index
    @ivar pci_dev_wrapper: pci device wrapper
    """

    def __init__(self, dev_name, exclude_devices):
        """Constructor

        @param dev_name: network device name
        @param exclude_devices: list of pci slots to exclude
        """
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

    def get_assigned_devices_info(self):
        """Get assigned Virtual Functions mac and pci slot
        information and populates vf_to_pci_slot mappings

        @return: list of VF pair (mac address, pci slot)
        """
        vf_to_pci_slot_mapping = {}
        assigned_devices_info = []
        ls = self.pci_dev_wrapper.link_show()
        for pci_slot, vf_index in self.pci_slot_map.items():
            if not PciOsWrapper.is_assigned_vf(self.dev_name, vf_index, ls):
                continue
            vf_to_pci_slot_mapping[vf_index] = pci_slot
        if vf_to_pci_slot_mapping:
            vf_to_mac_mapping = self.pci_dev_wrapper.get_assigned_macs(
                list(vf_to_pci_slot_mapping.keys()))
            for vf_index, mac in vf_to_mac_mapping.items():
                pci_slot = vf_to_pci_slot_mapping[vf_index]
                assigned_devices_info.append((mac, pci_slot))
        return assigned_devices_info

    def get_device_state(self, pci_slot):
        """Get device state.

        @param pci_slot: Virtual Function address
        """
        vf_index = self._get_vf_index(pci_slot)
        return self.pci_dev_wrapper.get_vf_state(vf_index)

    def set_device_state(self, pci_slot, state, propagate_uplink_state):
        """Set device state.

        @param pci_slot: Virtual Function address
        @param state: link state
        """
        vf_index = self._get_vf_index(pci_slot)
        return self.pci_dev_wrapper.set_vf_state(vf_index, state,
                                                 auto=propagate_uplink_state)

    def set_device_rate(self, pci_slot, rate_type, rate_kbps):
        """Set device rate: rate (max_tx_rate), min_tx_rate

        @param pci_slot: Virtual Function address
        @param rate_type: device rate name type. Could be 'rate' and
                          'min_tx_rate'.
        @param rate_kbps: device rate in kbps
        """
        vf_index = self._get_vf_index(pci_slot)
        # NOTE(ralonsoh): ip link sets rate in Mbps therefore we need to
        # convert the rate_kbps value from kbps to Mbps.
        # Zero means to disable the rate so the lowest rate available is 1Mbps.
        # Floating numbers are not allowed
        if 0 < rate_kbps < 1000:
            rate_mbps = 1
        else:
            rate_mbps = helpers.round_val(rate_kbps / 1000.0)

        log_dict = {
            'rate_mbps': rate_mbps,
            'rate_kbps': rate_kbps,
            'vf_index': vf_index,
            'rate_type': rate_type
        }
        if rate_kbps % 1000 != 0:
            LOG.debug("'%(rate_type)s' for SR-IOV ports is counted in Mbps; "
                      "setting %(rate_mbps)s Mbps limit for port %(vf_index)s "
                      "instead of %(rate_kbps)s kbps",
                      log_dict)
        else:
            LOG.debug("Setting %(rate_mbps)s Mbps limit for port %(vf_index)s",
                      log_dict)

        return self.pci_dev_wrapper.set_vf_rate(vf_index, rate_type, rate_mbps)

    def _get_vf_index(self, pci_slot):
        vf_index = self.pci_slot_map.get(pci_slot)
        if vf_index is None:
            LOG.warning("Cannot find vf index for pci slot %s",
                        pci_slot)
            raise exc.InvalidPciSlotError(pci_slot=pci_slot)
        return vf_index

    def set_device_spoofcheck(self, pci_slot, enabled):
        """Set device spoofchecking

        @param pci_slot: Virtual Function address
        @param enabled: True to enable spoofcheck, False to disable
        """
        vf_index = self.pci_slot_map.get(pci_slot)
        if vf_index is None:
            raise exc.InvalidPciSlotError(pci_slot=pci_slot)
        return self.pci_dev_wrapper.set_vf_spoofcheck(vf_index, enabled)

    def get_pci_device(self, pci_slot):
        """Get mac address for given Virtual Function address

        @param pci_slot: pci slot
        @return: MAC address of virtual function
        """
        vf_index = self.pci_slot_map.get(pci_slot)
        mac = None
        if vf_index is not None:
            ls = self.pci_dev_wrapper.link_show()
            if PciOsWrapper.is_assigned_vf(self.dev_name, vf_index, ls):
                macs = self.pci_dev_wrapper.get_assigned_macs([vf_index])
                mac = macs.get(vf_index)
        return mac


class ESwitchManager(object):
    """Manages logical Embedded Switch entities for physical network."""

    def __new__(cls):
        # make it a singleton
        if not hasattr(cls, '_instance'):
            cls._instance = super(ESwitchManager, cls).__new__(cls)
            cls.emb_switches_map = {}
            cls.pci_slot_map = {}
        return cls._instance

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

    def get_assigned_devices_info(self, phys_net=None):
        """Get all assigned devices.

        Get all assigned devices belongs to given embedded switch
        @param phys_net: physical network, if none get all assigned devices
        @return: set of assigned VFs (mac address, pci slot) pair
        """
        if phys_net:
            eswitch_objects = self.emb_switches_map.get(phys_net, set())
        else:
            eswitch_objects = set()
            for eswitch_list in self.emb_switches_map.values():
                eswitch_objects |= set(eswitch_list)
        assigned_devices = set()
        for embedded_switch in eswitch_objects:
            for device in embedded_switch.get_assigned_devices_info():
                assigned_devices.add(device)
        return assigned_devices

    def get_device_state(self, device_mac, pci_slot):
        """Get device state.

        Get the device state (up/enable, down/disable, or auto)
        @param device_mac: device mac
        @param pci_slot: VF PCI slot
        @return: device state (enable/disable/auto) None if failed
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            return embedded_switch.get_device_state(pci_slot)
        return pci_lib.LinkState.DISABLE

    def set_device_max_rate(self, device_mac, pci_slot, max_kbps):
        """Set device max rate

        Sets the device max rate in kbps
        @param device_mac: device mac
        @param pci_slot: pci slot
        @param max_kbps: device max rate in kbps
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            embedded_switch.set_device_rate(
                pci_slot,
                ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_RATE,
                max_kbps)

    def set_device_min_tx_rate(self, device_mac, pci_slot, min_kbps):
        """Set device min_tx_rate

        Sets the device min_tx_rate in kbps
        @param device_mac: device mac
        @param pci_slot: pci slot
        @param max_kbps: device min_tx_rate in kbps
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            embedded_switch.set_device_rate(
                pci_slot,
                ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_MIN_TX_RATE,
                min_kbps)

    def set_device_state(self, device_mac, pci_slot, admin_state_up,
                         propagate_uplink_state):
        """Set device state

        Sets the device state (up or down)
        @param device_mac: device mac
        @param pci_slot: pci slot
        @param admin_state_up: device admin state True/False
        @param propagate_uplink_state: follow uplink state True/False
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            embedded_switch.set_device_state(pci_slot,
                                             admin_state_up,
                                             propagate_uplink_state)

    def set_device_spoofcheck(self, device_mac, pci_slot, enabled):
        """Set device spoofcheck

        Sets device spoofchecking (enabled or disabled)
        @param device_mac: device mac
        @param pci_slot: pci slot
        @param enabled: device spoofchecking
        """
        embedded_switch = self._get_emb_eswitch(device_mac, pci_slot)
        if embedded_switch:
            embedded_switch.set_device_spoofcheck(pci_slot,
                                                  enabled)

    def _process_emb_switch_map(self, phys_net, dev_name, exclude_devices):
        """Process emb_switch_map
        @param phys_net: physical network
        @param dev_name: device name
        @param exclude_devices: PCI devices to ignore.
        """
        emb_switches = self.emb_switches_map.get(phys_net, [])
        for switch in emb_switches:
            if switch.dev_name == dev_name:
                if not PciOsWrapper.pf_device_exists(dev_name):
                    # If the device is given to the VM as PCI-PT
                    # then delete the respective emb_switch from map
                    self.emb_switches_map.get(phys_net).remove(switch)
                return

        # We don't know about this device at the moment, so add to the map.
        if PciOsWrapper.pf_device_exists(dev_name):
            self._create_emb_switch(
                phys_net, dev_name,
                exclude_devices.get(dev_name, set()))

    def discover_devices(self, device_mappings, exclude_devices):
        """Discover which Virtual functions to manage.

        Discover devices, and create embedded switch object for network device
        @param device_mappings: device mapping physical_network:device_name
        @param exclude_devices: excluded devices mapping device_name: pci slots
        """
        if exclude_devices is None:
            exclude_devices = {}
        for phys_net, dev_names in device_mappings.items():
            for dev_name in dev_names:
                self._process_emb_switch_map(phys_net, dev_name,
                                             exclude_devices)

    def _create_emb_switch(self, phys_net, dev_name, exclude_devices):
        embedded_switch = EmbSwitch(dev_name, exclude_devices)
        self.emb_switches_map.setdefault(phys_net, []).append(embedded_switch)
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
                LOG.warning("device pci mismatch: %(device_mac)s "
                            "- %(pci_slot)s",
                            {"device_mac": device_mac, "pci_slot": pci_slot})
                embedded_switch = None
        return embedded_switch

    def clear_max_rate(self, pci_slot):
        """Clear the VF "rate" parameter

        Clear the "rate" configuration from VF by setting it to 0.
        @param pci_slot: VF PCI slot
        """
        self._clear_rate(
            pci_slot,
            ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_RATE)

    def clear_min_tx_rate(self, pci_slot):
        """Clear the VF "min_tx_rate" parameter

        Clear the "min_tx_rate" configuration from VF by setting it to 0.
        @param pci_slot: VF PCI slot
        """
        self._clear_rate(
            pci_slot,
            ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_MIN_TX_RATE)

    def _clear_rate(self, pci_slot, rate_type):
        """Clear the VF rate parameter specified in rate_type

        Clear the rate configuration from VF by setting it to 0.
        @param pci_slot: VF PCI slot
        @param rate_type: rate to clear ('rate', 'min_tx_rate')
        """
        # NOTE(Moshe Levi): we don't use the self._get_emb_eswitch here,
        # because when clearing the VF it may be not assigned. This happens
        # when libvirt releases the VF back to the hypervisor on delete VM.
        # Therefore we should just clear the VF rate according to pci_slot no
        # matter if VF is assigned or not.
        embedded_switch = self.pci_slot_map.get(pci_slot)
        if embedded_switch:
            # NOTE(Moshe Levi): check the pci_slot is not assigned to some
            # other port before resetting the rate.
            if embedded_switch.get_pci_device(pci_slot) is None:
                embedded_switch.set_device_rate(pci_slot, rate_type, 0)
            else:
                LOG.warning("VF with PCI slot %(pci_slot)s is already "
                            "assigned; skipping reset for '%(rate_type)s' "
                            "device configuration parameter",
                            {'pci_slot': pci_slot, 'rate_type': rate_type})
        else:
            LOG.error("PCI slot %(pci_slot)s has no mapping to Embedded "
                      "Switch; skipping", {'pci_slot': pci_slot})
