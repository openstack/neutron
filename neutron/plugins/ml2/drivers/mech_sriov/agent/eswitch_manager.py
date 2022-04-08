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

from neutron_lib.utils import helpers
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent import rpc as agent_rpc
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib

LOG = logging.getLogger(__name__)


IP_LINK_CAPABILITY_STATE = 'state'
IP_LINK_CAPABILITY_VLAN = 'vlan'
IP_LINK_CAPABILITY_RATE = 'max_tx_rate'
IP_LINK_CAPABILITY_MIN_TX_RATE = 'min_tx_rate'
IP_LINK_CAPABILITY_RATES = (IP_LINK_CAPABILITY_RATE,
                            IP_LINK_CAPABILITY_MIN_TX_RATE)
IP_LINK_CAPABILITY_SPOOFCHK = 'spoofchk'
IP_LINK_SUB_CAPABILITY_QOS = 'qos'


class PciOsWrapper(object):
    """OS wrapper for checking virtual functions"""

    DEVICE_PATH = "/sys/class/net/%s/device"
    PCI_PATH = "/sys/class/net/%s/device/virtfn%s/net"
    NUMVFS_PATH = "/sys/class/net/%s/device/sriov_numvfs"
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
    def is_assigned_vf_direct(cls, dev_name, vf_index):
        """Check if VF is assigned.

        Checks if a given vf index of a given device name is assigned
        as PCI passthrough by checking the relevant path in the system:
        VF is assigned if:
            Direct VF: PCI_PATH does not exist.
        @param dev_name: pf network device name
        @param vf_index: vf index
        @return: True if VF is assigned, False otherwise
        """
        path = cls.PCI_PATH % (dev_name, vf_index)
        return not os.path.isdir(path)

    @classmethod
    def get_vf_macvtap_upper_devs(cls, dev_name, vf_index):
        """Retrieve VF netdev upper (macvtap) devices.

        @param dev_name: pf network device name
        @param vf_index: vf index
        @return: list of upper net devices associated with the VF
        """
        path = cls.PCI_PATH % (dev_name, vf_index)
        upper_macvtap_path = os.path.join(path, "*", cls.MAC_VTAP_PREFIX)
        devs = [os.path.basename(dev) for dev in glob.glob(upper_macvtap_path)]
        # file name is in the format of upper_<netdev_name> extract netdev name
        return [dev.split('_')[1] for dev in devs]

    @classmethod
    def is_assigned_vf_macvtap(cls, dev_name, vf_index):
        """Check if VF is assigned.

        Checks if a given vf index of a given device name is assigned
        as macvtap by checking the relevant path in the system:
            Macvtap VF: upper_macvtap path exists.
        @param dev_name: pf network device name
        @param vf_index: vf index
        @return: True if VF is assigned, False otherwise
        """
        return bool(cls.get_vf_macvtap_upper_devs(dev_name, vf_index))

    @classmethod
    def get_numvfs(cls, dev_name):
        """Get configured number of VFs on device

        @param dev_name: pf network device name
        @return: integer number of VFs or -1
        if sriov_numvfs file not found (device doesn't support this config)
        """
        try:
            with open(cls.NUMVFS_PATH % dev_name) as f:
                numvfs = int(f.read())
                LOG.debug("Number of VFs configured on device %s: %s",
                    dev_name, numvfs)
                return numvfs
        except IOError:
            LOG.warning("Error reading sriov_numvfs file for device %s, "
                        "probably not supported by this device", dev_name)
            return -1


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
        self.scanned_pci_list = []
        self.pci_dev_wrapper = pci_lib.PciDeviceIPWrapper(dev_name)

        self._load_devices(exclude_devices)

    def _load_devices(self, exclude_devices):
        """Load devices from driver and filter if needed.

        @param exclude_devices: excluded devices mapping device_name: pci slots
        """
        self.scanned_pci_list = PciOsWrapper.scan_vf_devices(self.dev_name)
        for pci_slot, vf_index in self.scanned_pci_list:
            if pci_slot not in exclude_devices:
                self.pci_slot_map[pci_slot] = vf_index

    def _get_vfs(self):
        return self.pci_dev_wrapper.device(self.dev_name).link.get_vfs()

    def get_pci_slot_list(self):
        """Get list of VF addresses."""
        return self.pci_slot_map.keys()

    def get_assigned_devices_info(self):
        """Get assigned Virtual Functions mac and pci slot
        information and populates vf_to_pci_slot mappings

        @return: list of VF pair (mac address, pci slot)
        """
        assigned_devices_info = []
        for pci_slot, vf_index in self.pci_slot_map.items():
            mac = self.get_pci_device(pci_slot)
            if mac:
                assigned_devices_info.append(
                    agent_rpc.DeviceInfo(mac, pci_slot))
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

    def set_device_rate(self, pci_slot, rates):
        """Set device rate: max_tx_rate, min_tx_rate

        @param pci_slot: Virtual Function address
        @param rates: dictionary with rate type (str) and the value (int)
                      in Kbps. Example:
                        {'max_tx_rate': 20000, 'min_tx_rate': 10000}
                        {'max_tx_rate': 30000}
                        {'min_tx_rate': 5000}

        """
        vf_index = self._get_vf_index(pci_slot)
        # NOTE(ralonsoh): ip link sets rate in Mbps therefore we need to
        # convert the rate_kbps value from kbps to Mbps.
        # Zero means to disable the rate so the lowest rate available is 1Mbps.
        # Floating numbers are not allowed
        rates_mbps = {}
        for rate_type, rate_kbps in rates.items():
            if 0 < rate_kbps < 1000:
                rate_mbps = 1
            else:
                rate_mbps = helpers.round_val(rate_kbps / 1000.0)

            rates_mbps[rate_type] = rate_mbps

        missing_rate_types = set(IP_LINK_CAPABILITY_RATES) - rates.keys()
        if missing_rate_types:
            # A key is missing. As explained in LP#1962844, in order not to
            # delete an existing rate ('max_tx_rate', 'min_tx_rate'), it is
            # needed to read the current VF rates and set the same value again.
            vf = self._get_vfs()[int(vf_index)]
            # Devices without 'min_tx_rate' support will return None in this
            # value. If current value is 0, there is no need to set it again.
            for _type in (_type for _type in missing_rate_types if vf[_type]):
                rates_mbps[_type] = vf[_type]

        LOG.debug('Setting %s limits (in Mbps) for port VF %s',
                  rates_mbps, vf_index)
        return self.pci_dev_wrapper.set_vf_rate(vf_index, rates_mbps)

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

    def _get_macvtap_mac(self, vf_index):
        upperdevs = PciOsWrapper.get_vf_macvtap_upper_devs(
            self.dev_name, vf_index)
        # NOTE(adrianc) although there can be many macvtap upper
        # devices, we expect to have excatly one.
        if len(upperdevs) > 1:
            LOG.warning("Found more than one macvtap upper device for PF "
                        "%(pf)s with VF index %(vf_index)s.",
                        {"pf": self.dev_name, "vf_index": vf_index})
        upperdev = upperdevs[0]
        return pci_lib.PciDeviceIPWrapper(
            upperdev).device(upperdev).link.address

    def get_pci_device(self, pci_slot):
        """Get mac address for given Virtual Function address

        @param pci_slot: pci slot
        @return: MAC address of virtual function
        """
        if not PciOsWrapper.pf_device_exists(self.dev_name):
            # If the root PCI path does not exist, then the VF cannot
            # actually have been allocated and there is no way we can
            # manage it.
            return None

        vf_index = self.pci_slot_map.get(pci_slot)
        mac = None

        if vf_index is not None:
            # NOTE(adrianc) for VF passthrough take administrative mac from PF
            # netdevice, for macvtap take mac directly from macvtap interface.
            # This is done to avoid relying on hypervisor [lack of] logic to
            # keep effective and administrative mac in sync.
            if PciOsWrapper.is_assigned_vf_direct(self.dev_name, vf_index):
                macs = self.pci_dev_wrapper.get_assigned_macs([vf_index])
                mac = macs.get(vf_index)
            elif PciOsWrapper.is_assigned_vf_macvtap(
                    self.dev_name, vf_index):
                mac = self._get_macvtap_mac(vf_index)
        return mac


class ESwitchManager(object):
    """Manages logical Embedded Switch entities for physical network."""

    def __new__(cls):
        # make it a singleton
        if not hasattr(cls, '_instance'):
            cls._instance = super(ESwitchManager, cls).__new__(cls)
            cls.emb_switches_map = {}
            cls.pci_slot_map = {}
            cls.skipped_devices = set()
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
        return pci_lib.LinkState.disable.name

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
                pci_slot, {IP_LINK_CAPABILITY_RATE: max_kbps})

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
                pci_slot, {IP_LINK_CAPABILITY_MIN_TX_RATE: min_kbps})

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
        numvfs = PciOsWrapper.get_numvfs(dev_name)
        if numvfs == 0:
            # numvfs might be 0 on pre-up state of a device
            # giving such devices one more chance to initialize
            if dev_name not in self.skipped_devices:
                self.skipped_devices.add(dev_name)
                LOG.info("Device %s has 0 VFs configured. Skipping "
                         "for now to let the device initialize", dev_name)
                return
            else:
                # looks like device indeed has 0 VFs configured
                # it is probably used just as direct-physical
                LOG.info("Device %s has 0 VFs configured", dev_name)

        numvfs_cur = len(embedded_switch.scanned_pci_list)
        if numvfs >= 0 and numvfs > numvfs_cur:
            LOG.info("Not all VFs were initialized on device %(device)s: "
                     "expected - %(expected)s, actual - %(actual)s. Skipping.",
                     {'device': dev_name, 'expected': numvfs,
                      'actual': numvfs_cur})
            self.skipped_devices.add(dev_name)
            return

        self.emb_switches_map.setdefault(phys_net, []).append(embedded_switch)
        for pci_slot in embedded_switch.get_pci_slot_list():
            self.pci_slot_map[pci_slot] = embedded_switch
        self.skipped_devices.discard(dev_name)

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
        self._clear_rate(pci_slot, IP_LINK_CAPABILITY_RATE)

    def clear_min_tx_rate(self, pci_slot):
        """Clear the VF "min_tx_rate" parameter

        Clear the "min_tx_rate" configuration from VF by setting it to 0.
        @param pci_slot: VF PCI slot
        """
        self._clear_rate(pci_slot, IP_LINK_CAPABILITY_MIN_TX_RATE)

    def _clear_rate(self, pci_slot, rate_type):
        """Clear the VF rate parameter specified in rate_type

        Clear the rate configuration from VF by setting it to 0.
        @param pci_slot: VF PCI slot
        @param rate_type: rate to clear ('max_tx_rate', 'min_tx_rate')
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
                embedded_switch.set_device_rate(pci_slot, {rate_type: 0})
            else:
                LOG.warning("VF with PCI slot %(pci_slot)s is already "
                            "assigned; skipping reset for '%(rate_type)s' "
                            "device configuration parameter",
                            {'pci_slot': pci_slot, 'rate_type': rate_type})
        else:
            LOG.error("PCI slot %(pci_slot)s has no mapping to Embedded "
                      "Switch; skipping", {'pci_slot': pci_slot})
