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


import contextlib
import os

import mock
import testtools


from neutron.plugins.sriovnicagent.common import exceptions as exc
from neutron.plugins.sriovnicagent import eswitch_manager as esm
from neutron.tests import base


class TestCreateESwitchManager(base.BaseTestCase):
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]

    def test_create_eswitch_mgr_fail(self):
        device_mappings = {'physnet1': 'p6p1'}
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.scan_vf_devices",
                       side_effect=exc.InvalidDeviceError(dev_name="p6p1",
                                                          reason="device"
                                                          " not found")),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):

            with testtools.ExpectedException(exc.InvalidDeviceError):
                esm.ESwitchManager(device_mappings, None)

    def test_create_eswitch_mgr_ok(self):
        device_mappings = {'physnet1': 'p6p1'}
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.scan_vf_devices",
                       return_value=self.SCANNED_DEVICES),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):

            esm.ESwitchManager(device_mappings, None)


class TestESwitchManagerApi(base.BaseTestCase):
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]

    ASSIGNED_MAC = '00:00:00:00:00:66'
    PCI_SLOT = '0000:06:00.1'
    WRONG_MAC = '00:00:00:00:00:67'
    WRONG_PCI = "0000:06:00.6"

    def setUp(self):
        super(TestESwitchManagerApi, self).setUp()
        device_mappings = {'physnet1': 'p6p1'}
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.scan_vf_devices",
                       return_value=self.SCANNED_DEVICES),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):
            self.eswitch_mgr = esm.ESwitchManager(device_mappings, None)

    def test_get_assigned_devices(self):
        with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                        "EmbSwitch.get_assigned_devices",
                        return_value=[self.ASSIGNED_MAC]):
            result = self.eswitch_mgr.get_assigned_devices()
            self.assertEqual(set([self.ASSIGNED_MAC]), result)

    def test_get_device_status_true(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_pci_device",
                       return_value=self.ASSIGNED_MAC),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_device_state",
                       return_value=True)):
            result = self.eswitch_mgr.get_device_state(self.ASSIGNED_MAC,
                                                       self.PCI_SLOT)
            self.assertTrue(result)

    def test_get_device_status_false(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_pci_device",
                       return_value=self.ASSIGNED_MAC),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_device_state",
                       return_value=False)):
            result = self.eswitch_mgr.get_device_state(self.ASSIGNED_MAC,
                                                       self.PCI_SLOT)
            self.assertFalse(result)

    def test_get_device_status_mismatch(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_pci_device",
                       return_value=self.ASSIGNED_MAC),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_device_state",
                       return_value=True)):
            with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                            "LOG.warning") as log_mock:
                result = self.eswitch_mgr.get_device_state(self.WRONG_MAC,
                                                           self.PCI_SLOT)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})
                self.assertFalse(result)

    def test_set_device_status(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_pci_device",
                       return_value=self.ASSIGNED_MAC),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.set_device_state")):
            self.eswitch_mgr.set_device_state(self.ASSIGNED_MAC,
                                              self.PCI_SLOT, True)

    def test_set_device_status_mismatch(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.get_pci_device",
                       return_value=self.ASSIGNED_MAC),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "EmbSwitch.set_device_state")):
            with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                            "LOG.warning") as log_mock:
                self.eswitch_mgr.set_device_state(self.WRONG_MAC,
                                                  self.PCI_SLOT, True)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})

    def _mock_device_exists(self, pci_slot, mac_address, expected_result):
        with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                        "EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC):
            result = self.eswitch_mgr.device_exists(mac_address,
                                                    pci_slot)
            self.assertEqual(expected_result, result)

    def test_device_exists_true(self):
        self._mock_device_exists(self.PCI_SLOT,
                                 self.ASSIGNED_MAC,
                                 True)

    def test_device_exists_false(self):
        self._mock_device_exists(self.WRONG_PCI,
                                 self.WRONG_MAC,
                                 False)

    def test_device_exists_mismatch(self):
        with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                        "EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC):
            with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                            "LOG.warning") as log_mock:
                result = self.eswitch_mgr.device_exists(self.WRONG_MAC,
                                                        self.PCI_SLOT)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})
                self.assertFalse(result)


class TestEmbSwitch(base.BaseTestCase):
    DEV_NAME = "eth2"
    PHYS_NET = "default"
    ASSIGNED_MAC = '00:00:00:00:00:66'
    PCI_SLOT = "0000:06:00.1"
    WRONG_PCI_SLOT = "0000:06:00.4"
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]

    def setUp(self):
        super(TestEmbSwitch, self).setUp()
        exclude_devices = set()
        with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                        "PciOsWrapper.scan_vf_devices",
                        return_value=self.SCANNED_DEVICES):
            self.emb_switch = esm.EmbSwitch(self.PHYS_NET, self.DEV_NAME,
                                            exclude_devices)

    def test_get_assigned_devices(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                       "PciDeviceIPWrapper.get_assigned_macs",
                       return_value=[self.ASSIGNED_MAC]),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):
            result = self.emb_switch.get_assigned_devices()
            self.assertEqual([self.ASSIGNED_MAC], result)

    def test_get_assigned_devices_empty(self):
        with mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                        "PciOsWrapper.is_assigned_vf",
                        return_value=False):
            result = self.emb_switch.get_assigned_devices()
            self.assertFalse(result)

    def test_get_device_state_ok(self):
        with mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                        "PciDeviceIPWrapper.get_vf_state",
                        return_value=False):
            result = self.emb_switch.get_device_state(self.PCI_SLOT)
            self.assertFalse(result)

    def test_get_device_state_fail(self):
        with mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                        "PciDeviceIPWrapper.get_vf_state",
                        return_value=False):
            self.assertRaises(exc.InvalidPciSlotError,
                              self.emb_switch.get_device_state,
                              self.WRONG_PCI_SLOT)

    def test_set_device_state_ok(self):
        with mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_state"):
            with mock.patch("neutron.plugins.sriovnicagent.pci_lib.LOG."
                            "warning") as log_mock:
                self.emb_switch.set_device_state(self.PCI_SLOT, True)
                self.assertEqual(0, log_mock.call_count)

    def test_set_device_state_fail(self):
        with mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_state"):
            self.assertRaises(exc.InvalidPciSlotError,
                              self.emb_switch.set_device_state,
                              self.WRONG_PCI_SLOT, True)

    def test_get_pci_device(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                       "PciDeviceIPWrapper.get_assigned_macs",
                       return_value=[self.ASSIGNED_MAC]),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):
            result = self.emb_switch.get_pci_device(self.PCI_SLOT)
            self.assertEqual(self.ASSIGNED_MAC, result)

    def test_get_pci_device_fail(self):
        with contextlib.nested(
            mock.patch("neutron.plugins.sriovnicagent.pci_lib."
                       "PciDeviceIPWrapper.get_assigned_macs",
                       return_value=[self.ASSIGNED_MAC]),
            mock.patch("neutron.plugins.sriovnicagent.eswitch_manager."
                       "PciOsWrapper.is_assigned_vf",
                       return_value=True)):
            result = self.emb_switch.get_pci_device(self.WRONG_PCI_SLOT)
            self.assertIsNone(result)

    def test_get_pci_list(self):
        result = self.emb_switch.get_pci_slot_list()
        self.assertEqual([tup[0] for tup in self.SCANNED_DEVICES],
                         sorted(result))


class TestPciOsWrapper(base.BaseTestCase):
    DEV_NAME = "p7p1"
    VF_INDEX = 1
    DIR_CONTENTS = [
        "mlx4_port1",
        "virtfn0",
        "virtfn1",
        "virtfn2"
    ]
    DIR_CONTENTS_NO_MATCH = [
        "mlx4_port1",
        "mlx4_port1"
    ]
    LINKS = {
        "virtfn0": "../0000:04:00.1",
        "virtfn1": "../0000:04:00.2",
        "virtfn2": "../0000:04:00.3"
    }
    PCI_SLOTS = [
        ('0000:04:00.1', 0),
        ('0000:04:00.2', 1),
        ('0000:04:00.3', 2)
    ]

    def test_scan_vf_devices(self):
        def _get_link(file_path):
            file_name = os.path.basename(file_path)
            return self.LINKS[file_name]

        with contextlib.nested(
            mock.patch("os.path.isdir",
                       return_value=True),
            mock.patch("os.listdir",
                       return_value=self.DIR_CONTENTS),
            mock.patch("os.path.islink",
                       return_value=True),
            mock.patch("os.readlink",
                       side_effect=_get_link),):
            result = esm.PciOsWrapper.scan_vf_devices(self.DEV_NAME)
            self.assertEqual(self.PCI_SLOTS, result)

    def test_scan_vf_devices_no_dir(self):
        with mock.patch("os.path.isdir", return_value=False):
            self.assertRaises(exc.InvalidDeviceError,
                              esm.PciOsWrapper.scan_vf_devices,
                              self.DEV_NAME)

    def test_scan_vf_devices_no_content(self):
        with contextlib.nested(
            mock.patch("os.path.isdir",
                       return_value=True),
            mock.patch("os.listdir",
                       return_value=[])):
            self.assertRaises(exc.InvalidDeviceError,
                              esm.PciOsWrapper.scan_vf_devices,
                              self.DEV_NAME)

    def test_scan_vf_devices_no_match(self):
        with contextlib.nested(
            mock.patch("os.path.isdir",
                       return_value=True),
            mock.patch("os.listdir",
                       return_value=self.DIR_CONTENTS_NO_MATCH)):
            self.assertRaises(exc.InvalidDeviceError,
                              esm.PciOsWrapper.scan_vf_devices,
                              self.DEV_NAME)

    def _mock_assign_vf(self, dir_exists):
        with mock.patch("os.path.isdir",
                        return_value=dir_exists):
            result = esm.PciOsWrapper.is_assigned_vf(self.DEV_NAME,
                                                     self.VF_INDEX)
            self.assertEqual(not dir_exists, result)

    def test_is_assigned_vf_true(self):
        self._mock_assign_vf(True)

    def test_is_assigned_vf_false(self):
        self._mock_assign_vf(False)

    def _mock_assign_vf_macvtap(self, macvtap_exists):
        def _glob(file_path):
            return ["upper_macvtap0"] if macvtap_exists else []

        with contextlib.nested(
            mock.patch("os.path.isdir",
                       return_value=True),
            mock.patch("glob.glob",
                       side_effect=_glob)):
            result = esm.PciOsWrapper.is_assigned_vf(self.DEV_NAME,
                                                     self.VF_INDEX)
            self.assertEqual(macvtap_exists, result)

    def test_is_assigned_vf_macvtap_true(self):
        self._mock_assign_vf_macvtap(True)

    def test_is_assigned_vf_macvtap_false(self):
        self._mock_assign_vf_macvtap(False)
