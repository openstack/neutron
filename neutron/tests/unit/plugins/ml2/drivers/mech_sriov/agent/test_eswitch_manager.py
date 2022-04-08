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
from unittest import mock

from neutron.agent import rpc as agent_rpc
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import eswitch_manager as esm
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib
from neutron.tests import base


class TestCreateESwitchManager(base.BaseTestCase):
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]

    @staticmethod
    def cleanup():
        if hasattr(esm.ESwitchManager, '_instance'):
            del esm.ESwitchManager._instance

    def test_create_eswitch_mgr_fail(self):
        device_mappings = {'physnet1': ['p6p1']}
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        side_effect=exc.InvalidDeviceError(
                            dev_name="p6p1", reason="device" " not found")),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.pf_device_exists",
                           return_value=True):
            eswitch_mgr = esm.ESwitchManager()
            self.addCleanup(self.cleanup)
            self.assertRaises(exc.InvalidDeviceError,
                              eswitch_mgr.discover_devices,
                              device_mappings, None)

    def test_create_eswitch_mgr_ok(self):
        device_mappings = {'physnet1': ['p6p1']}
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        return_value=self.SCANNED_DEVICES),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.pf_device_exists",
                           return_value=True):
            eswitch_mgr = esm.ESwitchManager()
            self.addCleanup(self.cleanup)
            eswitch_mgr.discover_devices(device_mappings, None)


class TestESwitchManagerApi(base.BaseTestCase):
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]

    ASSIGNED_MAC = '00:00:00:00:00:66'
    PCI_SLOT = '0000:06:00.1'
    WRONG_MAC = '00:00:00:00:00:67'
    WRONG_PCI = "0000:06:00.6"
    MAX_RATE = esm.IP_LINK_CAPABILITY_RATE
    MIN_RATE = esm.IP_LINK_CAPABILITY_MIN_TX_RATE

    def setUp(self):
        super(TestESwitchManagerApi, self).setUp()
        device_mappings = {'physnet1': ['p6p1']}
        self.eswitch_mgr = esm.ESwitchManager()
        self.addCleanup(self.cleanup)
        self._set_eswitch_manager(self.eswitch_mgr, device_mappings)

    @staticmethod
    def cleanup():
        if hasattr(esm.ESwitchManager, '_instance'):
            del esm.ESwitchManager._instance

    def _set_eswitch_manager(self, eswitch_mgr, device_mappings):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        return_value=self.SCANNED_DEVICES), \
                 mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                            "eswitch_manager.PciOsWrapper.pf_device_exists",
                            return_value=True):
            eswitch_mgr.discover_devices(device_mappings, None)

    def test_discover_devices_with_device(self):
        device_mappings = {'physnet1': ['p6p1', 'p6p2']}
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.pf_device_exists",
                        return_value=True), \
            mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                       "eswitch_manager.ESwitchManager._create_emb_switch",
                       ) as emb_switch:
            self.eswitch_mgr.discover_devices(device_mappings, None)
            self.assertTrue(emb_switch.called)

    def test_discover_devices_without_device(self):
        device_mappings = {'physnet1': ['p6p1', 'p6p2']}
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.pf_device_exists",
                        return_value=False), \
            mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                       "eswitch_manager.ESwitchManager._create_emb_switch",
                       ) as emb_switch:
            self.eswitch_mgr.discover_devices(device_mappings, None)
            self.assertFalse(emb_switch.called)

    def test_get_assigned_devices_info(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_assigned_devices_info",
                        return_value=[(self.ASSIGNED_MAC, self.PCI_SLOT)]):
            result = self.eswitch_mgr.get_assigned_devices_info()
            self.assertIn(self.ASSIGNED_MAC, list(result)[0])
            self.assertIn(self.PCI_SLOT, list(result)[0])

    def test_get_assigned_devices_info_multiple_nics_for_physnet(self):
        device_mappings = {'physnet1': ['p6p1', 'p6p2']}
        devices_info = {
            'p6p1': [(self.ASSIGNED_MAC, self.PCI_SLOT)],
            'p6p2': [(self.WRONG_MAC, self.WRONG_PCI)],
        }

        def get_assigned_devices_info(self):
            return devices_info[self.dev_name]

        self._set_eswitch_manager(self.eswitch_mgr, device_mappings)

        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_assigned_devices_info",
                        side_effect=get_assigned_devices_info,
                        autospec=True):
            result = self.eswitch_mgr.get_assigned_devices_info()
            self.assertIn(devices_info['p6p1'][0], list(result))
            self.assertIn(devices_info['p6p2'][0], list(result))

    def test_get_device_status_enable(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.get_device_state",
                           return_value='enable'):
            result = self.eswitch_mgr.get_device_state(self.ASSIGNED_MAC,
                                                       self.PCI_SLOT)
            self.assertEqual('enable', result)

    def test_get_device_status_disable(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.get_device_state",
                           return_value='disable'):
            result = self.eswitch_mgr.get_device_state(self.ASSIGNED_MAC,
                                                       self.PCI_SLOT)
            self.assertEqual('disable', result)

    def test_get_device_status_auto(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.get_device_state",
                           return_value='auto'):
            result = self.eswitch_mgr.get_device_state(self.ASSIGNED_MAC,
                                                       self.PCI_SLOT)
            self.assertEqual('auto', result)

    def test_get_device_status_mismatch(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.get_device_state",
                           return_value='enable'):
            with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                            "eswitch_manager.LOG.warning") as log_mock:
                result = self.eswitch_mgr.get_device_state(self.WRONG_MAC,
                                                           self.PCI_SLOT)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})
                self.assertEqual('disable', result)

    def test_set_device_status(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.set_device_state"):
            self.eswitch_mgr.set_device_state(self.ASSIGNED_MAC,
                                              self.PCI_SLOT, True, False)

    def test_set_device_max_rate(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC) as get_pci_mock,\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.set_device_rate")\
                as set_device_rate_mock:
            self.eswitch_mgr.set_device_max_rate(self.ASSIGNED_MAC,
                                                 self.PCI_SLOT, 1000)
            get_pci_mock.assert_called_once_with(self.PCI_SLOT)
            set_device_rate_mock.assert_called_once_with(
                self.PCI_SLOT, {self.MAX_RATE: 1000})

    def test_set_device_min_tx_rate(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC) as get_pci_mock,\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.set_device_rate")\
                as set_device_rate_mock:
            self.eswitch_mgr.set_device_min_tx_rate(self.ASSIGNED_MAC,
                                                    self.PCI_SLOT, 1000)
            get_pci_mock.assert_called_once_with(self.PCI_SLOT)
            set_device_rate_mock.assert_called_once_with(
                self.PCI_SLOT, {self.MIN_RATE: 1000})

    def test_set_device_status_mismatch(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.EmbSwitch.set_device_state"):
            with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                            "eswitch_manager.LOG.warning") as log_mock:
                self.eswitch_mgr.set_device_state(self.WRONG_MAC,
                                                  self.PCI_SLOT, True, False)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})

    def _mock_device_exists(self, pci_slot, mac_address, expected_result):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
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
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.EmbSwitch.get_pci_device",
                        return_value=self.ASSIGNED_MAC):
            with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                            "eswitch_manager.LOG.warning") as log_mock:
                result = self.eswitch_mgr.device_exists(self.WRONG_MAC,
                                                        self.PCI_SLOT)
                log_mock.assert_called_with('device pci mismatch: '
                                            '%(device_mac)s - %(pci_slot)s',
                                            {'pci_slot': self.PCI_SLOT,
                                             'device_mac': self.WRONG_MAC})
                self.assertFalse(result)

    def test_clear_max_rate(self):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.agent.'
                        'eswitch_manager.ESwitchManager._clear_rate') \
                as clear_rate_mock:
            self.eswitch_mgr.clear_max_rate(self.PCI_SLOT)
            clear_rate_mock.assert_called_once_with(self.PCI_SLOT,
                                                    self.MAX_RATE)

    def test_clear_min_tx_rate(self):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.agent.'
                        'eswitch_manager.ESwitchManager._clear_rate') \
                as clear_rate_mock:
            self.eswitch_mgr.clear_min_tx_rate(self.PCI_SLOT)
            clear_rate_mock.assert_called_once_with(self.PCI_SLOT,
                                                    self.MIN_RATE)

    def test_process_emb_switch_without_device(self):
        device_mappings = {'physnet1': ['p6p1', 'p6p2']}
        phys_net = 'physnet1'
        dev_name = 'p6p1'
        self._set_eswitch_manager(self.eswitch_mgr, device_mappings)
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.pf_device_exists",
                        return_value=False), \
            mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                       "eswitch_manager.ESwitchManager._create_emb_switch",
                       ) as emb_switch:
            self.eswitch_mgr._process_emb_switch_map(phys_net,
                                                     dev_name, {})
            self.assertFalse(emb_switch.called)

    def test_process_emb_switch_with_device(self):
        device_mappings = {'physnet1': ['p6p1', 'p6p2']}
        phys_net = 'physnet1'
        dev_name = 'p6p3'
        self._set_eswitch_manager(self.eswitch_mgr, device_mappings)
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.pf_device_exists",
                        return_value=True), \
            mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                       "eswitch_manager.ESwitchManager._create_emb_switch",
                       ) as emb_switch:
            self.eswitch_mgr._process_emb_switch_map(phys_net,
                                                     dev_name, {})
            self.assertTrue(emb_switch.called)

    def _test_clear_rate(self, rate_type, pci_slot, passed, mac_address):
        with mock.patch('neutron.plugins.ml2.drivers.mech_sriov.agent.'
                        'eswitch_manager.EmbSwitch.set_device_rate') \
                as set_rate_mock, \
                mock.patch('neutron.plugins.ml2.drivers.mech_sriov.agent.'
                           'pci_lib.PciDeviceIPWrapper.get_assigned_macs',
                           return_value=mac_address), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.pf_device_exists",
                           return_value=True):
            self.eswitch_mgr._clear_rate(pci_slot, rate_type)
            if passed:
                set_rate_mock.assert_called_once_with(pci_slot,
                                                      {rate_type: 0})
            else:
                self.assertFalse(set_rate_mock.called)

    def test_clear_rate_max_rate_existing_pci_slot(self):
        self._test_clear_rate(self.MAX_RATE, self.PCI_SLOT, passed=True,
                              mac_address={})

    def test_clear_rate_max_rate_exist_and_assigned_pci(self):
        self._test_clear_rate(self.MAX_RATE, self.PCI_SLOT, passed=False,
                              mac_address={0: self.ASSIGNED_MAC})

    def test_clear_rate_max_rate_nonexisting_pci_slot(self):
        self._test_clear_rate(self.MAX_RATE, self.WRONG_PCI, passed=False,
                              mac_address={})

    def test_clear_rate_min_tx_rate_existing_pci_slot(self):
        self._test_clear_rate(self.MIN_RATE, self.PCI_SLOT, passed=True,
                              mac_address={})

    def test_clear_rate_min_tx_rate_exist_and_assigned_pci(self):
        self._test_clear_rate(self.MIN_RATE, self.PCI_SLOT, passed=False,
                              mac_address={0: self.ASSIGNED_MAC})

    def test_clear_rate_min_tx_rate_nonexisting_pci_slot(self):
        self._test_clear_rate(self.MIN_RATE, self.WRONG_PCI, passed=False,
                              mac_address={})

    def test_create_emb_switch(self):
        DEVICES = [('0000:04:00.1', 0),
                   ('0000:04:00.2', 1)]
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        side_effect=[[], DEVICES]), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.get_numvfs",
                           return_value=2):
            physnet = 'test_create_emb_switch'
            self.assertNotIn(physnet, self.eswitch_mgr.emb_switches_map)
            # first time device will not be added as no VFs returned
            self.eswitch_mgr._create_emb_switch(physnet, 'dev1', [])
            self.assertNotIn(physnet, self.eswitch_mgr.emb_switches_map)
            self.assertEqual({'dev1'}, self.eswitch_mgr.skipped_devices)

            # second time device should be added with 2 VFs
            self.eswitch_mgr._create_emb_switch(physnet, 'dev1', [])
            self.assertIn(physnet, self.eswitch_mgr.emb_switches_map)
            self.assertEqual(set(), self.eswitch_mgr.skipped_devices)
            self.assertIn('0000:04:00.1', self.eswitch_mgr.pci_slot_map)
            self.assertIn('0000:04:00.2', self.eswitch_mgr.pci_slot_map)

    def test_create_emb_switch_zero_vfs(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        return_value=[]), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.get_numvfs",
                           return_value=0):
            physnet = 'test_create_emb_switch'
            self.assertNotIn(physnet, self.eswitch_mgr.emb_switches_map)
            # first time device will not be added
            self.eswitch_mgr._create_emb_switch(physnet, 'dev1', [])
            self.assertNotIn(physnet, self.eswitch_mgr.emb_switches_map)
            self.assertEqual({'dev1'}, self.eswitch_mgr.skipped_devices)

            # second time device should be added with 0 VFs
            self.eswitch_mgr._create_emb_switch(physnet, 'dev1', [])
            self.assertIn(physnet, self.eswitch_mgr.emb_switches_map)
            self.assertEqual(set(), self.eswitch_mgr.skipped_devices)


class TestEmbSwitch(base.BaseTestCase):
    DEV_NAME = "eth2"
    PHYS_NET = "default"
    ASSIGNED_MAC = '00:00:00:00:00:66'
    PCI_SLOT = "0000:06:00.1"
    WRONG_PCI_SLOT = "0000:06:00.4"
    SCANNED_DEVICES = [('0000:06:00.1', 0),
                       ('0000:06:00.2', 1),
                       ('0000:06:00.3', 2)]
    VF_TO_MAC_MAPPING = {0: '00:00:00:00:00:11',
                         1: '00:00:00:00:00:22',
                         2: '00:00:00:00:00:33'}
    EXPECTED_MAC_TO_PCI = {
        '00:00:00:00:00:11': '0000:06:00.1',
        '00:00:00:00:00:22': '0000:06:00.2',
        '00:00:00:00:00:33': '0000:06:00.3'}

    def setUp(self):
        super(TestEmbSwitch, self).setUp()
        exclude_devices = set()
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.scan_vf_devices",
                        return_value=self.SCANNED_DEVICES):
            self.emb_switch = esm.EmbSwitch(self.DEV_NAME, exclude_devices)
        self.mock_get_vfs = mock.patch.object(esm.EmbSwitch,
                                              '_get_vfs').start()
        self.vf_rates = [{esm.IP_LINK_CAPABILITY_RATE: 500,
                          esm.IP_LINK_CAPABILITY_MIN_TX_RATE: 250}]
        self.mock_get_vfs.return_value = self.vf_rates

    def test_get_assigned_devices_info(self):
        with mock.patch.object(pci_lib.PciDeviceIPWrapper, 'get_assigned_macs',
                               return_value={0: self.ASSIGNED_MAC}), \
                mock.patch.object(esm.PciOsWrapper, 'pf_device_exists',
                                  return_value=True), \
                mock.patch.object(esm.PciOsWrapper, 'is_assigned_vf_direct',
                                  return_value=True):
            result = self.emb_switch.get_assigned_devices_info()
            device_info = agent_rpc.DeviceInfo(self.ASSIGNED_MAC,
                                               self.PCI_SLOT)
            self.assertEqual(1, len(result))
            self.assertEqual(device_info, result[0])

    def test_get_assigned_devices_info_multiple_slots(self):
        with mock.patch.object(pci_lib.PciDeviceIPWrapper, 'get_assigned_macs',
                               return_value=self.VF_TO_MAC_MAPPING), \
                mock.patch.object(esm.PciOsWrapper, 'pf_device_exists',
                                  return_value=True), \
                mock.patch.object(esm.PciOsWrapper, 'is_assigned_vf_direct',
                                  return_value=True):
            devices_info = self.emb_switch.get_assigned_devices_info()
            for device_info in devices_info:
                self.assertEqual(self.EXPECTED_MAC_TO_PCI[device_info.mac],
                                 device_info.pci_slot)

    def test_get_assigned_devices_empty(self):
        with mock.patch.object(esm.PciOsWrapper, 'is_assigned_vf_direct',
                               return_value=False), \
                mock.patch.object(esm.PciOsWrapper, 'is_assigned_vf_macvtap',
                                  return_value=False):
            result = self.emb_switch.get_assigned_devices_info()
            self.assertEqual([], result)

    def test_get_device_state_ok(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.get_vf_state",
                        return_value=False):
            result = self.emb_switch.get_device_state(self.PCI_SLOT)
            self.assertFalse(result)

    def test_get_device_state_fail(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.get_vf_state",
                        return_value=False):
            self.assertRaises(exc.InvalidPciSlotError,
                              self.emb_switch.get_device_state,
                              self.WRONG_PCI_SLOT)

    def test_set_device_state_ok(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_state"):
            with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                            "pci_lib.LOG.warning") as log_mock:
                self.emb_switch.set_device_state(self.PCI_SLOT, True, False)
                self.assertEqual(0, log_mock.call_count)

    def test_set_device_state_fail(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_state"):
            self.assertRaises(exc.InvalidPciSlotError,
                              self.emb_switch.set_device_state,
                              self.WRONG_PCI_SLOT, True, False)

    def test_set_device_spoofcheck_ok(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_spoofcheck") as \
                                set_vf_spoofcheck_mock:
            self.emb_switch.set_device_spoofcheck(self.PCI_SLOT, True)
            self.assertTrue(set_vf_spoofcheck_mock.called)

    def test_set_device_spoofcheck_fail(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.set_vf_spoofcheck"):
            self.assertRaises(exc.InvalidPciSlotError,
                              self.emb_switch.set_device_spoofcheck,
                              self.WRONG_PCI_SLOT, True)

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_rate_ok(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 2000})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 2
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

        # No 'min_tx_rate' support
        vf_rates = [{esm.IP_LINK_CAPABILITY_RATE: 500,
                     esm.IP_LINK_CAPABILITY_MIN_TX_RATE: None}]
        self.mock_get_vfs.return_value = vf_rates
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 2000})
        vf_rates[0] = {esm.IP_LINK_CAPABILITY_RATE: 2}
        mock_set_vf_rate.assert_called_with(0, vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_ok2(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 99})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 1
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_rounded_ok(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 2001})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 2
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_rounded_ok2(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 2499})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 2
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_rounded_ok3(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 2500})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 3
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_disable(self, mock_set_vf_rate):
        self.emb_switch.set_device_rate(
            self.PCI_SLOT, {esm.IP_LINK_CAPABILITY_RATE: 0})
        self.vf_rates[0][esm.IP_LINK_CAPABILITY_RATE] = 0
        mock_set_vf_rate.assert_called_with(0, self.vf_rates[0])

    @mock.patch.object(pci_lib.PciDeviceIPWrapper, 'set_vf_rate')
    def test_set_device_max_rate_fail(self, *args):
        self.assertRaises(
            exc.InvalidPciSlotError,
            self.emb_switch.set_device_rate,
            self.WRONG_PCI_SLOT,
            {esm.IP_LINK_CAPABILITY_RATE: 1000})

    def test_get_pci_device(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.get_assigned_macs",
                        return_value={0: self.ASSIGNED_MAC}),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper."
                           "is_assigned_vf_direct", return_value=True), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                        "eswitch_manager.PciOsWrapper.pf_device_exists",
                        return_value=True):
            result = self.emb_switch.get_pci_device(self.PCI_SLOT)
            self.assertEqual(self.ASSIGNED_MAC, result)

    def test_get_pci_device_fail(self):
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper.get_assigned_macs",
                        return_value=[self.ASSIGNED_MAC]),\
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper.pf_device_exists",
                           return_value=True), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper."
                           "is_assigned_vf_direct", return_value=True):
            result = self.emb_switch.get_pci_device(self.WRONG_PCI_SLOT)
            self.assertIsNone(result)

    def test_get_pci_list(self):
        result = self.emb_switch.get_pci_slot_list()
        self.assertEqual([tup[0] for tup in self.SCANNED_DEVICES],
                         sorted(result))

    def _test__get_macvtap_mac(self, upper_devs):
        ip_wrapper_mock_inst = mock.MagicMock()
        with mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                        "PciDeviceIPWrapper",
                        return_value=ip_wrapper_mock_inst), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.PciOsWrapper."
                           "get_vf_macvtap_upper_devs",
                           return_value=upper_devs), \
                mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                           "eswitch_manager.LOG.warning") as log_mock:
            self.emb_switch._get_macvtap_mac(0)
            ip_wrapper_mock_inst.device.assert_called_with(upper_devs[0])
            if len(upper_devs) > 1:
                self.assertTrue(log_mock.called)
            else:
                self.assertFalse(log_mock.called)

    def test__get_macvtap_mac_single_upper_dev(self):
        upper_devs = ["macvtap0"]
        self._test__get_macvtap_mac(upper_devs)

    def test__get_macvtap_mac_multiple_upper_devs(self):
        upper_devs = ["macvtap0", "macvtap1"]
        self._test__get_macvtap_mac(upper_devs)


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

        with mock.patch("os.path.isdir", return_value=True),\
                mock.patch("os.listdir", return_value=self.DIR_CONTENTS),\
                mock.patch("os.path.islink", return_value=True),\
                mock.patch("os.readlink", side_effect=_get_link):
            result = esm.PciOsWrapper.scan_vf_devices(self.DEV_NAME)
            self.assertEqual(self.PCI_SLOTS, result)

    def test_scan_vf_devices_no_dir(self):
        with mock.patch("os.path.isdir", return_value=False):
            self.assertRaises(exc.InvalidDeviceError,
                              esm.PciOsWrapper.scan_vf_devices,
                              self.DEV_NAME)

    def test_scan_vf_devices_no_content(self):
        with mock.patch("os.path.isdir", return_value=True),\
                mock.patch("os.listdir", return_value=[]):
            self.assertEqual([],
                             esm.PciOsWrapper.scan_vf_devices(self.DEV_NAME))

    def test_scan_vf_devices_no_match(self):
        with mock.patch("os.path.isdir", return_value=True),\
                mock.patch("os.listdir",
                           return_value=self.DIR_CONTENTS_NO_MATCH):
            self.assertEqual([],
                             esm.PciOsWrapper.scan_vf_devices(self.DEV_NAME))

    def _mock_assign_vf_direct(self, dir_exists):
        with mock.patch("os.path.isdir",
                        return_value=dir_exists):
            result = esm.PciOsWrapper.is_assigned_vf_direct(self.DEV_NAME,
                                                            self.VF_INDEX)
            self.assertEqual(not dir_exists, result)

    def test_is_assigned_vf_direct_true(self):
        self._mock_assign_vf_direct(True)

    def test_is_assigned_vf_direct_false(self):
        self._mock_assign_vf_direct(False)

    def _mock_assign_vf_macvtap(self, macvtap_exists):
        def _glob(file_path):
            return ["upper_macvtap0"] if macvtap_exists else []

        with mock.patch("glob.glob", side_effect=_glob):
            result = esm.PciOsWrapper.is_assigned_vf_macvtap(self.DEV_NAME,
                                                             self.VF_INDEX)
            self.assertEqual(macvtap_exists, result)

    def test_is_assigned_vf_macvtap_true(self):
        self._mock_assign_vf_macvtap(True)

    def test_is_assigned_vf_macvtap_false(self):
        self._mock_assign_vf_macvtap(False)

    def _test_get_vf_macvtap_upper_devs(self, upper_devs):
        with mock.patch("glob.glob", return_value=upper_devs):
            result = esm.PciOsWrapper.get_vf_macvtap_upper_devs(self.DEV_NAME,
                                                                self.VF_INDEX)
            self.assertEqual([dev.split("_")[1] for dev in upper_devs], result)

    def test_get_vf_macvtap_upper_devs(self):
        upper_devs = ["upper_macvtap0", "upper_macvtap1"]
        self._test_get_vf_macvtap_upper_devs(upper_devs)

    def test_get_vf_macvtap_upper_devs_no_devs(self):
        upper_devs = []
        self._test_get_vf_macvtap_upper_devs(upper_devs)

    def test_pf_device_exists_with_no_dir(self):
        with mock.patch("os.path.isdir", return_value=False):
            self.assertFalse(esm.PciOsWrapper.pf_device_exists('p6p1'))

    def test_pf_device_exists_with_dir(self):
        with mock.patch("os.path.isdir", return_value=True):
            self.assertTrue(esm.PciOsWrapper.pf_device_exists('p6p1'))

    def test_get_numvfs(self):
        with mock.patch("builtins.open",
                        mock.mock_open(read_data="63")) as mock_open:
            self.assertEqual(63, esm.PciOsWrapper.get_numvfs('dev1'))
            mock_open.assert_called_once_with(
                esm.PciOsWrapper.NUMVFS_PATH % 'dev1')

    def test_get_numvfs_no_file(self):
        with mock.patch("builtins.open", side_effect=IOError()) as mock_open:
            self.assertEqual(-1, esm.PciOsWrapper.get_numvfs('dev1'))
            mock_open.assert_called_once_with(
                esm.PciOsWrapper.NUMVFS_PATH % 'dev1')
