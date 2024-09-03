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

from unittest import mock

from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib
from neutron.tests import base


class TestPciLib(base.BaseTestCase):
    DEV_NAME = "p7p1"

    VF_INDEX = 1
    VFS_LIST = {0: {'mac': 'fa:16:3e:b4:81:ac', 'link_state': 2},
                1: {'mac': '00:00:00:00:00:11', 'link_state': 1},
                2: {'mac': 'fa:16:3e:68:4e:79', 'link_state': 0}}

    MAC_MAPPING = {
        0: "fa:16:3e:b4:81:ac",
        1: "00:00:00:00:00:11",
        2: "fa:16:3e:68:4e:79",
    }

    STATE_MAPPING = {  # VF index: state (string), according to VFS_LIST
        0: pci_lib.LinkState.disable.name,
        1: pci_lib.LinkState.enable.name,
        2: pci_lib.LinkState.auto.name,
    }

    def setUp(self):
        super(TestPciLib, self).setUp()
        self.pci_wrapper = pci_lib.PciDeviceIPWrapper(self.DEV_NAME)
        self.mock_ip_device = mock.Mock()
        self.mock_ip_device.link.get_vfs.return_value = self.VFS_LIST
        mock.patch.object(ip_lib, 'IPDevice',
                          return_value=self.mock_ip_device).start()

    def test_get_assigned_macs(self):
        for idx in range(len(self.VFS_LIST)):
            result = self.pci_wrapper.get_assigned_macs([idx])
            self.assertEqual({idx: self.MAC_MAPPING[idx]}, result)

    def test_get_assigned_macs_not_present(self):
        result = self.pci_wrapper.get_assigned_macs([1000])
        self.assertEqual({}, result)

    def test_get_vf_state(self):
        for idx in range(len(self.VFS_LIST)):
            result = self.pci_wrapper.get_vf_state(idx)
            self.assertEqual(self.STATE_MAPPING[idx], result)

    def test_get_vf_state_not_present(self):
        result = self.pci_wrapper.get_vf_state(1000)
        self.assertEqual(pci_lib.LinkState.disable.name, result)

    def test_set_vf_state(self):
        # state=True, auto=False --> link_state=enable
        self.pci_wrapper.set_vf_state(self.VF_INDEX, True)
        vf = {'vf': self.VF_INDEX, 'link_state': 1}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

        # state=False, auto=False --> link_state=disable
        self.mock_ip_device.link.set_vf_feature.reset_mock()
        self.pci_wrapper.set_vf_state(self.VF_INDEX, False)
        vf = {'vf': self.VF_INDEX, 'link_state': 2}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

        # state=True, auto=True --> link_state=auto
        self.mock_ip_device.link.set_vf_feature.reset_mock()
        self.pci_wrapper.set_vf_state(self.VF_INDEX, True, auto=True)
        vf = {'vf': self.VF_INDEX, 'link_state': 0}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

        # state=False, auto=True --> link_state=disable
        self.mock_ip_device.link.set_vf_feature.reset_mock()
        self.pci_wrapper.set_vf_state(self.VF_INDEX, False, auto=True)
        vf = {'vf': self.VF_INDEX, 'link_state': 2}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

    def test_set_vf_spoofcheck(self):
        self.pci_wrapper.set_vf_spoofcheck(self.VF_INDEX, True)
        vf = {'vf': self.VF_INDEX, 'spoofchk': 1}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

        self.mock_ip_device.link.set_vf_feature.reset_mock()
        self.pci_wrapper.set_vf_spoofcheck(self.VF_INDEX, False)
        vf = {'vf': self.VF_INDEX, 'spoofchk': 0}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

    def test_set_vf_rate(self):
        self.pci_wrapper.set_vf_rate(self.VF_INDEX, {'max_tx_rate': 20})
        vf = {'vf': self.VF_INDEX, 'rate': {'max_tx_rate': 20}}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

        self.mock_ip_device.link.set_vf_feature.reset_mock()
        self.pci_wrapper.set_vf_rate(self.VF_INDEX, {'min_tx_rate': 10})
        vf = {'vf': self.VF_INDEX, 'rate': {'min_tx_rate': 10}}
        self.mock_ip_device.link.set_vf_feature.assert_called_once_with(vf)

    @mock.patch.object(pci_lib, 'LOG')
    def test_set_vf_rate_exception(self, mock_log):
        self.mock_ip_device.link.set_vf_feature.side_effect = (
            ip_lib.InvalidArgument)
        self.pci_wrapper.set_vf_rate(self.VF_INDEX, {'min_tx_rate': 10})
        mock_log.error.assert_called_once_with(
            'Device %(device)s does not support ip-link vf "min_tx_rate" '
            'parameter. Rates: %(rates)s',
            {'device': self.DEV_NAME, 'rates': {'min_tx_rate': 10}}
        )
