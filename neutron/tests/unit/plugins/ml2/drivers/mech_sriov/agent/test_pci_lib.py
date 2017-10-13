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


import mock

from neutron.agent.linux import ip_link_support
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib
from neutron.tests import base


class TestPciLib(base.BaseTestCase):
    DEV_NAME = "p7p1"
    VF_INDEX = 1
    VF_INDEX_DISABLE = 0
    PF_LINK_SHOW = ('122: p7p1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop'
                    ' state DOWN mode DEFAULT group default qlen 1000')
    PF_MAC = '    link/ether f4:52:14:2a:3e:c0 brd ff:ff:ff:ff:ff:ff'
    VF_0_LINK_SHOW = ('    vf 0 MAC fa:16:3e:b4:81:ac, vlan 4095, spoof'
                      ' checking off, link-state disable')
    VF_1_LINK_SHOW = ('    vf 1 MAC 00:00:00:00:00:11, vlan 4095, spoof'
                      ' checking off, link-state enable')
    VF_2_LINK_SHOW = ('    vf 2 MAC fa:16:3e:68:4e:79, vlan 4095, spoof'
                      ' checking off, link-state enable')
    VF_LINK_SHOW = '\n'.join((PF_LINK_SHOW, PF_MAC, VF_0_LINK_SHOW,
                              VF_1_LINK_SHOW, VF_2_LINK_SHOW))
    MACVTAP_LINK_SHOW = ('63: macvtap1@enp129s0f1: <BROADCAST,MULTICAST> mtu '
                         '1500 qdisc  noop state DOWN mode DEFAULT group '
                         'default qlen 500 link/ether 4a:9b:6d:de:65:b5 brd '
                         'ff:ff:ff:ff:ff:ff')
    MACVTAP_LINK_SHOW2 = ('64: macvtap2@p1p2_1: <BROADCAST,MULTICAST> mtu '
                          '1500 qdisc  noop state DOWN mode DEFAULT group '
                          'default qlen 500 link/ether 4a:9b:6d:de:65:b5 brd '
                          'ff:ff:ff:ff:ff:ff')

    IP_LINK_SHOW_WITH_MACVTAP = '\n'.join((VF_LINK_SHOW, MACVTAP_LINK_SHOW))
    IP_LINK_SHOW_WITH_MACVTAP2 = '\n'.join((VF_LINK_SHOW, MACVTAP_LINK_SHOW2))

    MAC_MAPPING = {
        0: "fa:16:3e:b4:81:ac",
        1: "00:00:00:00:00:11",
        2: "fa:16:3e:68:4e:79",
    }

    def setUp(self):
        super(TestPciLib, self).setUp()
        self.pci_wrapper = pci_lib.PciDeviceIPWrapper(self.DEV_NAME)

    def test_get_assigned_macs(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.return_value = self.VF_LINK_SHOW
            result = self.pci_wrapper.get_assigned_macs([self.VF_INDEX])
            self.assertEqual(
                {self.VF_INDEX: self.MAC_MAPPING[self.VF_INDEX]}, result)

    def test_get_assigned_macs_fail(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception()
            self.assertRaises(exc.IpCommandDeviceError,
                              self.pci_wrapper.get_assigned_macs,
                              [self.VF_INDEX])

    def test_get_vf_state_enable(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.return_value = self.VF_LINK_SHOW
            result = self.pci_wrapper.get_vf_state(self.VF_INDEX)
            self.assertTrue(result)

    def test_get_vf_state_disable(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.return_value = self.VF_LINK_SHOW
            result = self.pci_wrapper.get_vf_state(self.VF_INDEX_DISABLE)
            self.assertFalse(result)

    def test_get_vf_state_fail(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception()
            self.assertRaises(exc.IpCommandDeviceError,
                              self.pci_wrapper.get_vf_state,
                              self.VF_INDEX)

    def test_set_vf_state(self):
        with mock.patch.object(self.pci_wrapper, "_as_root"):
            result = self.pci_wrapper.set_vf_state(self.VF_INDEX,
                                                   True)
            self.assertIsNone(result)

    def test_set_vf_state_fail(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception()
            self.assertRaises(exc.IpCommandDeviceError,
                              self.pci_wrapper.set_vf_state,
                              self.VF_INDEX,
                              True)

    def test_set_vf_spoofcheck(self):
        with mock.patch.object(self.pci_wrapper, "_as_root"):
            result = self.pci_wrapper.set_vf_spoofcheck(self.VF_INDEX,
                                                        True)
            self.assertIsNone(result)

    def test_set_vf_spoofcheck_fail(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception()
            self.assertRaises(exc.IpCommandDeviceError,
                              self.pci_wrapper.set_vf_spoofcheck,
                              self.VF_INDEX,
                              True)

    def _set_vf_rate(self, rate, passed=True):
        if passed:
            with mock.patch.object(self.pci_wrapper, "_as_root") \
                    as mock_as_root:
                result = self.pci_wrapper.set_vf_rate(
                    self.VF_INDEX,
                    ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_RATE,
                    1000)
                self.assertIsNone(result)
                mock_as_root.assert_called_once_with(
                    [], "link", ("set", self.DEV_NAME, "vf",
                                 str(self.VF_INDEX), "rate", '1000'))
        else:
            with mock.patch.object(self.pci_wrapper, "_as_root",
                                   side_effect=Exception()):
                self.assertRaises(exc.IpCommandDeviceError,
                                  self.pci_wrapper.set_vf_rate,
                                  self.VF_INDEX,
                                  rate,
                                  1000)

    def test_set_vf_rate_max_rate(self):
        self._set_vf_rate(
            ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_RATE)

    def test_set_vf_rate_max_rate_fail(self):
        self._set_vf_rate('rate', passed=False)

    def test_set_vf_rate_min_tx_rate(self):
        self._set_vf_rate(
            ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_MIN_TX_RATE)

    def test_set_vf_rate_min_tx_rate_fail(self):
        self._set_vf_rate(
            ip_link_support.IpLinkConstants.IP_LINK_CAPABILITY_MIN_TX_RATE,
            passed=False)

    def test_set_vf_state_not_supported(self):
        with mock.patch.object(self.pci_wrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception(
                pci_lib.PciDeviceIPWrapper.IP_LINK_OP_NOT_SUPPORTED)
            self.assertRaises(exc.IpCommandOperationNotSupportedError,
                              self.pci_wrapper.set_vf_state,
                              self.VF_INDEX,
                              state=True)

    def test_is_macvtap_assigned(self):
        self.assertTrue(pci_lib.PciDeviceIPWrapper.is_macvtap_assigned(
            'enp129s0f1', self.IP_LINK_SHOW_WITH_MACVTAP))

    def test_is_macvtap_assigned_interface_with_underscore(self):
        self.assertTrue(pci_lib.PciDeviceIPWrapper.is_macvtap_assigned(
            'p1p2_1', self.IP_LINK_SHOW_WITH_MACVTAP2))

    def test_is_macvtap_assigned_not_assigned(self):
        self.assertFalse(pci_lib.PciDeviceIPWrapper.is_macvtap_assigned(
            'enp129s0f2', self.IP_LINK_SHOW_WITH_MACVTAP))

    def test_link_show_command_failed(self):
        with mock.patch.object(pci_lib.PciDeviceIPWrapper,
                               "_as_root") as mock_as_root:
            mock_as_root.side_effect = Exception()
            self.assertRaises(exc.IpCommandError,
                              self.pci_wrapper.link_show)
