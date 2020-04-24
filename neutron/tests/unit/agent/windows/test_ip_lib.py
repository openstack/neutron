# Copyright 2016 Cloudbase Solutions.
# All Rights Reserved.
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

from unittest import mock

import netifaces

from neutron.agent.windows import ip_lib
from neutron.tests import base


class TestIpWrapper(base.BaseTestCase):

    def test_get_device_by_ip_no_ip(self):
        ret = ip_lib.IPWrapper().get_device_by_ip(None)
        self.assertIsNone(ret)

    @mock.patch.object(ip_lib.IPWrapper, 'get_devices')
    def test_get_device_by_ip(self, mock_get_devices):
        mock_dev1 = mock.MagicMock()
        mock_dev2 = mock.MagicMock()
        mock_dev1.device_has_ip.return_value = False
        mock_dev2.device_has_ip.return_value = True
        mock_get_devices.return_value = [mock_dev1, mock_dev2]
        ret = ip_lib.IPWrapper().get_device_by_ip('fake_ip')

        self.assertEqual(mock_dev2, ret)

    @mock.patch('netifaces.interfaces')
    def test_get_devices(self, mock_interfaces):
        mock_interfaces.return_value = [mock.sentinel.dev1,
                                        mock.sentinel.dev2]

        ret = ip_lib.IPWrapper().get_devices()
        self.assertEqual(mock.sentinel.dev1, ret[0].name)
        self.assertEqual(mock.sentinel.dev2, ret[1].name)

    @mock.patch('netifaces.interfaces')
    def test_get_devices_error(self, mock_interfaces):
        mock_interfaces.side_effect = OSError
        ret = ip_lib.IPWrapper().get_devices()

        self.assertEqual([], ret)


class TestIpDevice(base.BaseTestCase):

    @mock.patch('netifaces.ifaddresses')
    def test_read_ifaddresses(self, mock_netifaces):
        mock_address = {'addr': mock.sentinel.fake_addr}
        mock_netifaces.return_value = {netifaces.AF_INET: [mock_address]}
        ret = ip_lib.IPDevice("fake_dev").read_ifaddresses()
        self.assertTrue(ret)

    @mock.patch('netifaces.ifaddresses')
    def test_read_ifaddresses_no_ip(self, mock_netifaces):
        mock_netifaces.return_value = {}
        ret = ip_lib.IPDevice("fake_dev").read_ifaddresses()
        self.assertFalse(ret)

    @mock.patch('netifaces.ifaddresses')
    def test_read_ifaddresses_ip_error(self, mock_netifaces):
        mock_netifaces.side_effect = OSError
        ret = ip_lib.IPDevice("fake_dev").read_ifaddresses()
        self.assertFalse(ret)

    @mock.patch('netifaces.ifaddresses')
    def test_read_faddresses_not_found(self, mock_netifaces):
        mock_netifaces.side_effect = ValueError
        ret = ip_lib.IPDevice("fake_dev").read_ifaddresses()
        self.assertFalse(ret)

    def test_device_has_ip(self):
        mock_address = {'addr': mock.sentinel.fake_addr}
        ip_device = ip_lib.IPDevice("fake_dev")
        with mock.patch.object(ip_device, "read_ifaddresses", return_value=(
                {netifaces.AF_INET: [mock_address]})):
            ret = ip_device.device_has_ip(mock.sentinel.fake_addr)
            self.assertTrue(ret)

    def test_device_has_ip_false(self):
        ip_device = ip_lib.IPDevice("fake_dev")
        with mock.patch.object(ip_device, "read_ifaddresses", return_value={}):
            ret = ip_device.device_has_ip(mock.sentinel.fake_addr)
            self.assertFalse(ret)

    def test_device_has_ip_error(self):
        ip_device = ip_lib.IPDevice("fake_dev")
        with mock.patch.object(ip_device, "read_ifaddresses",
                               return_value=None):
            ret = ip_device.device_has_ip(mock.sentinel.fake_addr)
            self.assertFalse(ret)


class TestIPLink(base.BaseTestCase):

    def setUp(self):
        super(TestIPLink, self).setUp()
        parent = ip_lib.IPDevice("fake_dev")
        self.ip_link = ip_lib.IPLink(parent)
        self.ip_link._parent.read_ifaddresses = mock.Mock()

    def test_address(self):
        mock_address = {'addr': mock.sentinel.fake_addr}
        self.ip_link._parent.read_ifaddresses.return_value = {
            netifaces.AF_LINK: [mock_address]}
        self.assertEqual([mock_address['addr']], self.ip_link.address)

    def test_address_no_address(self):
        self.ip_link._parent.read_ifaddresses.return_value = {
            netifaces.AF_LINK: []}
        self.assertEqual([], self.ip_link.address)

    def test_address_error(self):
        self.ip_link._parent.read_ifaddresses.return_value = None
        self.assertFalse(self.ip_link.address)
