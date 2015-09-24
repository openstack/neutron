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

import mock
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

    @mock.patch.object(ip_lib.IPWrapper, 'get_devices')
    def test_get_device_by_ip_exception(self, mock_get_devices):
        mock_get_devices.side_effects = OSError
        ret = ip_lib.IPWrapper().get_device_by_ip(mock.sentinel.fake_ip)

        self.assertIsNone(ret)

    @mock.patch('netifaces.interfaces')
    def test_get_devices(self, mock_interfaces):
        mock_interfaces.return_value = [mock.sentinel.dev1,
                                        mock.sentinel.dev2]

        ret = ip_lib.IPWrapper().get_devices()
        self.assertEqual(mock.sentinel.dev1, ret[0].device_name)
        self.assertEqual(mock.sentinel.dev2, ret[1].device_name)

    @mock.patch('netifaces.interfaces')
    def test_get_devices_error(self, mock_interfaces):
        mock_interfaces.side_effects = OSError
        ret = ip_lib.IPWrapper().get_devices()

        self.assertEqual([], ret)


class TestIpDevice(base.BaseTestCase):

    @mock.patch('netifaces.ifaddresses')
    def test_device_has_ip(self, mock_netifaces):
        mock_address = {'addr': mock.sentinel.fake_addr}
        mock_netifaces.return_value = {netifaces.AF_INET: [mock_address]}

        ret = ip_lib.IPDevice("fake_dev").device_has_ip(
            mock.sentinel.fake_addr)

        self.assertTrue(ret)

    @mock.patch('netifaces.ifaddresses')
    def test_device_has_ip_false(self, mock_netifaces):
        mock_netifaces.return_value = {}

        ret = ip_lib.IPDevice("fake_dev").device_has_ip(
            mock.sentinel.fake_addr)

        self.assertFalse(ret)

    @mock.patch('netifaces.ifaddresses')
    def test_device_has_ip_error(self, mock_netifaces):
        mock_netifaces.side_effects = OSError

        ret = ip_lib.IPDevice("fake_dev").device_has_ip(
            mock.sentinel.fake_addr)

        self.assertFalse(ret)
