# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
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

from neutron.agent.linux import bridge_lib
from neutron.tests import base


class BridgeLibTest(base.BaseTestCase):
    """A test suite to exercise the bridge libraries """
    _NAMESPACE = 'test-namespace'
    _BR_NAME = 'test-br'
    _IF_NAME = 'test-if'

    def setUp(self):
        super(BridgeLibTest, self).setUp()
        mock.patch(
            'neutron.common.ipv6_utils.is_enabled_and_bind_by_default',
            return_value=True).start()
        ip_wrapper = mock.patch('neutron.agent.linux.ip_lib.IPWrapper').start()
        self.execute = ip_wrapper.return_value.netns.execute

    def _verify_bridge_mock(self, cmd):
        self.execute.assert_called_once_with(cmd, run_as_root=True)
        self.execute.reset_mock()

    def _verify_bridge_sysctl_mock(self, cmd):
        self.execute.assert_called_once_with(cmd, run_as_root=True,
                                             log_fail_as_error=True)
        self.execute.reset_mock()

    def test_is_bridged_interface(self):
        exists = lambda path: path == "/sys/class/net/tapOK/brport"
        with mock.patch('os.path.exists', side_effect=exists):
            self.assertTrue(bridge_lib.is_bridged_interface("tapOK"))
            self.assertFalse(bridge_lib.is_bridged_interface("tapKO"))

    def test_get_interface_bridge(self):
        with mock.patch('os.readlink', side_effect=["prefix/br0", OSError()]):
            br = bridge_lib.BridgeDevice.get_interface_bridge('tap0')
            self.assertIsInstance(br, bridge_lib.BridgeDevice)
            self.assertEqual("br0", br.name)

            br = bridge_lib.BridgeDevice.get_interface_bridge('tap0')
            self.assertIsNone(br)

    def _test_br(self, namespace=None):
        br = bridge_lib.BridgeDevice.addbr(self._BR_NAME, namespace)
        self.assertEqual(namespace, br.namespace)
        self._verify_bridge_mock(['brctl', 'addbr', self._BR_NAME])

        br.setfd(0)
        self._verify_bridge_mock(['brctl', 'setfd', self._BR_NAME, '0'])

        br.disable_stp()
        self._verify_bridge_mock(['brctl', 'stp', self._BR_NAME, 'off'])

        br.disable_ipv6()
        cmd = 'net.ipv6.conf.%s.disable_ipv6=1' % self._BR_NAME
        self._verify_bridge_sysctl_mock(['sysctl', '-w', cmd])

        br.addif(self._IF_NAME)
        self._verify_bridge_mock(
            ['brctl', 'addif', self._BR_NAME, self._IF_NAME])

        br.delif(self._IF_NAME)
        self._verify_bridge_mock(
            ['brctl', 'delif', self._BR_NAME, self._IF_NAME])

        br.delbr()
        self._verify_bridge_mock(['brctl', 'delbr', self._BR_NAME])

    def test_addbr_with_namespace(self):
        self._test_br(self._NAMESPACE)

    def test_addbr_without_namespace(self):
        self._test_br()

    def test_addbr_exists(self):
        self.execute.side_effect = RuntimeError()
        with mock.patch.object(bridge_lib.BridgeDevice, 'exists',
                               return_value=True):
            bridge_lib.BridgeDevice.addbr(self._BR_NAME)
            bridge_lib.BridgeDevice.addbr(self._BR_NAME)

    def test_owns_interface(self):
        br = bridge_lib.BridgeDevice('br-int')
        exists = lambda path: path == "/sys/class/net/br-int/brif/abc"
        with mock.patch('os.path.exists', side_effect=exists):
            self.assertTrue(br.owns_interface("abc"))
            self.assertFalse(br.owns_interface("def"))

    def test_get_interfaces(self):
        br = bridge_lib.BridgeDevice('br-int')
        interfaces = ["tap1", "tap2"]
        with mock.patch('os.listdir', side_effect=[interfaces, OSError()]):
            self.assertEqual(interfaces, br.get_interfaces())
            self.assertEqual([], br.get_interfaces())
