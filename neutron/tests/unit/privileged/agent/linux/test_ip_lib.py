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

import errno
from unittest import mock

from pyroute2 import iproute
from pyroute2 import netlink
from pyroute2.netlink import exceptions as netlink_exceptions
from pyroute2.nslink import nslink

from neutron.privileged.agent.linux import ip_lib as priv_lib
from neutron.tests import base


class IpLibTestCase(base.BaseTestCase):

    def _test_run_iproute_link(self, namespace=None):
        ip_obj = "NetNS" if namespace else "IPRoute"
        _mod = nslink if namespace else iproute
        with mock.patch.object(_mod, ip_obj) as ip_mock_cls:
            ip_mock = ip_mock_cls()
            ip_mock.__enter__().link_lookup.return_value = [2]
            priv_lib._run_iproute_link("test_cmd", "eth0", namespace,
                                       test_param="test_value")
            ip_mock.assert_has_calls([
                mock.call.__enter__().link_lookup(ifname="eth0"),
                mock.call.__exit__(None, None, None),
                mock.call.__enter__().link("test_cmd", index=2,
                                           test_param="test_value")])

    def test_run_iproute_link_no_namespace(self):
        self._test_run_iproute_link()

    def test_run_iproute_link_in_namespace(self):
        self._test_run_iproute_link(namespace="testns")

    def test_run_iproute_link_interface_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ret_values = [
                [],    # No interface found.
                None,  # Unexpected output but also handled.
            ]
            for ret_val in ret_values:
                ip_mock.__enter__().link_lookup.return_value = ret_val
                self.assertRaises(
                    priv_lib.NetworkInterfaceNotFound,
                    priv_lib._run_iproute_link,
                    "test_cmd", "eth0", None, test_param="test_value")

    @mock.patch.object(priv_lib, 'get_iproute')
    def test_get_link_id(self, mock_iproute):
        mock_ip = mock.Mock()
        mock_ip.link_lookup.return_value = ['interface_id']
        mock_iproute.return_value.__enter__.return_value = mock_ip
        self.assertEqual('interface_id',
                         priv_lib.get_link_id('device', 'namespace'))

    def test_run_iproute_link_interface_removed_during_call(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().link.side_effect = (
                netlink_exceptions.NetlinkError(code=errno.ENODEV))
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_op_not_supported(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().link.side_effect = (
                netlink_exceptions.NetlinkError(code=errno.EOPNOTSUPP))
            self.assertRaises(
                priv_lib.InterfaceOperationNotSupported,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_namespace_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_error(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.EINVAL, "Test invalid argument exception")
            try:
                priv_lib._run_iproute_link(
                    "test_cmd", "eth0", None, test_param="test_value")
                self.fail("OSError exception not raised")
            except OSError as e:
                self.assertEqual(errno.EINVAL, e.errno)

    def _test_run_iproute_neigh(self, namespace=None):
        ip_obj = "NetNS" if namespace else "IPRoute"
        _mod = nslink if namespace else iproute
        with mock.patch.object(_mod, ip_obj) as ip_mock_cls:
            ip_mock = ip_mock_cls()
            ip_mock.__enter__().link_lookup.return_value = [2]
            priv_lib._run_iproute_neigh("test_cmd", "eth0", namespace,
                                        test_param="test_value")
            ip_mock.assert_has_calls([
                mock.call.__enter__().link_lookup(ifname="eth0"),
                mock.call.__exit__(None, None, None),
                mock.call.__enter__().neigh("test_cmd", ifindex=2,
                                            test_param="test_value")])

    def test_run_iproute_neigh_no_namespace(self):
        self._test_run_iproute_neigh()

    def test_run_iproute_neigh_in_namespace(self):
        self._test_run_iproute_neigh(namespace="testns")

    def test_run_iproute_neigh_interface_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = []
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_interface_removed_during_call(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().neigh.side_effect = (
                netlink_exceptions.NetlinkError(code=errno.ENODEV))
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_namespace_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_error(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.EINVAL, "Test invalid argument exception")
            try:
                priv_lib._run_iproute_neigh(
                    "test_cmd", "eth0", None, test_param="test_value")
                self.fail("OSError exception not raised")
            except OSError as e:
                self.assertEqual(errno.EINVAL, e.errno)

    def _test_run_iproute_addr(self, namespace=None):
        ip_obj = "NetNS" if namespace else "IPRoute"
        _mod = nslink if namespace else iproute
        with mock.patch.object(_mod, ip_obj) as ip_mock_cls:
            ip_mock = ip_mock_cls()
            ip_mock.__enter__().link_lookup.return_value = [2]
            priv_lib._run_iproute_addr("test_cmd", "eth0", namespace,
                                       test_param="test_value")
            ip_mock.assert_has_calls([
                mock.call.__enter__().link_lookup(ifname="eth0"),
                mock.call.__exit__(None, None, None),
                mock.call.__enter__().addr("test_cmd", index=2,
                                           test_param="test_value")])

    def test_run_iproute_addr_no_namespace(self):
        self._test_run_iproute_addr()

    def test_run_iproute_addr_in_namespace(self):
        self._test_run_iproute_addr(namespace="testns")

    def test_run_iproute_addr_interface_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = []
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_interface_removed_during_call(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().addr.side_effect = (
                netlink_exceptions.NetlinkError(code=errno.ENODEV))
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_namespace_not_exists(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_error(self):
        with mock.patch.object(iproute, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.EINVAL, "Test invalid argument exception")
            try:
                priv_lib._run_iproute_addr(
                    "test_cmd", "eth0", None, test_param="test_value")
                self.fail("OSError exception not raised")
            except OSError as e:
                self.assertEqual(errno.EINVAL, e.errno)

    def _clean(self, client_mode):
        priv_lib.privileged.link_cmd.client_mode = client_mode

    def test_get_link_vfs(self):
        # NOTE(ralonsoh): there should be a functional test checking this
        # method, but this is not possible due to the lack of SR-IOV capable
        # NICs in the CI servers.
        vf_info = []
        for idx in range(3):
            vf_info.append(netlink.nlmsg_base())
            mac_info = {'mac': 'mac_%s' % idx, 'vf': idx}
            link_state = {'link_state': idx}  # see SR-IOV pci_lib.LinkState
            rates = {'max_tx_rate': idx * 1000, 'min_tx_rate': idx * 500}
            vf_info[idx].setvalue(
                {'attrs': [('IFLA_VF_MAC', mac_info),
                           ('IFLA_VF_LINK_STATE', link_state),
                           ('IFLA_VF_RATE', rates)]})
        vfinfo_list = netlink.nlmsg_base()
        vfinfo_list.setvalue({'attrs': [('IFLA_VF_INFO', vf_info[0]),
                                        ('IFLA_VF_INFO', vf_info[1]),
                                        ('IFLA_VF_INFO', vf_info[2])]})
        value = netlink.nlmsg_base()
        value.setvalue({'attrs': [('IFLA_NUM_VF', 3),
                                  ('IFLA_VFINFO_LIST', vfinfo_list)]})
        client_mode = priv_lib.privileged.default.client_mode
        priv_lib.privileged.link_cmd.client_mode = False
        self.addCleanup(self._clean, client_mode)
        with mock.patch.object(priv_lib, '_run_iproute_link') as mock_iplink:
            mock_iplink.side_effect = [
                netlink_exceptions.NetlinkDumpInterrupted(), value]
            result = priv_lib.get_link_vfs('device', 'namespace')
            exp = {0: {'mac': 'mac_0', 'link_state': 0,
                       'max_tx_rate': 0, 'min_tx_rate': 0},
                   1: {'mac': 'mac_1', 'link_state': 1,
                       'max_tx_rate': 1000, 'min_tx_rate': 500},
                   2: {'mac': 'mac_2', 'link_state': 2,
                       'max_tx_rate': 2000, 'min_tx_rate': 1000}}
            self.assertEqual(exp, result)
            # Check that _run_iproute_link was called twice
            mock_iplink.assert_has_calls(
                [mock.call('get', 'device', namespace='namespace', ext_mask=1),
                 mock.call('get', 'device', namespace='namespace', ext_mask=1)]
            )
