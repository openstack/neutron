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

import mock
import pyroute2
from pyroute2 import netlink
from pyroute2.netlink.rtnl import ifinfmsg

from neutron.privileged.agent.linux import ip_lib as priv_lib
from neutron.tests import base


class IpLibTestCase(base.BaseTestCase):

    def _test_run_iproute_link(self, namespace=None):
        ip_obj = "NetNS" if namespace else "IPRoute"
        with mock.patch.object(pyroute2, ip_obj) as ip_mock_cls:
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
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = []
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_interface_removed_during_call(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().link.side_effect = pyroute2.NetlinkError(
                code=errno.ENODEV)
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_op_not_supported(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().link.side_effect = pyroute2.NetlinkError(
                code=errno.EOPNOTSUPP)
            self.assertRaises(
                priv_lib.InterfaceOperationNotSupported,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_namespace_not_exists(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_link,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_link_error(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
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
        with mock.patch.object(pyroute2, ip_obj) as ip_mock_cls:
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
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = []
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_interface_removed_during_call(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().neigh.side_effect = pyroute2.NetlinkError(
                code=errno.ENODEV)
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_namespace_not_exists(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_neigh,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_neigh_error(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
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
        with mock.patch.object(pyroute2, ip_obj) as ip_mock_cls:
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
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = []
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_interface_removed_during_call(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            ip_mock = iproute_mock()
            ip_mock.__enter__().link_lookup.return_value = [2]
            ip_mock.__enter__().addr.side_effect = pyroute2.NetlinkError(
                code=errno.ENODEV)
            self.assertRaises(
                priv_lib.NetworkInterfaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_namespace_not_exists(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.ENOENT, "Test no netns exception")
            self.assertRaises(
                priv_lib.NetworkNamespaceNotFound,
                priv_lib._run_iproute_addr,
                "test_cmd", "eth0", None, test_param="test_value")

    def test_run_iproute_addr_error(self):
        with mock.patch.object(pyroute2, "IPRoute") as iproute_mock:
            iproute_mock.side_effect = OSError(
                errno.EINVAL, "Test invalid argument exception")
            try:
                priv_lib._run_iproute_addr(
                    "test_cmd", "eth0", None, test_param="test_value")
                self.fail("OSError exception not raised")
            except OSError as e:
                self.assertEqual(errno.EINVAL, e.errno)

    def _clean(self, client_mode):
        priv_lib.privileged.default.client_mode = client_mode

    def test_get_link_vfs(self):
        # NOTE(ralonsoh): there should be a functional test checking this
        # method, but this is not possible due to the lack of SR-IOV capable
        # NICs in the CI servers.
        vf_info = []
        for idx in range(3):
            vf_info.append(pyroute2.netlink.nlmsg_base())
            mac_info = {'mac': 'mac_%s' % idx, 'vf': idx}
            link_state = {'link_state': idx}  # see SR-IOV pci_lib.LinkState
            vf_info[idx].setvalue(
                {'attrs': [('IFLA_VF_MAC', mac_info),
                           ('IFLA_VF_LINK_STATE', link_state)]})
        vfinfo_list = pyroute2.netlink.nlmsg_base()
        vfinfo_list.setvalue({'attrs': [('IFLA_VF_INFO', vf_info[0]),
                                        ('IFLA_VF_INFO', vf_info[1]),
                                        ('IFLA_VF_INFO', vf_info[2])]})
        value = pyroute2.netlink.nlmsg_base()
        value.setvalue({'attrs': [('IFLA_NUM_VF', 3),
                                  ('IFLA_VFINFO_LIST', vfinfo_list)]})
        client_mode = priv_lib.privileged.default.client_mode
        priv_lib.privileged.default.client_mode = False
        self.addCleanup(self._clean, client_mode)
        with mock.patch.object(priv_lib, '_run_iproute_link') as mock_iplink:
            mock_iplink.return_value = [value]
            result = priv_lib.get_link_vfs('device', 'namespace')
            self.assertEqual({0: {'mac': 'mac_0', 'link_state': 0},
                              1: {'mac': 'mac_1', 'link_state': 1},
                              2: {'mac': 'mac_2', 'link_state': 2}},
                             result)


class MakeSerializableTestCase(base.BaseTestCase):

    NLA_DATA1 = ifinfmsg.ifinfbase.state(data=b'54321')
    NLA_DATA2 = ifinfmsg.ifinfbase.state(data=b'abcdef')
    INPUT_1 = {'key1': 'value1', b'key2': b'value2', 'key3': ('a', 2),
               'key4': [1, 2, 'c'],
               b'key5': netlink.nla_slot('nla_name1', NLA_DATA1),
               'key6': netlink.nla_slot(b'nla_name2', NLA_DATA2)}
    OUTPUT_1 = {'key1': 'value1', 'key2': 'value2', 'key3': ('a', 2),
                'key4': [1, 2, 'c'],
                'key5': ['nla_name1', '54321'],
                'key6': ['nla_name2', 'abcdef']}

    def test_make_serializable(self):
        self.assertEqual(self.OUTPUT_1,
                         priv_lib.make_serializable(self.INPUT_1))
