# Copyright 2016 OVH SAS
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

import math
import mock
import testtools

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
from neutron.services.qos import qos_consts
from neutron.tests import base

DEVICE_NAME = "tap_device"
BW_LIMIT = 2000  # [kbps]
BURST = 100  # [kbit]


class BaseUnitConversionTest(object):

    def test_convert_to_kilo_bare_value(self):
        value = "10000"
        expected_value = int(math.ceil(float(80000) / self.base_unit))  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilo(value, self.base_unit)
        )

    def test_convert_to_kilo_bytes_value(self):
        value = "10000b"
        expected_value = int(math.ceil(float(80000) / self.base_unit))  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilo(value, self.base_unit)
        )

    def test_convert_to_kilo_bits_value(self):
        value = "1000bit"
        expected_value = int(math.ceil(float(1000) / self.base_unit))
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilo(value, self.base_unit)
        )

    def test_convert_to_kilo_megabytes_value(self):
        value = "1m"
        expected_value = int(math.ceil(float(self.base_unit ** 2 * 8) /
                                       self.base_unit))
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilo(value, self.base_unit)
        )

    def test_convert_to_kilo_megabits_value(self):
        value = "1mbit"
        expected_value = int(math.ceil(float(self.base_unit ** 2) /
                                       self.base_unit))
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilo(value, self.base_unit)
        )

    def test_convert_to_bytes_wrong_unit(self):
        value = "1Zbit"
        self.assertRaises(
            tc_lib.InvalidUnit,
            tc_lib.convert_to_kilo, value, self.base_unit
        )

    def test_bytes_to_bits(self):
        test_values = [
            (0, 0),  # 0 bytes should be 0 bits
            (1, 8)   # 1 byte should be 8 bits
        ]
        for input_bytes, expected_bits in test_values:
            self.assertEqual(
                expected_bits, tc_lib.bytes_to_bits(input_bytes)
            )


class TestSIUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = tc_lib.SI_BASE

    def test_bits_to_kilobits(self):
        test_values = [
            (0, 0),  # 0 bites should be 0 kilobites
            (1, 1),  # 1 bit should be 1 kilobit
            (999, 1),  # 999 bits should be 1 kilobit
            (1000, 1),  # 1000 bits should be 1 kilobit
            (1001, 2)   # 1001 bits should be 2 kilobits
        ]
        for input_bits, expected_kilobits in test_values:
            self.assertEqual(
                expected_kilobits,
                tc_lib.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestIECUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = tc_lib.IEC_BASE

    def test_bits_to_kilobits(self):
        test_values = [
            (0, 0),  # 0 bites should be 0 kilobites
            (1, 1),  # 1 bit should be 1 kilobit
            (1023, 1),  # 1023 bits should be 1 kilobit
            (1024, 1),  # 1024 bits should be 1 kilobit
            (1025, 2)   # 1025 bits should be 2 kilobits
        ]
        for input_bits, expected_kilobits in test_values:
            self.assertEqual(
                expected_kilobits,
                tc_lib.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestTcCommand(base.BaseTestCase):
    MAX_RATE = 10000
    BURST_RATE = 8000
    CBURST_RATE = 1500
    MIN_RATE = 1500
    RATE_LIMIT = 8
    DIRECTION_EGRESS = 'egress'
    DIRECTION_INGRESS = 'ingress'
    DEVICE_NAME = 'tap-test-dev'
    IFB_NAME = 'ifb-test-dev'
    CLASS_PARENT = '10:'
    CLASSID = '10:1'
    QDISC_PARENT = '20:2'
    QDISC_HANDLE = '30:'
    QDISC_ROOT = 'root'
    QDISC_INGRESS = 'ingress'
    QDISC_INGRESS_HANDLE = 'ffff:'
    FILTER_PARENT = CLASS_PARENT
    FILTER_PROTOCOL = ['all', 'u32']
    FILTER_FILTER = ['match', 'u32', '0', '0']
    FILTER_ACTION = ['mirred', 'egress', 'redirect', 'dev', IFB_NAME]
    TYPE_HTB = 'htb'

    def _call_qdisc_add(self, device, parent, handle, qdisc_type):
        cmd = ['tc', 'qdisc', 'add', 'dev', device]
        if parent in [self.QDISC_ROOT, self.QDISC_INGRESS]:
            cmd += [parent]
        else:
            cmd += ['parent', parent]
        qdisc_type = '' if qdisc_type is None else qdisc_type
        cmd += ['handle', handle, qdisc_type]
        return cmd

    def _call_qdisc_del(self, device, parent):
        cmd = ['tc', 'qdisc', 'del', 'dev', device]
        if parent in [self.QDISC_ROOT, self.QDISC_INGRESS]:
            cmd += [parent]
        else:
            cmd += ['parent', parent]
        return cmd

    @staticmethod
    def _call_qdisc_show(device):
        return ['tc', 'qdisc', 'show', 'dev', device]

    def _call_class_replace(self, device, parent, classid, type, rate, ceil,
                            burst):
        cmd = ['class', 'replace', 'dev', device]
        if parent:
            cmd += ['parent', parent]
        rate = self.RATE_LIMIT if rate < self.RATE_LIMIT else rate
        cmd += ['classid', classid, type, 'rate', rate]
        if ceil:
            ceil = rate if ceil < rate else ceil
            cmd += ['ceil', ceil]
        if burst:
            cmd += ['burst', burst]
        return cmd

    @staticmethod
    def _call_class_show(device):
        return ['tc', 'class', 'show', 'dev', device]

    @staticmethod
    def _call_filter_add(device, parent, protocol, filter, action):
        cmd = ['tc', 'filter', 'add', 'dev', device, 'parent', parent,
               'protocol'] + protocol + filter
        if action:
            cmd += ['action'] + action
        return cmd

    @staticmethod
    def _call_filter_show(device, parent):
        return ['tc', 'filter', 'show', 'dev', device, 'parent', parent]

    def setUp(self):
        super(TestTcCommand, self).setUp()
        self.tc = tc_lib.TcCommand(self.DEVICE_NAME)
        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

    def test_set_bw_egress(self):
        with mock.patch.object(self.tc, '_set_ingress_bw') as \
                mock_set_ingress_bw:
            self.tc.set_bw(self.MAX_RATE,
                           self.BURST_RATE,
                           self.MIN_RATE,
                           self.DIRECTION_EGRESS)
            mock_set_ingress_bw.assert_called_once_with(
                self.MAX_RATE * tc_lib.SI_BASE,
                (self.BURST_RATE * tc_lib.IEC_BASE) / 8,
                self.MIN_RATE * tc_lib.SI_BASE)

    def test_set_bw_ingress(self):
        with testtools.ExpectedException(NotImplementedError):
            self.tc.set_bw(self.MAX_RATE, self.BURST_RATE, self.MIN_RATE,
                           self.DIRECTION_INGRESS)

    def test_delete_bw_egress(self):
        with mock.patch.object(self.tc, '_delete_ingress') as \
                mock_delete_ingress:
            self.tc.delete_bw(self.DIRECTION_EGRESS)
            mock_delete_ingress.assert_called_once_with()

    def test_delete_bw_ingress(self):
        with testtools.ExpectedException(NotImplementedError):
            self.tc.delete_bw(self.DIRECTION_INGRESS)

    def test_set_ingress_bw(self):
        with mock.patch.object(self.tc, '_add_policy_qdisc') as \
                mock_add_policy_qdisc, \
                mock.patch.object(self.tc, '_configure_ifb') as \
                mock_configure_ifb:
            self.tc._set_ingress_bw(self.MAX_RATE, self.BURST_RATE,
                                    self.MIN_RATE)
            mock_add_policy_qdisc.assert_called_once_with(
                tc_lib.INGRESS_QDISC, tc_lib.INGRESS_QDISC_HANDLE)
            mock_configure_ifb.assert_called_once_with(
                max=self.MAX_RATE, burst=self.BURST_RATE,
                min=self.MIN_RATE)

    def test_delete_ingress_no_ifb(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                return_value=None) as mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_del_policy_qdisc') as \
                mock_del_policy_qdisc:
            self.tc._delete_ingress()
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_del_policy_qdisc.assert_called_once_with(tc_lib.INGRESS_QDISC)

    def test_delete_ingress_with_ifb(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                return_value=self.IFB_NAME) as mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_del_policy_qdisc') as \
                mock_del_policy_qdisc, \
                mock.patch.object(self.tc, '_del_ifb') as mock_del_ifb:
            self.tc._delete_ingress()
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_del_policy_qdisc.assert_called_once_with(tc_lib.INGRESS_QDISC)
            mock_del_ifb.assert_called_once_with(self.IFB_NAME)

    def test_add_policy_qdisc_no_qdisc(self):
        with mock.patch.object(self.tc, '_show_policy_qdisc',
                               return_value=None) as \
                mock_show_policy_qdisc:
            self.tc._add_policy_qdisc(self.QDISC_PARENT, self.QDISC_HANDLE)
            mock_show_policy_qdisc.assert_called_once_with(
                self.QDISC_PARENT, dev=self.DEVICE_NAME)

    def test_add_policy_qdisc_existing_qdisc(self):
        with mock.patch.object(self.tc, '_show_policy_qdisc') as \
                mock_show_policy_qdisc, \
                mock.patch.object(self.tc, '_del_policy_qdisc') as \
                mock_del_policy_qdisc:
            qdisc = {'type': self.TYPE_HTB,
                     'handle': self.QDISC_HANDLE,
                     'parentid': 'parent1'}
            mock_show_policy_qdisc.return_value = qdisc
            self.tc._add_policy_qdisc(self.QDISC_PARENT,
                self.QDISC_HANDLE, qdisc_type=self.TYPE_HTB)
            mock_show_policy_qdisc.assert_called_once_with(
                self.QDISC_PARENT, dev=self.DEVICE_NAME)
            mock_del_policy_qdisc.assert_not_called()

    def _add_policy_qdisc_parent_type(self, parent, type):
        with mock.patch.object(self.tc, '_show_policy_qdisc') as \
                mock_show_policy_qdisc, \
                mock.patch.object(self.tc, '_del_policy_qdisc') as \
                mock_del_policy_qdisc:
            qdisc = {'type': 'type1',
                     'handle': 'handle1',
                     'parentid': 'parent1'}
            mock_show_policy_qdisc.return_value = qdisc
            self.tc._add_policy_qdisc(parent, self.QDISC_HANDLE,
                                      qdisc_type=type)
            mock_show_policy_qdisc.assert_called_once_with(
                parent, dev=self.DEVICE_NAME)
            mock_del_policy_qdisc.assert_called_once_with(parent,
                                                          dev=self.DEVICE_NAME)
            cmd = self._call_qdisc_add(self.DEVICE_NAME, parent,
                                       self.QDISC_HANDLE, type)
            self.execute.assert_called_once_with(cmd, check_exit_code=True,
                extra_ok_codes=None, log_fail_as_error=True, run_as_root=True)

    def test_add_policy_qdisc_root_parent(self):
        self._add_policy_qdisc_parent_type(self.QDISC_ROOT, self.TYPE_HTB)

    def test_add_policy_qdisc_ingress_parent(self):
        self._add_policy_qdisc_parent_type(self.QDISC_INGRESS, self.TYPE_HTB)

    def test_add_policy_qdisc_other_parent(self):
        self._add_policy_qdisc_parent_type(self.QDISC_PARENT, self.TYPE_HTB)

    def _add_policy_qdisc_no_qdisc_type(self):
        self._add_policy_qdisc_parent_type(self.QDISC_PARENT, None)

    def test_del_policy_qdisc(self):
        with mock.patch.object(self.tc, '_show_policy_qdisc',
                               return_value=True):
            self.tc._del_policy_qdisc(self.QDISC_PARENT)
            cmd = self._call_qdisc_del(self.DEVICE_NAME, self.QDISC_PARENT)
            self.execute.assert_called_once_with(cmd, check_exit_code=True,
                extra_ok_codes=None, log_fail_as_error=True, run_as_root=True)

    def test_del_policy_qdisc_root_parent(self):
        with mock.patch.object(self.tc, '_show_policy_qdisc',
                               return_value=True):
            self.tc._del_policy_qdisc(self.QDISC_ROOT)
            cmd = self._call_qdisc_del(self.DEVICE_NAME, self.QDISC_ROOT)
            self.execute.assert_called_once_with(cmd, check_exit_code=True,
                extra_ok_codes=None, log_fail_as_error=True, run_as_root=True)

    def test_del_policy_qdisc_no_qdisc(self):
        with mock.patch.object(self.tc, '_show_policy_qdisc',
                               return_value=False):
            self.tc._del_policy_qdisc(self.QDISC_ROOT)
            self.execute.assert_not_called()

    def test_list_policy_qdisc(self):
        qdisc_out = 'qdisc htb 1: root refcnt 2 r2q 10 default 0 '
        qdisc_out += 'direct_packets_stat 138 direct_qlen 32\n'
        qdisc_out += 'qdisc htb 10: parent 1:1 r2q 10 default 0 '
        qdisc_out += 'direct_packets_stat 0 direct_qlen 32\n'
        qdisc_out += 'qdisc ingress ffff: parent ffff:fff1 ----------------'
        self.execute.return_value = qdisc_out
        ret_value = self.tc._list_policy_qdisc()
        cmd = self._call_qdisc_show(self.DEVICE_NAME)
        self.execute.assert_called_once_with(cmd, check_exit_code=True,
                                             extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             run_as_root=True)
        qdiscs = {'1:1': {'handle': '10:',
                          'type': 'htb',
                          'parentid': '1:1'},
                  'root': {'handle': '1:',
                           'type': 'htb',
                           'parentid': 'root'},
                  'ingress': {'handle': 'ffff:',
                              'type': 'ingress',
                              'parentid': 'ffff:fff1'}}
        self.assertEqual(qdiscs, ret_value)

    def test_list_policy_qdisc_no_match(self):
        self.execute.return_value = 'no matches'
        ret_value = self.tc._list_policy_qdisc()
        cmd = self._call_qdisc_show(self.DEVICE_NAME)
        self.execute.assert_called_once_with(cmd, check_exit_code=True,
                                             extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             run_as_root=True)
        qdiscs = {}
        self.assertEqual(qdiscs, ret_value)

    def test_show_policy_qdisc(self):
        with mock.patch.object(self.tc, '_list_policy_qdisc') as \
                mock_list_policy_qdisc:
            self.tc._show_policy_qdisc(self.QDISC_PARENT)
            mock_list_policy_qdisc.assert_called_once_with(self.DEVICE_NAME)

    def test_add_policy_class_existing_class_set_min_bw(self):
        with mock.patch.object(self.tc, '_show_policy_class') as \
                mock_show_policy_class, \
                mock.patch.object(self.tc, '_cmd_policy_class') as \
                mock_cmd_policy_class:
            classes = {'type': self.TYPE_HTB,
                       'parentid': self.CLASS_PARENT,
                       'prio': 0,
                       'rate': self.MIN_RATE + 1,
                       'ceil': self.MAX_RATE,
                       'burst': self.BURST_RATE,
                       'cburst': self.CBURST_RATE}
            mock_show_policy_class.return_value = classes
            _min = tc_lib.kilobits_to_bits(self.MIN_RATE, tc_lib.SI_BASE)
            _max = tc_lib.kilobits_to_bits(self.MAX_RATE, tc_lib.SI_BASE)
            _burst = tc_lib.bits_to_bytes(tc_lib.kilobits_to_bits(
                self.BURST_RATE, tc_lib.IEC_BASE))
            cmd = self._call_class_replace(self.DEVICE_NAME,
                self.CLASS_PARENT, self.CLASSID, self.TYPE_HTB, _min,
                None, None)
            mock_cmd_policy_class.return_value = cmd
            self.tc._add_policy_class(self.CLASS_PARENT, self.CLASSID,
                                      self.TYPE_HTB, rate=_min)
            mock_show_policy_class.assert_called_once_with(
                self.CLASSID, dev=self.DEVICE_NAME)
            mock_cmd_policy_class.assert_called_once_with(self.CLASSID,
                self.TYPE_HTB, _min, self.DEVICE_NAME, self.CLASS_PARENT,
                _max, _burst)
            self.execute.assert_called_once_with(['tc'] + cmd,
                check_exit_code=True, extra_ok_codes=None,
                log_fail_as_error=True, run_as_root=True)

    def test_add_policy_class_existing_class_set_bw_limit(self):
        with mock.patch.object(self.tc, '_show_policy_class') as \
                mock_show_policy_class, \
                mock.patch.object(self.tc, '_cmd_policy_class') as \
                mock_cmd_policy_class:
            classes = {'type': self.TYPE_HTB,
                       'parentid': self.CLASS_PARENT,
                       'prio': 0,
                       'rate': self.MIN_RATE,
                       'ceil': self.MAX_RATE + 1,
                       'burst': self.BURST_RATE + 1,
                       'cburst': self.CBURST_RATE}
            mock_show_policy_class.return_value = classes
            _min = tc_lib.kilobits_to_bits(self.MIN_RATE, tc_lib.SI_BASE)
            _max = tc_lib.kilobits_to_bits(self.MAX_RATE, tc_lib.SI_BASE)
            _burst = tc_lib.bits_to_bytes(tc_lib.kilobits_to_bits(
                self.BURST_RATE, tc_lib.IEC_BASE))
            cmd = ['tc'] + self._call_class_replace(self.DEVICE_NAME,
                self.CLASS_PARENT, self.CLASSID, self.TYPE_HTB, _min,
                _max, _burst)
            mock_cmd_policy_class.return_value = cmd
            self.tc._add_policy_class(self.CLASS_PARENT, self.CLASSID,
                                      self.TYPE_HTB, ceil=_max, burst=_burst)
            mock_show_policy_class.assert_called_once_with(
                self.CLASSID, dev=self.DEVICE_NAME)
            mock_cmd_policy_class.assert_called_once_with(self.CLASSID,
                self.TYPE_HTB, _min, self.DEVICE_NAME, self.CLASS_PARENT,
                _max, _burst)
            self.execute.assert_called_once_with(['tc'] + cmd,
                check_exit_code=True, extra_ok_codes=None,
                log_fail_as_error=True, run_as_root=True)

    def test_add_policy_class_non_existing_class(self):
        with mock.patch.object(self.tc, '_show_policy_class',
                               return_value={}) as mock_show_policy_class, \
                mock.patch.object(self.tc, '_cmd_policy_class') as \
                mock_cmd_policy_class:
            _min = tc_lib.kilobits_to_bits(self.MIN_RATE, tc_lib.SI_BASE)
            cmd = ['tc'] + self._call_class_replace(self.DEVICE_NAME,
                self.CLASS_PARENT, self.CLASSID, self.TYPE_HTB, _min,
                None, None)
            mock_cmd_policy_class.return_value = cmd
            self.tc._add_policy_class(self.CLASS_PARENT, self.CLASSID,
                                      self.TYPE_HTB, rate=_min)
            mock_show_policy_class.assert_called_once_with(
                self.CLASSID, dev=self.DEVICE_NAME)
            mock_cmd_policy_class.assert_called_once_with(self.CLASSID,
                self.TYPE_HTB, _min, self.DEVICE_NAME, self.CLASS_PARENT,
                None, None)
            self.execute.assert_called_once_with(['tc'] + cmd,
                check_exit_code=True, extra_ok_codes=None,
                log_fail_as_error=True, run_as_root=True)

    def test_add_policy_class_no_rate_no_ceil(self):
        with testtools.ExpectedException(tc_lib.InvalidPolicyClassParameters):
            self.tc._add_policy_class(self.CLASS_PARENT, self.CLASSID,
                                      self.TYPE_HTB, rate=None, ceil=None)

    def test_cmd_policy_class(self):
        cmd_out = self.tc._cmd_policy_class(self.CLASSID, self.TYPE_HTB,
                                            self.MIN_RATE, self.DEVICE_NAME,
                                            self.CLASS_PARENT, self.MAX_RATE,
                                            self.BURST_RATE)
        cmd_ref = self._call_class_replace(self.DEVICE_NAME, self.CLASS_PARENT,
                                           self.CLASSID, self.TYPE_HTB,
                                           self.MIN_RATE, self.MAX_RATE,
                                           self.BURST_RATE)
        self.assertEqual(cmd_ref, cmd_out)

    def test_cmd_policy_class_no_parent(self):
        cmd_out = self.tc._cmd_policy_class(self.CLASSID, self.TYPE_HTB,
                                            self.MIN_RATE, self.DEVICE_NAME,
                                            None, self.MAX_RATE,
                                            self.BURST_RATE)
        cmd_ref = self._call_class_replace(self.DEVICE_NAME, None,
                                           self.CLASSID, self.TYPE_HTB,
                                           self.MIN_RATE, self.MAX_RATE,
                                           self.BURST_RATE)
        self.assertEqual(cmd_ref, cmd_out)

    def test_cmd_policy_class_rate_less_8(self):
        cmd_out = self.tc._cmd_policy_class(self.CLASSID, self.TYPE_HTB,
                                            5, self.DEVICE_NAME,
                                            self.CLASS_PARENT, None, None)
        cmd_ref = self._call_class_replace(self.DEVICE_NAME, self.CLASS_PARENT,
                                           self.CLASSID, self.TYPE_HTB,
                                           self.RATE_LIMIT, None, None)
        self.assertEqual(cmd_ref, cmd_out)

    def test_cmd_policy_class_no_ceil(self):
        cmd_out = self.tc._cmd_policy_class(self.CLASSID, self.TYPE_HTB,
                                            self.MIN_RATE, self.DEVICE_NAME,
                                            self.CLASS_PARENT, None,
                                            self.BURST_RATE)
        cmd_ref = self._call_class_replace(self.DEVICE_NAME, self.CLASS_PARENT,
                                           self.CLASSID, self.TYPE_HTB,
                                           self.MIN_RATE, None,
                                           self.BURST_RATE)
        self.assertEqual(cmd_ref, cmd_out)

    def test_cmd_policy_class_no_burst(self):
        cmd_out = self.tc._cmd_policy_class(self.CLASSID, self.TYPE_HTB,
                                            self.MIN_RATE, self.DEVICE_NAME,
                                            self.CLASS_PARENT, None, None)
        cmd_ref = self._call_class_replace(self.DEVICE_NAME, self.CLASS_PARENT,
                                           self.CLASSID, self.TYPE_HTB,
                                           self.MIN_RATE, None, None)
        self.assertEqual(cmd_ref, cmd_out)

    def test_list_policy_class(self):
        class_out = 'class htb 1:1 root rate 300000bit ceil 300000bit burst '
        class_out += '2560b cburst 2688b\n'
        class_out += 'class htb 1:10 parent 1:1 prio 0 rate 24000bit ceil '
        class_out += '300000bit burst 2560b cburst 2688b\n'
        class_out += 'class htb 1:20 parent 1:1 prio 1 rate 24000bit ceil '
        class_out += '300000bit burst 2560b cburst 2688b'
        self.execute.return_value = class_out
        ret_val = self.tc._list_policy_class()
        cmd = self._call_class_show(self.DEVICE_NAME)
        self.execute.assert_called_once_with(cmd, check_exit_code=False,
                                             extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             run_as_root=True)
        expected = {'1:1': {'prio': None, 'burst': 20, 'ceil': 300,
                            'rate': 300, 'parentid': None, 'cburst': 21,
                            'type': 'htb'},
                    '1:10': {'prio': '0', 'burst': 20, 'ceil': 300, 'rate': 24,
                             'parentid': '1:1', 'cburst': 21, 'type': 'htb'},
                    '1:20': {'prio': '1', 'burst': 20, 'ceil': 300, 'rate': 24,
                             'parentid': '1:1', 'cburst': 21, 'type': 'htb'}}
        self.assertEqual(expected, ret_val)

    def test_show_policy_class(self):
        with mock.patch.object(self.tc, '_list_policy_class') as \
                mock_list_policy_class:
            classes = {self.CLASSID: {'prio': None, 'burst': 20, 'ceil': 300,
                                      'rate': 300, 'parentid': None,
                                      'cburst': 21, 'type': 'htb'}}
            mock_list_policy_class.return_value = classes
            ret_val = self.tc._show_policy_class(self.CLASSID)
            mock_list_policy_class.assert_called_once_with(self.DEVICE_NAME)
            self.assertEqual(classes[self.CLASSID], ret_val)

    def test_add_policy_filter_with_action(self):
        self.tc._add_policy_filter(self.FILTER_PARENT, self.FILTER_PROTOCOL,
                                   self.FILTER_FILTER,
                                   action=self.FILTER_ACTION)
        cmd = self._call_filter_add(self.DEVICE_NAME, self.FILTER_PARENT,
                                    self.FILTER_PROTOCOL, self.FILTER_FILTER,
                                    self.FILTER_ACTION)
        self.execute.assert_called_once_with(cmd, check_exit_code=True,
                                             extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             run_as_root=True)

    def test_add_policy_filter_without_action(self):
        self.tc._add_policy_filter(self.FILTER_PARENT, self.FILTER_PROTOCOL,
                                   self.FILTER_FILTER)
        cmd = self._call_filter_add(self.DEVICE_NAME, self.FILTER_PARENT,
                                    self.FILTER_PROTOCOL, self.FILTER_FILTER,
                                    None)
        self.execute.assert_called_once_with(cmd, check_exit_code=True,
                                             extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             run_as_root=True)

    def test_list_policy_filters_root_parent(self):
        self.tc._list_policy_filters(self.QDISC_ROOT)
        cmd = self._call_filter_show(self.DEVICE_NAME,
                                     self.QDISC_ROOT)
        self.execute.assert_called_once_with(cmd, extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             check_exit_code=True,
                                             run_as_root=True)

    def test_list_policy_filters_other_parent(self):
        self.tc._list_policy_filters(self.QDISC_INGRESS_HANDLE)
        cmd = self._call_filter_show(self.DEVICE_NAME,
                                     self.QDISC_INGRESS_HANDLE)
        self.execute.assert_called_once_with(cmd, extra_ok_codes=None,
                                             log_fail_as_error=True,
                                             check_exit_code=True,
                                             run_as_root=True)

    @mock.patch.object(ip_lib.IPWrapper, "add_ifb")
    @mock.patch.object(ip_lib.IPDevice, "exists")
    @mock.patch.object(ip_lib.IPDevice, "disable_ipv6")
    @mock.patch.object(ip_lib.IpLinkCommand, "set_up")
    def test_add_ifb_existing_ifb(self, mock_set_up, mock_disable_ipv6,
                                  mock_exists, mock_add_ifb):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=True):
            mock_exists.return_value = True
            self.tc._add_ifb(self.DEVICE_NAME)
            mock_add_ifb.assert_not_called()
            mock_exists.assert_called_once_with()
            mock_disable_ipv6.assert_called_once_with()
            mock_set_up.assert_called_once_with()

    @mock.patch.object(ip_lib.IPWrapper, "add_ifb")
    @mock.patch.object(ip_lib.IPDevice, "exists")
    @mock.patch.object(ip_lib.IPDevice, "disable_ipv6")
    @mock.patch.object(ip_lib.IpLinkCommand, "set_up")
    def test_add_ifb_non_existing_ifb(self, mock_set_up, mock_disable_ipv6,
                                      mock_exists,
                                      mock_add_ifb):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=True), \
                mock.patch.object(self.tc, '_del_ifb') as mock_del_ifb:
            mock_exists.return_value = False
            mock_add_ifb.return_value = ip_lib.IPDevice(self.DEVICE_NAME)
            self.tc._add_ifb(self.DEVICE_NAME)
            mock_add_ifb.assert_called_once_with(self.DEVICE_NAME)
            mock_exists.assert_called_once_with()
            mock_del_ifb.assert_called_once_with(dev_name=self.DEVICE_NAME)
            mock_disable_ipv6.assert_called_once_with()
            mock_set_up.assert_called_once_with()

    @mock.patch.object(ip_lib.IPWrapper, "add_ifb")
    @mock.patch.object(ip_lib.IPDevice, "disable_ipv6")
    @mock.patch.object(ip_lib.IpLinkCommand, "set_up")
    def test_add_ifb_not_found(self, mock_set_up, mock_disable_ipv6,
                               mock_add_ifb):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=False), \
                mock.patch.object(self.tc, '_del_ifb') as mock_del_ifb:
            mock_add_ifb.return_value = ip_lib.IPDevice(self.DEVICE_NAME)
            self.tc._add_ifb(self.DEVICE_NAME)
            mock_add_ifb.assert_called_once_with(self.DEVICE_NAME)
            mock_del_ifb.assert_called_once_with(dev_name=self.DEVICE_NAME)
            mock_disable_ipv6.assert_called_once_with()
            mock_set_up.assert_called_once_with()

    @mock.patch.object(ip_lib.IPWrapper, "del_ifb")
    @mock.patch.object(ip_lib.IPWrapper, "get_devices")
    def test_del_ifb_existing_netdevice(self, mock_get_devices, mock_del_ifb):
        ret_val = [ip_lib.IPDevice('other_name'),
                   ip_lib.IPDevice(self.DEVICE_NAME)]
        mock_get_devices.return_value = ret_val
        self.tc._del_ifb(self.DEVICE_NAME)
        mock_del_ifb.assert_called_once_with(self.DEVICE_NAME)

    @mock.patch.object(ip_lib.IPWrapper, "del_ifb")
    @mock.patch.object(ip_lib.IPWrapper, "get_devices")
    def test_del_ifb_not_existing_netdevice(self, mock_get_devices,
                                            mock_del_ifb):
        ret_val = [ip_lib.IPDevice('other_name'),
                   ip_lib.IPDevice('another_name')]
        mock_get_devices.return_value = ret_val
        self.tc._del_ifb(self.DEVICE_NAME)
        mock_del_ifb.assert_not_called()

    @mock.patch.object(ip_lib.IPWrapper, "del_ifb")
    @mock.patch.object(ip_lib.IPWrapper, "get_devices")
    def test_del_ifb_no_netdevices(self, mock_get_devices, mock_del_ifb):
        mock_get_devices.return_value = []
        self.tc._del_ifb(self.DEVICE_NAME)
        mock_del_ifb.assert_not_called()

    @mock.patch.object(ip_lib.IPDevice, "exists")
    def test_find_mirrored_ifb(self, mock_ipdevice_exists):
        ifb_name = self.tc._name.replace("tap", "ifb")
        mock_ipdevice_exists.return_value = True
        ret = self.tc._find_mirrored_ifb()
        self.assertEqual(ifb_name, ret)
        mock_ipdevice_exists.return_value = False
        ret = self.tc._find_mirrored_ifb()
        self.assertIsNone(ret)

    def test_configure_ifb_non_existing_ifb(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=None) as \
                mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_add_ifb',
                                  return_value=self.IFB_NAME) as \
                mock_add_ifb, \
                mock.patch.object(self.tc, '_add_policy_qdisc') as \
                mock_add_policy_qdisc, \
                mock.patch.object(self.tc, '_add_policy_class') as \
                mock_add_policy_class, \
                mock.patch.object(self.tc, '_add_policy_filter') as \
                mock_add_policy_filter:
            self.tc._configure_ifb(max=self.MAX_RATE, burst=self.BURST_RATE,
                                   min=self.MIN_RATE)
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_add_ifb.assert_called_once_with(self.IFB_NAME)
            mock_add_policy_filter.assert_called_once_with(
                self.QDISC_INGRESS_HANDLE, self.FILTER_PROTOCOL,
                self.FILTER_FILTER, dev=self.DEVICE_NAME,
                action=self.FILTER_ACTION)
            mock_add_policy_qdisc.assert_called_once_with(
                self.QDISC_ROOT, "1:", qdisc_type=self.TYPE_HTB,
                dev=self.IFB_NAME)
            mock_add_policy_class.assert_called_once_with("1:", "1:1",
                self.TYPE_HTB, rate=self.MIN_RATE, ceil=self.MAX_RATE,
                burst=self.BURST_RATE, dev=self.IFB_NAME)

    def test_configure_ifb_existing_ifb(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=self.IFB_NAME) as \
                mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_add_ifb',
                                  return_value=self.IFB_NAME) as \
                mock_add_ifb, \
                mock.patch.object(self.tc, '_add_policy_qdisc') as \
                mock_add_policy_qdisc, \
                mock.patch.object(self.tc, '_add_policy_class') as \
                mock_add_policy_class:
            self.tc._configure_ifb(max=self.MAX_RATE, burst=self.BURST_RATE,
                                   min=self.MIN_RATE)
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_add_ifb.assert_not_called()
            mock_add_policy_qdisc.assert_called_once_with(
                self.QDISC_ROOT, "1:", qdisc_type=self.TYPE_HTB,
                dev=self.IFB_NAME)
            mock_add_policy_class.assert_called_once_with("1:", "1:1",
                self.TYPE_HTB, rate=self.MIN_RATE, ceil=self.MAX_RATE,
                burst=self.BURST_RATE, dev=self.IFB_NAME)

    def test_get_ingress_qdisc_burst_value_burst_not_none(self):
        self.assertEqual(
            BURST, self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, BURST)
        )

    def test_get_ingress_qdisc_burst_value_no_burst_value_given(self):
        expected_burst = BW_LIMIT * qos_consts.DEFAULT_BURST_RATE
        self.assertEqual(
            expected_burst,
            self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, None)
        )

    def test_get_ingress_qdisc_burst_value_burst_value_zero(self):
        expected_burst = BW_LIMIT * qos_consts.DEFAULT_BURST_RATE
        self.assertEqual(
            expected_burst,
            self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, 0)
        )

    def test_get_ingress_limits_no_ifb(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=None) as \
                mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_show_policy_class') as \
                mock_show_policy_class:
            max_bw, burst, min_bw = self.tc._get_ingress_limits()
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_show_policy_class.assert_not_called()
            self.assertIsNone(max_bw)
            self.assertIsNone(burst)
            self.assertIsNone(min_bw)

    def test_get_ingress_limits_ifb_present(self):
        with mock.patch.object(self.tc, '_find_mirrored_ifb',
                               return_value=self.IFB_NAME) as \
                mock_find_mirrored_ifb, \
                mock.patch.object(self.tc, '_show_policy_class') as \
                mock_show_policy_class:
            classes = {'rate': self.MIN_RATE,
                       'ceil': self.MAX_RATE,
                       'burst': self.BURST_RATE}
            mock_show_policy_class.return_value = classes
            max_bw, burst, min_bw = self.tc._get_ingress_limits()
            mock_find_mirrored_ifb.assert_called_once_with()
            mock_show_policy_class.assert_called_once_with("1:1",
                                                           dev=self.IFB_NAME)
            self.assertEqual((self.MAX_RATE, self.BURST_RATE, self.MIN_RATE),
                             (max_bw, burst, min_bw))
