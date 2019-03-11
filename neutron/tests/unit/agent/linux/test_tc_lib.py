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

import mock
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.services.qos import constants as qos_consts
from pyroute2.netlink import rtnl

from neutron.agent.linux import tc_lib
from neutron.common import constants
from neutron.common import utils
from neutron.privileged.agent.linux import tc_lib as priv_tc_lib
from neutron.tests import base

DEVICE_NAME = "tap_device"
KERNEL_HZ_VALUE = 1000
BW_LIMIT = 2000  # [kbps]
BURST = 100  # [kbit]
LATENCY = 50  # [ms]

TC_FILTERS_OUTPUT = (
    'filter protocol all pref 49152 u32 \nfilter protocol all pref '
    '49152 u32 fh 800: ht divisor 1 \nfilter protocol all pref 49152 u32 fh '
    '800::800 order 2048 key ht 800 \n  match 00000000/00000000 at 0\n  '
    'police 0x1e rate %(bw)skbit burst %(burst)skbit mtu 2Kb action \n'
    'drop overhead 0b \n  ref 1 bind 1'
) % {'bw': BW_LIMIT, 'burst': BURST}


class BaseUnitConversionTest(object):

    def test_convert_to_kilobits_bare_value(self):
        value = "1000"
        expected_value = 8  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_bytes_value(self):
        value = "1000b"
        expected_value = 8  # kbit
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_bits_value(self):
        value = "1000bit"
        expected_value = utils.bits_to_kilobits(1000, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_megabytes_value(self):
        value = "1m"
        expected_value = utils.bits_to_kilobits(
            self.base_unit ** 2 * 8, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_kilobits_megabits_value(self):
        value = "1mbit"
        expected_value = utils.bits_to_kilobits(
            self.base_unit ** 2, self.base_unit)
        self.assertEqual(
            expected_value,
            tc_lib.convert_to_kilobits(value, self.base_unit)
        )

    def test_convert_to_bytes_wrong_unit(self):
        value = "1Zbit"
        self.assertRaises(
            tc_lib.InvalidUnit,
            tc_lib.convert_to_kilobits, value, self.base_unit
        )


class TestSIUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = constants.SI_BASE


class TestIECUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = constants.IEC_BASE


class TestTcCommand(base.BaseTestCase):
    def setUp(self):
        super(TestTcCommand, self).setUp()
        self.tc = tc_lib.TcCommand(DEVICE_NAME, KERNEL_HZ_VALUE)
        self.mock_list_tc_qdiscs = mock.patch.object(tc_lib,
                                                     'list_tc_qdiscs').start()
        self.mock_add_tc_qdisc = mock.patch.object(tc_lib,
                                                   'add_tc_qdisc').start()
        self.mock_delete_tc_qdisc = mock.patch.object(
            tc_lib, 'delete_tc_qdisc').start()
        self.mock_list_tc_filters = mock.patch.object(
            tc_lib, 'list_tc_filters').start()
        self.mock_add_tc_filter_policy = mock.patch.object(
            tc_lib, 'add_tc_filter_policy').start()

    def test_check_kernel_hz_lower_then_zero(self):
        self.assertRaises(
            tc_lib.InvalidKernelHzValue,
            tc_lib.TcCommand, DEVICE_NAME, 0
        )
        self.assertRaises(
            tc_lib.InvalidKernelHzValue,
            tc_lib.TcCommand, DEVICE_NAME, -100
        )

    def test_get_filters_bw_limits(self):
        self.mock_list_tc_filters.return_value = [{'rate_kbps': BW_LIMIT,
                                                   'burst_kb': BURST}]
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst_limit)

    def test_get_filters_bw_limits_no_filters(self):
        self.mock_list_tc_filters.return_value = []
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_filters_bw_limits_no_rate_info(self):
        self.mock_list_tc_filters.return_value = [{'other_values': 1}]
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_tbf_bw_limits(self):
        self.mock_list_tc_qdiscs.return_value = [
            {'qdisc_type': 'tbf', 'max_kbps': BW_LIMIT, 'burst_kb': BURST}]
        self.assertEqual((BW_LIMIT, BURST), self.tc.get_tbf_bw_limits())

    def test_get_tbf_bw_limits_when_wrong_qdisc(self):
        self.mock_list_tc_qdiscs.return_value = [{'qdisc_type': 'other_type'}]
        self.assertEqual((None, None), self.tc.get_tbf_bw_limits())

    def test_set_tbf_bw_limit(self):
        self.tc.set_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        self.mock_add_tc_qdisc.assert_called_once_with(
            DEVICE_NAME, 'tbf', parent='root', max_kbps=BW_LIMIT,
            burst_kb=BURST, latency_ms=LATENCY, kernel_hz=self.tc.kernel_hz,
            namespace=self.tc.namespace)

    def test_update_filters_bw_limit(self):
        self.tc.update_filters_bw_limit(BW_LIMIT, BURST)
        self.mock_add_tc_qdisc.assert_called_once_with(
            self.tc.name, 'ingress', namespace=self.tc.namespace)
        self.mock_delete_tc_qdisc.assert_called_once_with(
            self.tc.name, is_ingress=True, raise_interface_not_found=False,
            raise_qdisc_not_found=False, namespace=self.tc.namespace)
        self.mock_add_tc_filter_policy.assert_called_once_with(
            self.tc.name, tc_lib.INGRESS_QDISC_ID, BW_LIMIT, BURST,
            tc_lib.MAX_MTU_VALUE, 'drop', priority=49)

    def test_delete_filters_bw_limit(self):
        self.tc.delete_filters_bw_limit()
        self.mock_delete_tc_qdisc.assert_called_once_with(
            DEVICE_NAME, is_ingress=True, raise_interface_not_found=False,
            raise_qdisc_not_found=False, namespace=self.tc.namespace)

    def test_delete_tbf_bw_limit(self):
        self.tc.delete_tbf_bw_limit()
        self.mock_delete_tc_qdisc.assert_called_once_with(
            DEVICE_NAME, parent='root', raise_interface_not_found=False,
            raise_qdisc_not_found=False, namespace=self.tc.namespace)

    def test_get_ingress_qdisc_burst_value_burst_not_none(self):
        self.assertEqual(
            BURST, self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, BURST)
        )

    def test_get_ingress_qdisc_burst_no_burst_value_given(self):
        expected_burst = BW_LIMIT * qos_consts.DEFAULT_BURST_RATE
        self.assertEqual(
            expected_burst,
            self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, None)
        )

    def test_get_ingress_qdisc_burst_burst_value_zero(self):
        expected_burst = BW_LIMIT * qos_consts.DEFAULT_BURST_RATE
        self.assertEqual(
            expected_burst,
            self.tc.get_ingress_qdisc_burst_value(BW_LIMIT, 0)
        )


class TcTestCase(base.BaseTestCase):

    def setUp(self):
        super(TcTestCase, self).setUp()
        self.mock_add_tc_qdisc = mock.patch.object(
            priv_tc_lib, 'add_tc_qdisc').start()
        self.namespace = 'namespace'

    def test_add_tc_qdisc_htb(self):
        tc_lib.add_tc_qdisc('device', 'htb', parent='root', handle='1:',
                            namespace=self.namespace)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb', handle='1:0',
            namespace=self.namespace)
        self.mock_add_tc_qdisc.reset_mock()

        tc_lib.add_tc_qdisc('device', 'htb', parent='root', handle='2',
                            namespace=self.namespace)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb', handle='2:0',
            namespace=self.namespace)
        self.mock_add_tc_qdisc.reset_mock()

        tc_lib.add_tc_qdisc('device', 'htb', parent='root', handle='3:12',
                            namespace=self.namespace)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb', handle='3:0',
            namespace=self.namespace)
        self.mock_add_tc_qdisc.reset_mock()

        tc_lib.add_tc_qdisc('device', 'htb', parent='root', handle=4,
                            namespace=self.namespace)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb', handle='4:0',
            namespace=self.namespace)
        self.mock_add_tc_qdisc.reset_mock()

        tc_lib.add_tc_qdisc('device', 'htb', parent='root',
                            namespace=self.namespace)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb',
            namespace=self.namespace)
        self.mock_add_tc_qdisc.reset_mock()

        tc_lib.add_tc_qdisc('device', 'htb', parent='root', handle=5)
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='htb', handle='5:0',
            namespace=None)
        self.mock_add_tc_qdisc.reset_mock()

    def test_add_tc_qdisc_tbf(self):
        tc_lib.add_tc_qdisc('device', 'tbf', parent='root', max_kbps=10000,
                            burst_kb=1500, latency_ms=70, kernel_hz=250,
                            namespace=self.namespace)
        burst = tc_lib._get_tbf_burst_value(10000, 1500, 70) * 1024 / 8
        self.mock_add_tc_qdisc.assert_called_once_with(
            'device', parent=rtnl.TC_H_ROOT, kind='tbf', rate=10000 * 128,
            burst=burst, latency=70000, namespace=self.namespace)

    def test_add_tc_qdisc_tbf_missing_arguments(self):
        self.assertRaises(
            qos_exc.TcLibQdiscNeededArguments, tc_lib.add_tc_qdisc,
            'device', 'tbf', parent='root')

    def test_add_tc_qdisc_wrong_qdisc_type(self):
        self.assertRaises(qos_exc.TcLibQdiscTypeError, tc_lib.add_tc_qdisc,
                          mock.ANY, 'wrong_qdic_type_name')

    def test_list_tc_qdiscs_htb(self):
        qdisc = {'index': 2, 'handle': 327680, 'parent': 4294967295,
                 'attrs': (('TCA_KIND', 'htb'), )}
        with mock.patch.object(priv_tc_lib, 'list_tc_qdiscs') as \
                mock_list_tc_qdiscs:
            mock_list_tc_qdiscs.return_value = tuple([qdisc])
            qdiscs = tc_lib.list_tc_qdiscs('device',
                                           namespace=self.namespace)
        self.assertEqual(1, len(qdiscs))
        self.assertEqual('root', qdiscs[0]['parent'])
        self.assertEqual('5:0', qdiscs[0]['handle'])
        self.assertEqual('htb', qdiscs[0]['qdisc_type'])

    @mock.patch('pyroute2.netlink.rtnl.tcmsg.common.tick_in_usec', 15.625)
    def test_list_tc_qdiscs_tbf(self):
        tca_tbf_params = {'buffer': 9375000,
                          'rate': 320000,
                          'limit': 208000}
        qdisc = {'index': 2, 'handle': 327681, 'parent': 4294967295,
                 'attrs': (
                     ('TCA_KIND', 'tbf'),
                     ('TCA_OPTIONS', {'attrs': (
                         ('TCA_TBF_PARMS', tca_tbf_params), )}))
                 }
        with mock.patch.object(priv_tc_lib, 'list_tc_qdiscs') as \
                mock_list_tc_qdiscs:
            mock_list_tc_qdiscs.return_value = tuple([qdisc])
            qdiscs = tc_lib.list_tc_qdiscs('device',
                                           namespace=self.namespace)
        self.assertEqual(1, len(qdiscs))
        self.assertEqual('root', qdiscs[0]['parent'])
        self.assertEqual('5:1', qdiscs[0]['handle'])
        self.assertEqual('tbf', qdiscs[0]['qdisc_type'])
        self.assertEqual(2500, qdiscs[0]['max_kbps'])
        self.assertEqual(1500, qdiscs[0]['burst_kb'])
        self.assertEqual(50, qdiscs[0]['latency_ms'])

    def test__get_tbf_burst_value_when_burst_bigger_then_minimal(self):
        result = tc_lib._get_tbf_burst_value(BW_LIMIT, BURST, KERNEL_HZ_VALUE)
        self.assertEqual(BURST, result)

    def test__get_tbf_burst_value_when_burst_smaller_then_minimal(self):
        result = tc_lib._get_tbf_burst_value(BW_LIMIT, 0, KERNEL_HZ_VALUE)
        self.assertEqual(2, result)


class TcPolicyClassTestCase(base.BaseTestCase):

    def setUp(self):
        super(TcPolicyClassTestCase, self).setUp()
        self.mock_add_tc_policy_class = mock.patch.object(
            priv_tc_lib, 'add_tc_policy_class').start()
        self.mock_list_tc_policy_classes = mock.patch.object(
            priv_tc_lib, 'list_tc_policy_classes').start()
        self.namespace = 'namespace'

    def test_add_tc_policy_class(self):
        tc_lib.add_tc_policy_class(
            'device', 'root', '1:10', 'qdisc_type', min_kbps=1000,
            max_kbps=2000, burst_kb=1600, namespace=self.namespace)
        self.mock_add_tc_policy_class.assert_called_once_with(
            'device', rtnl.TC_H_ROOT, '1:10', 'qdisc_type', rate=1000 * 128,
            ceil=2000 * 128, burst=1600 * 128, namespace=self.namespace)

    @mock.patch('pyroute2.netlink.rtnl.tcmsg.common.tick_in_usec', 15.625)
    def test_list_tc_policy_classes(self):
        htb_params = {'buffer': 12500000, 'ceil': 256000, 'rate': 192000}
        self.mock_list_tc_policy_classes.return_value = tuple([
            {'index': 3, 'handle': 65537, 'parent': 4294967295,
             'attrs': (
                 ('TCA_KIND', 'htb'),
                 ('TCA_OPTIONS', {
                     'attrs': tuple([('TCA_HTB_PARMS', htb_params)])}))
             }])
        _class = tc_lib.list_tc_policy_class('device',
                                             namespace=self.namespace)[0]
        reference = {'device': 'device',
                     'index': 3,
                     'namespace': self.namespace,
                     'parent': 'root',
                     'classid': '1:1',
                     'qdisc_type': 'htb',
                     'min_kbps': 1500,
                     'max_kbps': 2000,
                     'burst_kb': 1200}
        self.assertEqual(reference, _class)


class TcFilterTestCase(base.BaseTestCase):

    def test__mac_to_pyroute2_keys(self):
        mac = '01:23:45:67:89:ab'
        offset = 10
        keys = tc_lib._mac_to_pyroute2_keys(mac, offset)
        high = {'value': 0x1234567,
                'mask': 0xffffffff,
                'offset': 10,
                'key': '0x1234567/0xffffffff+10'}
        low = {'value': 0x89ab0000,
               'mask': 0xffff0000,
               'offset': 14,
               'key': '0x89ab0000/0xffff0000+14'}
        self.assertEqual(high, keys[0])
        self.assertEqual(low, keys[1])
