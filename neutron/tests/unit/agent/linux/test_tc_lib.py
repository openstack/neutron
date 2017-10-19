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
from neutron_lib.services.qos import constants as qos_consts

from neutron.agent.linux import tc_lib
from neutron.common import constants
from neutron.common import utils
from neutron.tests import base

DEVICE_NAME = "tap_device"
KERNEL_HZ_VALUE = 1000
BW_LIMIT = 2000  # [kbps]
BURST = 100  # [kbit]
LATENCY = 50  # [ms]

TC_QDISC_OUTPUT = (
    'qdisc tbf 8011: root refcnt 2 rate %(bw)skbit burst %(burst)skbit '
    'lat 50.0ms \n') % {'bw': BW_LIMIT, 'burst': BURST}

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
        self.bw_limit = "%s%s" % (BW_LIMIT, tc_lib.BW_LIMIT_UNIT)
        self.burst = "%s%s" % (BURST, tc_lib.BURST_UNIT)
        self.latency = "%s%s" % (LATENCY, tc_lib.LATENCY_UNIT)
        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

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
        self.execute.return_value = TC_FILTERS_OUTPUT
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst_limit)

    def test_get_filters_bw_limits_when_output_not_match(self):
        output = (
            "Some different "
            "output from command:"
            "tc filters show dev XXX parent ffff:"
        )
        self.execute.return_value = output
        bw_limit, burst_limit = self.tc.get_filters_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_filters_bw_limits_when_wrong_units(self):
        output = TC_FILTERS_OUTPUT.replace("kbit", "Xbit")
        self.execute.return_value = output
        self.assertRaises(tc_lib.InvalidUnit, self.tc.get_filters_bw_limits)

    def test_get_tbf_bw_limits(self):
        self.execute.return_value = TC_QDISC_OUTPUT
        bw_limit, burst_limit = self.tc.get_tbf_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst_limit)

    def test_get_tbf_bw_limits_when_wrong_qdisc(self):
        output = TC_QDISC_OUTPUT.replace("tbf", "different_qdisc")
        self.execute.return_value = output
        bw_limit, burst_limit = self.tc.get_tbf_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst_limit)

    def test_get_tbf_bw_limits_when_wrong_units(self):
        output = TC_QDISC_OUTPUT.replace("kbit", "Xbit")
        self.execute.return_value = output
        self.assertRaises(tc_lib.InvalidUnit, self.tc.get_tbf_bw_limits)

    def test_set_tbf_bw_limit(self):
        self.tc.set_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "replace", "dev", DEVICE_NAME,
             "root", "tbf", "rate", self.bw_limit,
             "latency", self.latency,
             "burst", self.burst],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test_update_filters_bw_limit(self):
        self.tc.update_filters_bw_limit(BW_LIMIT, BURST)
        self.execute.assert_has_calls([
            mock.call(
                ["tc", "qdisc", "del", "dev", DEVICE_NAME, "ingress"],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=[1, 2]
            ),
            mock.call(
                ['tc', 'qdisc', 'add', 'dev', DEVICE_NAME, "ingress",
                 "handle", tc_lib.INGRESS_QDISC_ID],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=None
            ),
            mock.call(
                ['tc', 'filter', 'add', 'dev', DEVICE_NAME,
                 'parent', tc_lib.INGRESS_QDISC_ID, 'protocol', 'all',
                 'prio', '49', 'basic', 'police',
                 'rate', self.bw_limit,
                 'burst', self.burst,
                 'mtu', tc_lib.MAX_MTU_VALUE,
                 'drop'],
                run_as_root=True,
                check_exit_code=True,
                log_fail_as_error=True,
                extra_ok_codes=None
            )]
        )

    def test_update_tbf_bw_limit(self):
        self.tc.update_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "replace", "dev", DEVICE_NAME,
             "root", "tbf", "rate", self.bw_limit,
             "latency", self.latency,
             "burst", self.burst],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=None
        )

    def test_delete_filters_bw_limit(self):
        self.tc.delete_filters_bw_limit()
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "del", "dev", DEVICE_NAME, "ingress"],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=[1, 2]
        )

    def test_delete_tbf_bw_limit(self):
        self.tc.delete_tbf_bw_limit()
        self.execute.assert_called_once_with(
            ["tc", "qdisc", "del", "dev", DEVICE_NAME, "root"],
            run_as_root=True,
            check_exit_code=True,
            log_fail_as_error=True,
            extra_ok_codes=[1, 2]
        )

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

    def test__get_tbf_burst_value_when_burst_bigger_then_minimal(self):
        result = self.tc._get_tbf_burst_value(BW_LIMIT, BURST)
        self.assertEqual(BURST, result)

    def test__get_tbf_burst_value_when_burst_smaller_then_minimal(self):
        result = self.tc._get_tbf_burst_value(BW_LIMIT, 0)
        self.assertEqual(2, result)
