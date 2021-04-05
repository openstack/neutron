# Copyright (c) 2012 OpenStack Foundation.
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

import os.path
import random
import re
import sys
from unittest import mock

import ddt
import eventlet
from eventlet import queue
import netaddr
from neutron_lib import constants
from oslo_log import log as logging
from osprofiler import profiler
import testscenarios
import testtools

from neutron.common import utils
from neutron.tests import base
from neutron.tests.unit import tests

load_tests = testscenarios.load_tests_apply_scenarios


class _PortRange(object):
    """A linked list of port ranges."""
    def __init__(self, base, prev_ref=None):
        self.base = base
        self.mask = 0xffff
        self.prev_ref = prev_ref

    @property
    def possible_mask_base(self):
        return self.base & (self.mask << 1)

    @property
    def can_merge(self):
        return (self.prev_ref and
                self.possible_mask_base == self.prev_ref.possible_mask_base and
                self.mask == self.prev_ref.mask)

    def shake(self):
        """Try to merge ranges created earlier.

        If previous number in a list can be merged with current item under
        common mask, it's merged. Then it continues to do the same with the
        rest of the list.
        """
        while self.can_merge:
            self.mask <<= 1
            self.base = self.prev_ref.base
            if self.prev_ref:
                self.prev_ref = self.prev_ref.prev_ref

    def __str__(self):
        return _hex_format(self.base, self.mask)

    def get_list(self):
        if self.prev_ref:
            return self.prev_ref.get_list() + [str(self)]
        return [str(self)]


_hex_str = lambda num: format(num, '#06x')


def _hex_format(port, mask):
    if mask != 0xffff:
        return "%s/%s" % (_hex_str(port), _hex_str(0xffff & mask))
    return _hex_str(port)


def _port_rule_masking(port_min, port_max):
    current = None
    for num in range(port_min, port_max + 1):
        port_range = _PortRange(num, prev_ref=current)
        port_range.shake()
        current = port_range
    return current.get_list()


class TestExceptionLogger(base.BaseTestCase):
    def test_normal_call(self):
        result = "Result"

        @utils.exception_logger()
        def func():
            return result

        self.assertEqual(result, func())

    def test_raise(self):
        result = "Result"

        @utils.exception_logger()
        def func():
            raise RuntimeError(result)

        self.assertRaises(RuntimeError, func)

    def test_spawn_normal(self):
        result = "Result"
        logger = mock.Mock()

        @utils.exception_logger(logger=logger)
        def func():
            return result

        gt = eventlet.spawn(func)
        self.assertEqual(result, gt.wait())
        self.assertFalse(logger.called)

    def test_spawn_raise(self):
        result = "Result"
        logger = mock.Mock()

        @utils.exception_logger(logger=logger)
        def func():
            raise RuntimeError(result)

        gt = eventlet.spawn(func)
        self.assertRaises(RuntimeError, gt.wait)
        self.assertTrue(logger.called)

    def test_pool_spawn_normal(self):
        logger = mock.Mock()
        calls = mock.Mock()

        @utils.exception_logger(logger=logger)
        def func(i):
            calls(i)

        pool = eventlet.GreenPool(4)
        for i in range(0, 4):
            pool.spawn(func, i)
        pool.waitall()

        calls.assert_has_calls([mock.call(0), mock.call(1),
                                mock.call(2), mock.call(3)],
                               any_order=True)
        self.assertFalse(logger.called)

    def test_pool_spawn_raise(self):
        logger = mock.Mock()
        calls = mock.Mock()

        @utils.exception_logger(logger=logger)
        def func(i):
            if i == 2:
                raise RuntimeError(2)
            calls(i)

        pool = eventlet.GreenPool(4)
        for i in range(0, 4):
            pool.spawn(func, i)
        pool.waitall()

        calls.assert_has_calls([mock.call(0), mock.call(1), mock.call(3)],
                               any_order=True)
        self.assertTrue(logger.called)


class TestDvrServices(base.BaseTestCase):

    def _test_is_dvr_serviced(self, device_owner, expected):
        self.assertEqual(expected, utils.is_dvr_serviced(device_owner))

    def test_is_dvr_serviced_with_lb_port(self):
        self._test_is_dvr_serviced(constants.DEVICE_OWNER_LOADBALANCER, True)

    def test_is_dvr_serviced_with_lbv2_port(self):
        self._test_is_dvr_serviced(constants.DEVICE_OWNER_LOADBALANCERV2, True)

    def test_is_dvr_serviced_with_dhcp_port(self):
        self._test_is_dvr_serviced(constants.DEVICE_OWNER_DHCP, True)

    def test_is_dvr_serviced_with_vm_port(self):
        self._test_is_dvr_serviced(constants.DEVICE_OWNER_COMPUTE_PREFIX, True)


class TestFipServices(base.BaseTestCase):

    def _test_is_fip_serviced(self, device_owner, expected):
        self.assertEqual(expected, utils.is_fip_serviced(device_owner))

    def test_is_fip_serviced_with_lb_port(self):
        self._test_is_fip_serviced(constants.DEVICE_OWNER_LOADBALANCER, True)

    def test_is_fip_serviced_with_lbv2_port(self):
        self._test_is_fip_serviced(constants.DEVICE_OWNER_LOADBALANCERV2, True)

    def test_is_fip_serviced_with_dhcp_port(self):
        self._test_is_fip_serviced(constants.DEVICE_OWNER_DHCP, False)

    def test_is_fip_serviced_with_vm_port(self):
        self._test_is_fip_serviced(constants.DEVICE_OWNER_COMPUTE_PREFIX, True)


class TestIpToCidr(base.BaseTestCase):
    def test_ip_to_cidr_ipv4_default(self):
        self.assertEqual('15.1.2.3/32', utils.ip_to_cidr('15.1.2.3'))

    def test_ip_to_cidr_ipv4_prefix(self):
        self.assertEqual('15.1.2.3/24', utils.ip_to_cidr('15.1.2.3', 24))

    def test_ip_to_cidr_ipv4_netaddr(self):
        ip_address = netaddr.IPAddress('15.1.2.3')
        self.assertEqual('15.1.2.3/32', utils.ip_to_cidr(ip_address))

    def test_ip_to_cidr_ipv4_bad_prefix(self):
        self.assertRaises(netaddr.core.AddrFormatError,
                          utils.ip_to_cidr, '15.1.2.3', 33)

    def test_ip_to_cidr_ipv6_default(self):
        self.assertEqual('::1/128', utils.ip_to_cidr('::1'))

    def test_ip_to_cidr_ipv6_prefix(self):
        self.assertEqual('::1/64', utils.ip_to_cidr('::1', 64))

    def test_ip_to_cidr_ipv6_bad_prefix(self):
        self.assertRaises(netaddr.core.AddrFormatError,
                          utils.ip_to_cidr, '2000::1', 129)


class TestCidrIsHost(base.BaseTestCase):
    def test_is_cidr_host_ipv4(self):
        self.assertTrue(utils.is_cidr_host('15.1.2.3/32'))

    def test_is_cidr_host_ipv4_not_cidr(self):
        self.assertRaises(ValueError,
                          utils.is_cidr_host,
                          '15.1.2.3')

    def test_is_cidr_host_ipv6(self):
        self.assertTrue(utils.is_cidr_host('2000::1/128'))

    def test_is_cidr_host_ipv6_netaddr(self):
        net = netaddr.IPNetwork("2000::1")
        self.assertTrue(utils.is_cidr_host(net))

    def test_is_cidr_host_ipv6_32(self):
        self.assertFalse(utils.is_cidr_host('2000::1/32'))

    def test_is_cidr_host_ipv6_not_cidr(self):
        self.assertRaises(ValueError,
                          utils.is_cidr_host,
                          '2000::1')

    def test_is_cidr_host_ipv6_not_cidr_netaddr(self):
        ip_address = netaddr.IPAddress("2000::3")
        self.assertRaises(ValueError,
                          utils.is_cidr_host,
                          ip_address)


class TestIpVersionFromInt(base.BaseTestCase):
    def test_ip_version_from_int_ipv4(self):
        self.assertEqual(constants.IPv4,
                         utils.ip_version_from_int(constants.IP_VERSION_4))

    def test_ip_version_from_int_ipv6(self):
        self.assertEqual(constants.IPv6,
                         utils.ip_version_from_int(constants.IP_VERSION_6))

    def test_ip_version_from_int_illegal_int(self):
        self.assertRaises(ValueError,
                          utils.ip_version_from_int,
                          8)


class TestIsVersionGreaterEqual(base.BaseTestCase):
    def test_is_version_greater_equal_greater(self):
        self.assertTrue(utils.is_version_greater_equal('1.6.2', '1.6.0'))

    def test_is_version_greater_equal_equal(self):
        self.assertTrue(utils.is_version_greater_equal('1.6.2', '1.6.2'))

    def test_is_version_greater_equal_less(self):
        self.assertFalse(utils.is_version_greater_equal('1.6.0', '1.6.2'))


class TestDelayedStringRenderer(base.BaseTestCase):
    def test_call_deferred_until_str(self):
        my_func = mock.MagicMock(return_value='Brie cheese!')
        delayed = utils.DelayedStringRenderer(my_func, 1, 2, key_arg=44)
        self.assertFalse(my_func.called)
        string = "Type: %s" % delayed
        my_func.assert_called_once_with(1, 2, key_arg=44)
        self.assertEqual("Type: Brie cheese!", string)

    def test_not_called_with_low_log_level(self):
        LOG = logging.getLogger(__name__)
        # make sure we return logging to previous level
        current_log_level = LOG.logger.getEffectiveLevel()
        self.addCleanup(LOG.logger.setLevel, current_log_level)

        my_func = mock.MagicMock()
        delayed = utils.DelayedStringRenderer(my_func)

        # set to warning so we shouldn't be logging debug messages
        LOG.logger.setLevel(logging.logging.WARNING)
        LOG.debug("Hello %s", delayed)
        self.assertFalse(my_func.called)

        # but it should be called with the debug level
        LOG.logger.setLevel(logging.logging.DEBUG)
        LOG.debug("Hello %s", delayed)
        self.assertTrue(my_func.called)


class TestPortRuleMasking(base.BaseTestCase):
    def test_port_rule_wrong_input(self):
        with testtools.ExpectedException(ValueError):
            utils.port_rule_masking(12, 5)

    def compare_port_ranges_results(self, port_min, port_max):
        observed = utils.port_rule_masking(port_min, port_max)
        expected = _port_rule_masking(port_min, port_max)
        self.assertItemsEqual(expected, observed)

    def test_port_rule_masking_random_ranges(self):
        # calling randint a bunch of times is really slow
        randports = sorted(random.sample(range(1, 65536), 2000))
        port_max = 0
        for i in randports:
            port_min = port_max
            port_max = i
            self.compare_port_ranges_results(port_min, port_max)

    def test_port_rule_masking_edge_cases(self):
        # (port_min, port_max) tuples
        TESTING_DATA = [
            (5, 12),
            (20, 130),
            (4501, 33057),
            (0, 65535),
            (22, 22),
            (5001, 5001),
            (0, 7),
            (8, 15),
            (1, 127),
        ]
        for port_min, port_max in TESTING_DATA:
            self.compare_port_ranges_results(port_min, port_max)


class TestExcDetails(base.BaseTestCase):

    def test_attach_exc_details(self):
        e = Exception()
        utils.attach_exc_details(e, 'details')
        self.assertEqual('details', utils.extract_exc_details(e))

    def test_attach_exc_details_with_interpolation(self):
        e = Exception()
        utils.attach_exc_details(e, 'details: %s', 'foo')
        self.assertEqual('details: foo', utils.extract_exc_details(e))

    def test_attach_exc_details_with_None_interpolation(self):
        e = Exception()
        utils.attach_exc_details(e, 'details: %s', None)
        self.assertEqual(
            'details: %s' % str(None), utils.extract_exc_details(e))

    def test_attach_exc_details_with_multiple_interpolation(self):
        e = Exception()
        utils.attach_exc_details(
            e, 'details: %s, %s', ('foo', 'bar'))
        self.assertEqual('details: foo, bar', utils.extract_exc_details(e))

    def test_attach_exc_details_with_dict_interpolation(self):
        e = Exception()
        utils.attach_exc_details(
            e, 'details: %(foo)s, %(bar)s', {'foo': 'foo', 'bar': 'bar'})
        self.assertEqual('details: foo, bar', utils.extract_exc_details(e))

    def test_extract_exc_details_no_details_attached(self):
        self.assertIsInstance(
            utils.extract_exc_details(Exception()), str)


@ddt.ddt
class ImportModulesRecursivelyTestCase(base.BaseTestCase):

    @ddt.data('/', r'\\')
    def test_recursion(self, separator):
        expected_modules = (
            'neutron.tests.unit.tests.example.dir.example_module',
            'neutron.tests.unit.tests.example.dir.subdir.example_module',
        )
        for module in expected_modules:
            sys.modules.pop(module, None)

        topdir = re.sub(r'[/\\]+', separator, os.path.dirname(tests.__file__))
        modules = utils.import_modules_recursively(topdir)
        for module in expected_modules:
            self.assertIn(module, modules)
            self.assertIn(module, sys.modules)


class TestThrottler(base.BaseTestCase):
    def test_throttler(self):
        threshold = 1
        orig_function = mock.Mock()
        # Add this magic name as it's required by functools
        orig_function.__name__ = 'mock_func'
        throttled_func = utils.throttler(threshold)(orig_function)

        throttled_func()

        sleep = utils.eventlet.sleep

        def sleep_mock(amount_to_sleep):
            sleep(amount_to_sleep)
            self.assertGreaterEqual(threshold, amount_to_sleep)

        with mock.patch.object(utils.eventlet, "sleep",
                               side_effect=sleep_mock):
            throttled_func()

        self.assertEqual(2, orig_function.call_count)

        lock_with_timer = throttled_func.__closure__[1].cell_contents
        timestamp = lock_with_timer.timestamp - threshold
        lock_with_timer.timestamp = timestamp

        throttled_func()

        self.assertEqual(3, orig_function.call_count)
        self.assertLess(timestamp, lock_with_timer.timestamp)

    def test_method_docstring_is_preserved(self):
        class Klass(object):
            @utils.throttler()
            def method(self):
                """Docstring"""

        self.assertEqual("Docstring", Klass.method.__doc__)

    def test_method_still_callable(self):
        class Klass(object):
            @utils.throttler()
            def method(self):
                pass

        obj = Klass()
        obj.method()


class BaseUnitConversionTest(object):

    def test_bytes_to_bits(self):
        test_values = [
            (0, 0),  # 0 bytes should be 0 bits
            (1, 8)   # 1 byte should be 8 bits
        ]
        for input_bytes, expected_bits in test_values:
            self.assertEqual(
                expected_bits, utils.bytes_to_bits(input_bytes)
            )


class TestSIUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = constants.SI_BASE

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
                utils.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestIECUnitConversions(BaseUnitConversionTest, base.BaseTestCase):

    base_unit = constants.IEC_BASE

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
                utils.bits_to_kilobits(input_bits, self.base_unit)
            )


class TestRpBandwidthValidator(base.BaseTestCase):

    def setUp(self):
        super(TestRpBandwidthValidator, self).setUp()
        self.device_name_set = {'ens4', 'ens7'}
        self.valid_rp_bandwidths = {
            'ens7': {'egress': 10000, 'ingress': 10000}
        }
        self.not_valid_rp_bandwidth = {
            'ens8': {'egress': 10000, 'ingress': 10000}
        }

    def test_validate_rp_bandwidth_with_device_names(self):
        try:
            utils.validate_rp_bandwidth(self.valid_rp_bandwidths,
                                        self.device_name_set)
        except ValueError:
            self.fail("validate_rp_bandwidth failed to validate %s" %
                      self.valid_rp_bandwidths)

        self.assertRaises(ValueError, utils.validate_rp_bandwidth,
                          self.not_valid_rp_bandwidth, self.device_name_set)


class SpawnWithOrWithoutProfilerTestCase(
        testscenarios.WithScenarios, base.BaseTestCase):

    scenarios = [
        ('spawn', {'spawn_variant': utils.spawn}),
        ('spawn_n', {'spawn_variant': utils.spawn_n}),
    ]

    def _compare_profilers_in_parent_and_in_child(self, init_profiler):

        q = queue.Queue()

        def is_profiler_initialized(where):
            # Instead of returning a single boolean add information so we can
            # identify which thread produced the result without depending on
            # queue order.
            return {where: bool(profiler.get())}

        def thread_with_no_leaked_profiler():
            if init_profiler:
                profiler.init(hmac_key='fake secret')

            self.spawn_variant(
                lambda: q.put(is_profiler_initialized('in-child')))
            q.put(is_profiler_initialized('in-parent'))

        # Make sure in parent we start with an uninitialized profiler by
        # eventlet.spawn()-ing a new thread. Otherwise the unit test runner
        # thread may leak an initialized profiler from one test to another.
        eventlet.spawn(thread_with_no_leaked_profiler)

        # In order to have some global protection against leaking initialized
        # profilers neutron.test.base.BaseTestCase.setup() also calls
        # addCleanup(profiler.clean)

        # Merge the results independently of queue order.
        results = {}
        results.update(q.get())
        results.update(q.get())

        self.assertEqual(
            {'in-parent': init_profiler,
             'in-child': init_profiler},
            results)

    def test_spawn_with_profiler(self):
        self._compare_profilers_in_parent_and_in_child(init_profiler=True)

    def test_spawn_without_profiler(self):
        self._compare_profilers_in_parent_and_in_child(init_profiler=False)


@utils.SingletonDecorator
class _TestSingletonClass(object):

    def __init__(self):
        self.variable = None


class SingletonDecoratorTestCase(base.BaseTestCase):

    def test_singleton_instance_class(self):
        instance_1 = _TestSingletonClass()
        instance_1.variable = 'value1'

        instance_2 = _TestSingletonClass()
        self.assertEqual(instance_1.__hash__(), instance_2.__hash__())
        self.assertEqual('value1', instance_2.variable)
