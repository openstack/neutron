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

import ddt
import eventlet
import mock
import netaddr
from neutron_lib import constants
from neutron_lib import exceptions as exc
from oslo_log import log as logging
import six
import testscenarios
import testtools

from neutron.common import constants as common_constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.plugins.common import utils as plugin_utils
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
        return (self.prev_ref
                and self.possible_mask_base == self.prev_ref.possible_mask_base
                and self.mask == self.prev_ref.mask)

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


class TestParseTunnelRangesMixin(object):
    TUN_MIN = None
    TUN_MAX = None
    TYPE = None
    _err_prefix = "Invalid network tunnel range: '%d:%d' - "
    _err_suffix = "%s is not a valid %s identifier."
    _err_range = "End of tunnel range is less than start of tunnel range."

    def _build_invalid_tunnel_range_msg(self, t_range_tuple, n):
        bad_id = t_range_tuple[n - 1]
        return (self._err_prefix % t_range_tuple) + (self._err_suffix
                                                 % (bad_id, self.TYPE))

    def _build_range_reversed_msg(self, t_range_tuple):
        return (self._err_prefix % t_range_tuple) + self._err_range

    def _verify_range(self, tunnel_range):
        return plugin_utils.verify_tunnel_range(tunnel_range, self.TYPE)

    def _check_range_valid_ranges(self, tunnel_range):
        self.assertIsNone(self._verify_range(tunnel_range))

    def _check_range_invalid_ranges(self, bad_range, which):
        expected_msg = self._build_invalid_tunnel_range_msg(bad_range, which)
        err = self.assertRaises(exc.NetworkTunnelRangeError,
                                self._verify_range, bad_range)
        self.assertEqual(expected_msg, str(err))

    def _check_range_reversed(self, bad_range):
        err = self.assertRaises(exc.NetworkTunnelRangeError,
                                self._verify_range, bad_range)
        expected_msg = self._build_range_reversed_msg(bad_range)
        self.assertEqual(expected_msg, str(err))

    def test_range_tunnel_id_valid(self):
            self._check_range_valid_ranges((self.TUN_MIN, self.TUN_MAX))

    def test_range_tunnel_id_invalid(self):
            self._check_range_invalid_ranges((-1, self.TUN_MAX), 1)
            self._check_range_invalid_ranges((self.TUN_MIN,
                                              self.TUN_MAX + 1), 2)
            self._check_range_invalid_ranges((self.TUN_MIN - 1,
                                              self.TUN_MAX + 1), 1)

    def test_range_tunnel_id_reversed(self):
            self._check_range_reversed((self.TUN_MAX, self.TUN_MIN))


class TestGreTunnelRangeVerifyValid(TestParseTunnelRangesMixin,
                                    base.BaseTestCase):
    TUN_MIN = constants.MIN_GRE_ID
    TUN_MAX = constants.MAX_GRE_ID
    TYPE = constants.TYPE_GRE


class TestVxlanTunnelRangeVerifyValid(TestParseTunnelRangesMixin,
                                      base.BaseTestCase):
    TUN_MIN = constants.MIN_VXLAN_VNI
    TUN_MAX = constants.MAX_VXLAN_VNI
    TYPE = constants.TYPE_VXLAN


class UtilTestParseVlanRanges(base.BaseTestCase):
    _err_prefix = "Invalid network VLAN range: '"
    _err_bad_count = "' - 'Need exactly two values for VLAN range'."
    _err_bad_vlan = "' - '%s is not a valid VLAN tag'."
    _err_range = "' - 'End of VLAN range is less than start of VLAN range'."

    def _range_err_bad_count(self, nv_range):
        return self._err_prefix + nv_range + self._err_bad_count

    def _range_invalid_vlan(self, nv_range, n):
        vlan = nv_range.split(':')[n]
        return self._err_prefix + nv_range + (self._err_bad_vlan % vlan)

    def _nrange_invalid_vlan(self, nv_range, n):
        vlan = nv_range.split(':')[n]
        v_range = ':'.join(nv_range.split(':')[1:])
        return self._err_prefix + v_range + (self._err_bad_vlan % vlan)

    def _vrange_invalid_vlan(self, v_range_tuple, n):
        vlan = v_range_tuple[n - 1]
        v_range_str = '%d:%d' % v_range_tuple
        return self._err_prefix + v_range_str + (self._err_bad_vlan % vlan)

    def _vrange_invalid(self, v_range_tuple):
        v_range_str = '%d:%d' % v_range_tuple
        return self._err_prefix + v_range_str + self._err_range


class TestVlanNetworkNameValid(base.BaseTestCase):
    def parse_vlan_ranges(self, vlan_range):
        return plugin_utils.parse_network_vlan_ranges(vlan_range)

    def test_validate_provider_phynet_name_mixed(self):
        self.assertRaises(n_exc.PhysicalNetworkNameError,
                          self.parse_vlan_ranges,
                          ['', ':23:30', 'physnet1',
                           'tenant_net:100:200'])

    def test_validate_provider_phynet_name_bad(self):
        self.assertRaises(n_exc.PhysicalNetworkNameError,
                          self.parse_vlan_ranges,
                          [':1:34'])


class TestVlanRangeVerifyValid(UtilTestParseVlanRanges):
    def verify_range(self, vlan_range):
        return plugin_utils.verify_vlan_range(vlan_range)

    def test_range_valid_ranges(self):
        self.assertIsNone(self.verify_range((1, 2)))
        self.assertIsNone(self.verify_range((1, 1999)))
        self.assertIsNone(self.verify_range((100, 100)))
        self.assertIsNone(self.verify_range((100, 200)))
        self.assertIsNone(self.verify_range((4001, 4094)))
        self.assertIsNone(self.verify_range((1, 4094)))

    def check_one_vlan_invalid(self, bad_range, which):
        expected_msg = self._vrange_invalid_vlan(bad_range, which)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.verify_range, bad_range)
        self.assertEqual(str(err), expected_msg)

    def test_range_first_vlan_invalid_negative(self):
        self.check_one_vlan_invalid((-1, 199), 1)

    def test_range_first_vlan_invalid_zero(self):
        self.check_one_vlan_invalid((0, 199), 1)

    def test_range_first_vlan_invalid_limit_plus_one(self):
        self.check_one_vlan_invalid((4095, 199), 1)

    def test_range_first_vlan_invalid_too_big(self):
        self.check_one_vlan_invalid((9999, 199), 1)

    def test_range_second_vlan_invalid_negative(self):
        self.check_one_vlan_invalid((299, -1), 2)

    def test_range_second_vlan_invalid_zero(self):
        self.check_one_vlan_invalid((299, 0), 2)

    def test_range_second_vlan_invalid_limit_plus_one(self):
        self.check_one_vlan_invalid((299, 4095), 2)

    def test_range_second_vlan_invalid_too_big(self):
        self.check_one_vlan_invalid((299, 9999), 2)

    def test_range_both_vlans_invalid_01(self):
        self.check_one_vlan_invalid((-1, 0), 1)

    def test_range_both_vlans_invalid_02(self):
        self.check_one_vlan_invalid((0, 4095), 1)

    def test_range_both_vlans_invalid_03(self):
        self.check_one_vlan_invalid((4095, 9999), 1)

    def test_range_both_vlans_invalid_04(self):
        self.check_one_vlan_invalid((9999, -1), 1)

    def test_range_reversed(self):
        bad_range = (95, 10)
        expected_msg = self._vrange_invalid(bad_range)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.verify_range, bad_range)
        self.assertEqual(str(err), expected_msg)


class TestParseOneVlanRange(UtilTestParseVlanRanges):
    def parse_one(self, cfg_entry):
        return plugin_utils.parse_network_vlan_range(cfg_entry)

    def test_parse_one_net_no_vlan_range(self):
        config_str = "net1"
        expected_networks = ("net1", None)
        self.assertEqual(expected_networks, self.parse_one(config_str))

    def test_parse_one_net_and_vlan_range(self):
        config_str = "net1:100:199"
        expected_networks = ("net1", (100, 199))
        self.assertEqual(expected_networks, self.parse_one(config_str))

    def test_parse_one_net_incomplete_range(self):
        config_str = "net1:100"
        expected_msg = self._range_err_bad_count(config_str)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))

    def test_parse_one_net_range_too_many(self):
        config_str = "net1:100:150:200"
        expected_msg = self._range_err_bad_count(config_str)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))

    def test_parse_one_net_vlan1_not_int(self):
        config_str = "net1:foo:199"
        expected_msg = self._range_invalid_vlan(config_str, 1)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))

    def test_parse_one_net_vlan2_not_int(self):
        config_str = "net1:100:bar"
        expected_msg = self._range_invalid_vlan(config_str, 2)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))

    def test_parse_one_net_and_max_range(self):
        config_str = "net1:1:4094"
        expected_networks = ("net1", (1, 4094))
        self.assertEqual(expected_networks, self.parse_one(config_str))

    def test_parse_one_net_range_bad_vlan1(self):
        config_str = "net1:9000:150"
        expected_msg = self._nrange_invalid_vlan(config_str, 1)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))

    def test_parse_one_net_range_bad_vlan2(self):
        config_str = "net1:4000:4999"
        expected_msg = self._nrange_invalid_vlan(config_str, 2)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(expected_msg, str(err))


class TestParseVlanRangeList(UtilTestParseVlanRanges):
    def parse_list(self, cfg_entries):
        return plugin_utils.parse_network_vlan_ranges(cfg_entries)

    def test_parse_list_one_net_no_vlan_range(self):
        config_list = ["net1"]
        expected_networks = {"net1": []}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_list_one_net_vlan_range(self):
        config_list = ["net1:100:199"]
        expected_networks = {"net1": [(100, 199)]}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_two_nets_no_vlan_range(self):
        config_list = ["net1",
                       "net2"]
        expected_networks = {"net1": [],
                             "net2": []}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_two_nets_range_and_no_range(self):
        config_list = ["net1:100:199",
                       "net2"]
        expected_networks = {"net1": [(100, 199)],
                             "net2": []}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_two_nets_no_range_and_range(self):
        config_list = ["net1",
                       "net2:200:299"]
        expected_networks = {"net1": [],
                             "net2": [(200, 299)]}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_two_nets_bad_vlan_range1(self):
        config_list = ["net1:100",
                       "net2:200:299"]
        expected_msg = self._range_err_bad_count(config_list[0])
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(expected_msg, str(err))

    def test_parse_two_nets_vlan_not_int2(self):
        config_list = ["net1:100:199",
                       "net2:200:0x200"]
        expected_msg = self._range_invalid_vlan(config_list[1], 2)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(expected_msg, str(err))

    def test_parse_two_nets_and_append_1_2(self):
        config_list = ["net1:100:199",
                       "net1:1000:1099",
                       "net2:200:299"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(expected_networks, self.parse_list(config_list))

    def test_parse_two_nets_and_append_1_3(self):
        config_list = ["net1:100:199",
                       "net2:200:299",
                       "net1:1000:1099"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(expected_networks, self.parse_list(config_list))


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
            else:
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
                         utils.ip_version_from_int(4))

    def test_ip_version_from_int_ipv6(self):
        self.assertEqual(constants.IPv6,
                         utils.ip_version_from_int(6))

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
        randports = sorted(random.sample(six.moves.range(1, 65536), 2000))
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


class TestAuthenticEUI(base.BaseTestCase):

    def test_retains_original_format(self):
        for mac_str in ('FA-16-3E-73-A2-E9', 'fa:16:3e:73:a2:e9'):
            self.assertEqual(mac_str, str(utils.AuthenticEUI(mac_str)))

    def test_invalid_values(self):
        for mac in ('XXXX', 'ypp', 'g3:vvv'):
            with testtools.ExpectedException(netaddr.core.AddrFormatError):
                utils.AuthenticEUI(mac)


class TestAuthenticIPNetwork(base.BaseTestCase):

    def test_retains_original_format(self):
        for addr_str in ('10.0.0.0/24', '10.0.0.10/32', '100.0.0.1'):
            self.assertEqual(addr_str, str(utils.AuthenticIPNetwork(addr_str)))

    def test_invalid_values(self):
        for addr in ('XXXX', 'ypp', 'g3:vvv'):
            with testtools.ExpectedException(netaddr.core.AddrFormatError):
                utils.AuthenticIPNetwork(addr)


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
            utils.extract_exc_details(Exception()), six.text_type)


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
            self.assertTrue(threshold > amount_to_sleep)

        with mock.patch.object(utils.eventlet, "sleep",
                               side_effect=sleep_mock):
            throttled_func()

        self.assertEqual(2, orig_function.call_count)

        lock_with_timer = six.get_function_closure(
            throttled_func)[1].cell_contents
        timestamp = lock_with_timer.timestamp - threshold
        lock_with_timer.timestamp = timestamp

        throttled_func()

        self.assertEqual(3, orig_function.call_count)
        self.assertTrue(timestamp < lock_with_timer.timestamp)

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

    base_unit = common_constants.SI_BASE

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

    base_unit = common_constants.IEC_BASE

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
