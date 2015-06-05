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

import eventlet
import mock
import netaddr
import testtools

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as plugin_utils
from neutron.tests import base

from oslo_log import log as logging


class TestParseMappings(base.BaseTestCase):
    def parse(self, mapping_list, unique_values=True):
        return utils.parse_mappings(mapping_list, unique_values)

    def test_parse_mappings_fails_for_missing_separator(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key'])

    def test_parse_mappings_fails_for_missing_key(self):
        with testtools.ExpectedException(ValueError):
            self.parse([':val'])

    def test_parse_mappings_fails_for_missing_value(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:'])

    def test_parse_mappings_fails_for_extra_separator(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:val:junk'])

    def test_parse_mappings_fails_for_duplicate_key(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:val1', 'key:val2'])

    def test_parse_mappings_fails_for_duplicate_value(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key1:val', 'key2:val'])

    def test_parse_mappings_succeeds_for_one_mapping(self):
        self.assertEqual(self.parse(['key:val']), {'key': 'val'})

    def test_parse_mappings_succeeds_for_n_mappings(self):
        self.assertEqual(self.parse(['key1:val1', 'key2:val2']),
                         {'key1': 'val1', 'key2': 'val2'})

    def test_parse_mappings_succeeds_for_duplicate_value(self):
        self.assertEqual(self.parse(['key1:val', 'key2:val'], False),
                         {'key1': 'val', 'key2': 'val'})

    def test_parse_mappings_succeeds_for_no_mappings(self):
        self.assertEqual(self.parse(['']), {})


class TestParseTunnelRangesMixin(object):
    TUN_MIN = None
    TUN_MAX = None
    TYPE = None
    _err_prefix = "Invalid network Tunnel range: '%d:%d' - "
    _err_suffix = "%s is not a valid %s identifier"
    _err_range = "End of tunnel range is less than start of tunnel range"

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
        err = self.assertRaises(n_exc.NetworkTunnelRangeError,
                                self._verify_range, bad_range)
        self.assertEqual(expected_msg, str(err))

    def _check_range_reversed(self, bad_range):
        err = self.assertRaises(n_exc.NetworkTunnelRangeError,
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
    TUN_MIN = p_const.MIN_GRE_ID
    TUN_MAX = p_const.MAX_GRE_ID
    TYPE = p_const.TYPE_GRE


class TestVxlanTunnelRangeVerifyValid(TestParseTunnelRangesMixin,
                                      base.BaseTestCase):
    TUN_MIN = p_const.MIN_VXLAN_VNI
    TUN_MAX = p_const.MAX_VXLAN_VNI
    TYPE = p_const.TYPE_VXLAN


class UtilTestParseVlanRanges(base.BaseTestCase):
    _err_prefix = "Invalid network VLAN range: '"
    _err_too_few = "' - 'need more than 2 values to unpack'"
    _err_too_many = "' - 'too many values to unpack'"
    _err_not_int = "' - 'invalid literal for int() with base 10: '%s''"
    _err_bad_vlan = "' - '%s is not a valid VLAN tag'"
    _err_range = "' - 'End of VLAN range is less than start of VLAN range'"

    def _range_too_few_err(self, nv_range):
        return self._err_prefix + nv_range + self._err_too_few

    def _range_too_many_err(self, nv_range):
        return self._err_prefix + nv_range + self._err_too_many

    def _vlan_not_int_err(self, nv_range, vlan):
        return self._err_prefix + nv_range + (self._err_not_int % vlan)

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
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_and_vlan_range(self):
        config_str = "net1:100:199"
        expected_networks = ("net1", (100, 199))
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_incomplete_range(self):
        config_str = "net1:100"
        expected_msg = self._range_too_few_err(config_str)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_range_too_many(self):
        config_str = "net1:100:150:200"
        expected_msg = self._range_too_many_err(config_str)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_vlan1_not_int(self):
        config_str = "net1:foo:199"
        expected_msg = self._vlan_not_int_err(config_str, 'foo')
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_vlan2_not_int(self):
        config_str = "net1:100:bar"
        expected_msg = self._vlan_not_int_err(config_str, 'bar')
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_and_max_range(self):
        config_str = "net1:1:4094"
        expected_networks = ("net1", (1, 4094))
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_range_bad_vlan1(self):
        config_str = "net1:9000:150"
        expected_msg = self._nrange_invalid_vlan(config_str, 1)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_range_bad_vlan2(self):
        config_str = "net1:4000:4999"
        expected_msg = self._nrange_invalid_vlan(config_str, 2)
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)


class TestParseVlanRangeList(UtilTestParseVlanRanges):
    def parse_list(self, cfg_entries):
        return plugin_utils.parse_network_vlan_ranges(cfg_entries)

    def test_parse_list_one_net_no_vlan_range(self):
        config_list = ["net1"]
        expected_networks = {"net1": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_list_one_net_vlan_range(self):
        config_list = ["net1:100:199"]
        expected_networks = {"net1": [(100, 199)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_no_vlan_range(self):
        config_list = ["net1",
                       "net2"]
        expected_networks = {"net1": [],
                             "net2": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_range_and_no_range(self):
        config_list = ["net1:100:199",
                       "net2"]
        expected_networks = {"net1": [(100, 199)],
                             "net2": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_no_range_and_range(self):
        config_list = ["net1",
                       "net2:200:299"]
        expected_networks = {"net1": [],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_bad_vlan_range1(self):
        config_list = ["net1:100",
                       "net2:200:299"]
        expected_msg = self._range_too_few_err(config_list[0])
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(str(err), expected_msg)

    def test_parse_two_nets_vlan_not_int2(self):
        config_list = ["net1:100:199",
                       "net2:200:0x200"]
        expected_msg = self._vlan_not_int_err(config_list[1], '0x200')
        err = self.assertRaises(n_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(str(err), expected_msg)

    def test_parse_two_nets_and_append_1_2(self):
        config_list = ["net1:100:199",
                       "net1:1000:1099",
                       "net2:200:299"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_and_append_1_3(self):
        config_list = ["net1:100:199",
                       "net2:200:299",
                       "net1:1000:1099"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)


class TestDictUtils(base.BaseTestCase):
    def test_dict2str(self):
        dic = {"key1": "value1", "key2": "value2", "key3": "value3"}
        expected = "key1=value1,key2=value2,key3=value3"
        self.assertEqual(utils.dict2str(dic), expected)

    def test_str2dict(self):
        string = "key1=value1,key2=value2,key3=value3"
        expected = {"key1": "value1", "key2": "value2", "key3": "value3"}
        self.assertEqual(utils.str2dict(string), expected)

    def test_dict_str_conversion(self):
        dic = {"key1": "value1", "key2": "value2"}
        self.assertEqual(utils.str2dict(utils.dict2str(dic)), dic)

    def test_diff_list_of_dict(self):
        old_list = [{"key1": "value1"},
                    {"key2": "value2"},
                    {"key3": "value3"}]
        new_list = [{"key1": "value1"},
                    {"key2": "value2"},
                    {"key4": "value4"}]
        added, removed = utils.diff_list_of_dict(old_list, new_list)
        self.assertEqual(added, [dict(key4="value4")])
        self.assertEqual(removed, [dict(key3="value3")])


class _CachingDecorator(object):
    def __init__(self):
        self.func_retval = 'bar'
        self._cache = mock.Mock()

    @utils.cache_method_results
    def func(self, *args, **kwargs):
        return self.func_retval


class TestCachingDecorator(base.BaseTestCase):
    def setUp(self):
        super(TestCachingDecorator, self).setUp()
        self.decor = _CachingDecorator()
        self.func_name = '%(module)s._CachingDecorator.func' % {
            'module': self.__module__
        }
        self.not_cached = self.decor.func.func.im_self._not_cached

    def test_cache_miss(self):
        expected_key = (self.func_name, 1, 2, ('foo', 'bar'))
        args = (1, 2)
        kwargs = {'foo': 'bar'}
        self.decor._cache.get.return_value = self.not_cached
        retval = self.decor.func(*args, **kwargs)
        self.decor._cache.set.assert_called_once_with(
            expected_key, self.decor.func_retval, None)
        self.assertEqual(self.decor.func_retval, retval)

    def test_cache_hit(self):
        expected_key = (self.func_name, 1, 2, ('foo', 'bar'))
        args = (1, 2)
        kwargs = {'foo': 'bar'}
        retval = self.decor.func(*args, **kwargs)
        self.assertFalse(self.decor._cache.set.called)
        self.assertEqual(self.decor._cache.get.return_value, retval)
        self.decor._cache.get.assert_called_once_with(expected_key,
                                                      self.not_cached)

    def test_get_unhashable(self):
        expected_key = (self.func_name, [1], 2)
        self.decor._cache.get.side_effect = TypeError
        retval = self.decor.func([1], 2)
        self.assertFalse(self.decor._cache.set.called)
        self.assertEqual(self.decor.func_retval, retval)
        self.decor._cache.get.assert_called_once_with(expected_key,
                                                      self.not_cached)

    def test_missing_cache(self):
        delattr(self.decor, '_cache')
        self.assertRaises(NotImplementedError, self.decor.func, (1, 2))

    def test_no_cache(self):
        self.decor._cache = False
        retval = self.decor.func((1, 2))
        self.assertEqual(self.decor.func_retval, retval)


class TestDict2Tuples(base.BaseTestCase):
    def test_dict(self):
        input_dict = {'foo': 'bar', 42: 'baz', 'aaa': 'zzz'}
        expected = ((42, 'baz'), ('aaa', 'zzz'), ('foo', 'bar'))
        output_tuple = utils.dict2tuple(input_dict)
        self.assertEqual(expected, output_tuple)


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

    def test_is_dvr_serviced_with_dhcp_port(self):
        self._test_is_dvr_serviced(constants.DEVICE_OWNER_DHCP, True)

    def test_is_dvr_serviced_with_vm_port(self):
        self._test_is_dvr_serviced('compute:', True)


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
        self.assertEqual(utils.ip_version_from_int(4),
                         constants.IPv4)

    def test_ip_version_from_int_ipv6(self):
        self.assertEqual(utils.ip_version_from_int(6),
                         constants.IPv6)

    def test_ip_version_from_int_illegal_int(self):
        self.assertRaises(ValueError,
                          utils.ip_version_from_int,
                          8)


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
