# Copyright (c) 2014 OpenStack Foundation, all rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
import testtools
from testtools import matchers

from neutron.objects import network_segment_range as obj_network_segment_range
from neutron.plugins.ml2.drivers import type_tunnel

TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"
TUNNEL_IPV6_ONE = "2001:db8:1::10"
HOST_ONE = 'fake_host_one'
HOST_TWO = 'fake_host_two'
TUN_MIN = 100
TUN_MAX = 109
RAW_TUNNEL_RANGES = [str(TUN_MIN) + ':' + str(TUN_MAX)]
TUNNEL_RANGES = [(TUN_MIN, TUN_MAX)]
UPDATED_TUNNEL_RANGES = [(TUN_MIN + 5, TUN_MAX + 5)]
SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class TunnelTypeTestMixin(object):
    DRIVER_CLASS = None
    TYPE = None

    def setUp(self):
        super(TunnelTypeTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()
        self.driver.tunnel_ranges = TUNNEL_RANGES
        self.driver.sync_allocations()
        self.context = context.Context()

    def test_tunnel_type(self):
        self.assertEqual(self.TYPE, self.driver.get_type())

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: 'phys_net',
                   api.SEGMENTATION_ID: None}

        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.validate_provider_segment(segment)

        segment[api.PHYSICAL_NETWORK] = None
        self.driver.validate_provider_segment(segment)

        segment[api.SEGMENTATION_ID] = 1
        self.driver.validate_provider_segment(segment)

    def test_sync_tunnel_allocations(self):
        self.assertIsNone(
            self.driver.get_allocation(self.context, (TUN_MIN - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MIN)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MIN + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MAX - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MAX)).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.context, (TUN_MAX + 1)))

        self.driver.tunnel_ranges = UPDATED_TUNNEL_RANGES
        self.driver.sync_allocations()

        self.assertIsNone(
            self.driver.get_allocation(self.context, (TUN_MIN + 5 - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MIN + 5)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context,
                                       (TUN_MIN + 5 + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context,
                                       (TUN_MAX + 5 - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context, (TUN_MAX + 5)).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.context, (TUN_MAX + 5 + 1)))

    def _test_sync_allocations_and_allocated(self, tunnel_id):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: tunnel_id}
        self.driver.reserve_provider_segment(self.context, segment)

        self.driver.tunnel_ranges = UPDATED_TUNNEL_RANGES
        self.driver.sync_allocations()

        self.assertTrue(
            self.driver.get_allocation(self.context, tunnel_id).allocated)

    def test_sync_allocations_and_allocated_in_initial_range(self):
        self._test_sync_allocations_and_allocated(TUN_MIN + 2)

    def test_sync_allocations_and_allocated_in_final_range(self):
        self._test_sync_allocations_and_allocated(TUN_MAX + 2)

    def test_sync_allocations_no_op(self):

        def verify_no_chunk(iterable, chunk_size):
            # no segment removed/added
            self.assertEqual(0, len(list(iterable)))
            return []
        with mock.patch.object(
                type_tunnel, 'chunks', side_effect=verify_no_chunk) as chunks:
            self.driver.sync_allocations()
            self.assertEqual(2, len(chunks.mock_calls))

    def test_partial_segment_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: None}
        self.assertTrue(self.driver.is_partial_segment(segment))

    def test_specific_segment_is_not_partial_segment(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 101}
        self.assertFalse(self.driver.is_partial_segment(segment))

    def test_reserve_provider_segment_full_specs(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 101}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self.driver.get_allocation(self.context,
                                           observed[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        with testtools.ExpectedException(exc.TunnelIdInUse):
            self.driver.reserve_provider_segment(self.context, segment)

        self.driver.release_segment(self.context, segment)
        alloc = self.driver.get_allocation(self.context,
                                           observed[api.SEGMENTATION_ID])
        self.assertFalse(alloc.allocated)

        segment[api.SEGMENTATION_ID] = 1000
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self.driver.get_allocation(self.context,
                                           observed[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        self.driver.release_segment(self.context, segment)
        alloc = self.driver.get_allocation(self.context,
                                           observed[api.SEGMENTATION_ID])
        self.assertIsNone(alloc)

    def test_reserve_provider_segment(self):
        tunnel_ids = set()
        specs = {api.NETWORK_TYPE: self.TYPE,
                 api.PHYSICAL_NETWORK: 'None',
                 api.SEGMENTATION_ID: None}

        for x in range(TUN_MIN, TUN_MAX + 1):
            segment = self.driver.reserve_provider_segment(self.context,
                                                           specs)
            self.assertEqual(self.TYPE, segment[api.NETWORK_TYPE])
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.GreaterThan(TUN_MIN - 1))
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.LessThan(TUN_MAX + 1))
            tunnel_ids.add(segment[api.SEGMENTATION_ID])

        with testtools.ExpectedException(exc.NoNetworkAvailable):
            segment = self.driver.reserve_provider_segment(self.context,
                                                           specs)

        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: 'None',
                   api.SEGMENTATION_ID: tunnel_ids.pop()}
        self.driver.release_segment(self.context, segment)
        segment = self.driver.reserve_provider_segment(self.context, specs)
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.GreaterThan(TUN_MIN - 1))
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.LessThan(TUN_MAX + 1))
        tunnel_ids.add(segment[api.SEGMENTATION_ID])

        for tunnel_id in tunnel_ids:
            segment[api.SEGMENTATION_ID] = tunnel_id
            self.driver.release_segment(self.context, segment)

    def test_allocate_tenant_segment(self):
        tunnel_ids = set()
        for x in range(TUN_MIN, TUN_MAX + 1):
            segment = self.driver.allocate_tenant_segment(self.context)
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.GreaterThan(TUN_MIN - 1))
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.LessThan(TUN_MAX + 1))
            tunnel_ids.add(segment[api.SEGMENTATION_ID])

        segment = self.driver.allocate_tenant_segment(self.context)
        self.assertIsNone(segment)

        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: 'None',
                   api.SEGMENTATION_ID: tunnel_ids.pop()}
        self.driver.release_segment(self.context, segment)
        segment = self.driver.allocate_tenant_segment(self.context)
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.GreaterThan(TUN_MIN - 1))
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.LessThan(TUN_MAX + 1))
        tunnel_ids.add(segment[api.SEGMENTATION_ID])

        for tunnel_id in tunnel_ids:
            segment[api.SEGMENTATION_ID] = tunnel_id
            self.driver.release_segment(self.context, segment)

    def add_endpoint(self, ip=TUNNEL_IP_ONE, host=HOST_ONE):
        return self.driver.add_endpoint(ip, host)

    def test_add_endpoint(self):
        endpoint = self.add_endpoint()
        self.assertEqual(TUNNEL_IP_ONE, endpoint.ip_address)
        self.assertEqual(HOST_ONE, endpoint.host)
        return endpoint

    def test_add_endpoint_for_existing_tunnel_ip(self):
        self.add_endpoint()

        with mock.patch.object(type_tunnel.LOG, 'warning') as log_warn:
            self.add_endpoint()
            log_warn.assert_called_once_with(mock.ANY, TUNNEL_IP_ONE)

    def test_get_endpoint_by_host(self):
        self.add_endpoint()

        host_endpoint = self.driver.get_endpoint_by_host(HOST_ONE)
        self.assertEqual(TUNNEL_IP_ONE, host_endpoint.ip_address)
        return host_endpoint

    def test_get_endpoint_by_host_for_not_existing_host(self):
        ip_endpoint = self.driver.get_endpoint_by_host(HOST_TWO)
        self.assertIsNone(ip_endpoint)

    def test_get_endpoint_by_ip(self):
        self.add_endpoint()

        ip_endpoint = self.driver.get_endpoint_by_ip(TUNNEL_IP_ONE)
        self.assertEqual(HOST_ONE, ip_endpoint.host)
        return ip_endpoint

    def test_get_endpoint_by_ip_for_not_existing_tunnel_ip(self):
        ip_endpoint = self.driver.get_endpoint_by_ip(TUNNEL_IP_TWO)
        self.assertIsNone(ip_endpoint)

    def test_delete_endpoint(self):
        self.add_endpoint()

        self.assertIsNone(self.driver.delete_endpoint(TUNNEL_IP_ONE))
        # Get all the endpoints and verify its empty
        endpoints = self.driver.get_endpoints()
        self.assertNotIn(TUNNEL_IP_ONE, endpoints)


class TunnelTypeMultiRangeTestMixin(object):
    DRIVER_CLASS = None

    TUN_MIN0 = 100
    TUN_MAX0 = 101
    TUN_MIN1 = 200
    TUN_MAX1 = 201
    TUNNEL_MULTI_RANGES = [(TUN_MIN0, TUN_MAX0), (TUN_MIN1, TUN_MAX1)]

    def setUp(self):
        super(TunnelTypeMultiRangeTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()
        self.driver.tunnel_ranges = self.TUNNEL_MULTI_RANGES
        self.driver.sync_allocations()
        self.context = context.Context()

    def test_release_segment(self):
        segments = [self.driver.allocate_tenant_segment(self.context)
                    for i in range(4)]

        # Release them in random order. No special meaning.
        for i in (0, 2, 1, 3):
            self.driver.release_segment(self.context, segments[i])

        for key in (self.TUN_MIN0, self.TUN_MAX0,
                    self.TUN_MIN1, self.TUN_MAX1):
            alloc = self.driver.get_allocation(self.context, key)
            self.assertFalse(alloc.allocated)


class TunnelRpcCallbackTestMixin(object):

    DRIVER_CLASS = None
    TYPE = None

    def setUp(self):
        super(TunnelRpcCallbackTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()

    def _test_tunnel_sync(self, kwargs, delete_tunnel=False):
        with mock.patch.object(self.notifier,
                               'tunnel_update') as tunnel_update,\
                mock.patch.object(self.notifier,
                                  'tunnel_delete') as tunnel_delete:
            details = self.callbacks.tunnel_sync('fake_context', **kwargs)
            tunnels = details['tunnels']
            for tunnel in tunnels:
                self.assertEqual(kwargs['tunnel_ip'], tunnel['ip_address'])
                self.assertEqual(kwargs['host'], tunnel['host'])
            self.assertTrue(tunnel_update.called)
            if delete_tunnel:
                self.assertTrue(tunnel_delete.called)
            else:
                self.assertFalse(tunnel_delete.called)

    def _test_tunnel_sync_raises(self, kwargs):
        with mock.patch.object(self.notifier,
                               'tunnel_update') as tunnel_update,\
                mock.patch.object(self.notifier,
                                  'tunnel_delete') as tunnel_delete:
            self.assertRaises(exc.InvalidInput,
                              self.callbacks.tunnel_sync,
                              'fake_context', **kwargs)
            self.assertFalse(tunnel_update.called)
            self.assertFalse(tunnel_delete.called)

    def test_tunnel_sync_called_without_host_passed(self):
        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': None}
        self._test_tunnel_sync(kwargs)

    def test_tunnel_sync_called_with_host_passed_for_existing_tunnel_ip(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, None)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync(kwargs)

    def test_tunnel_sync_called_with_host_passed(self):
        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync(kwargs)

    def test_tunnel_sync_called_with_host_passed_ipv6(self):
        cfg.CONF.set_override('overlay_ip_version', p_const.IP_VERSION_6,
                              group='ml2')
        kwargs = {'tunnel_ip': TUNNEL_IPV6_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync(kwargs)

    def test_tunnel_sync_called_for_existing_endpoint(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, HOST_ONE)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync(kwargs)

    def test_tunnel_sync_called_for_existing_host_with_tunnel_ip_changed(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, HOST_ONE)

        kwargs = {'tunnel_ip': TUNNEL_IP_TWO, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync(kwargs, True)

    def test_tunnel_sync_called_with_used_tunnel_ip_host_roaming(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, HOST_ONE)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_TWO}
        self._test_tunnel_sync(kwargs, False)

    def test_tunnel_sync_called_with_used_tunnel_ip_roaming_case_two(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, None)
        self.driver.add_endpoint(TUNNEL_IP_TWO, HOST_TWO)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_TWO}
        self._test_tunnel_sync(kwargs, False)

    def test_tunnel_sync_called_without_tunnel_ip(self):
        kwargs = {'tunnel_type': self.TYPE, 'host': None}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_without_tunnel_type(self):
        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'host': None}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_with_tunnel_overlay_mismatch(self):
        cfg.CONF.set_override('overlay_ip_version', p_const.IP_VERSION_6,
                              group='ml2')
        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_with_tunnel_overlay_mismatch_ipv6(self):
        cfg.CONF.set_override('overlay_ip_version', p_const.IP_VERSION_4,
                              group='ml2')
        kwargs = {'tunnel_ip': TUNNEL_IPV6_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_ONE}
        self._test_tunnel_sync_raises(kwargs)


class TunnelTypeMTUTestMixin(object):

    DRIVER_CLASS = None
    TYPE = None
    ENCAP_OVERHEAD = 0

    def setUp(self):
        super(TunnelTypeMTUTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()

    def _test_get_mtu(self, ip_version):
        cfg.CONF.set_override('overlay_ip_version', ip_version,
                              group='ml2')
        ip_header_length = p_const.IP_HEADER_LENGTH[ip_version]

        cfg.CONF.set_override('global_physnet_mtu', 1500)
        cfg.CONF.set_override('path_mtu', 1475, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1475 - self.ENCAP_OVERHEAD - ip_header_length,
                         self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 1450)
        cfg.CONF.set_override('path_mtu', 1475, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1400, 'physnet2': 1425}
        self.assertEqual(1450 - self.ENCAP_OVERHEAD - ip_header_length,
                         self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 0)
        cfg.CONF.set_override('path_mtu', 1450, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1425, 'physnet2': 1400}
        self.assertEqual(1450 - self.ENCAP_OVERHEAD - ip_header_length,
                         self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 0)
        cfg.CONF.set_override('path_mtu', 0, group='ml2')
        self.driver.physnet_mtus = {}
        self.assertEqual(0, self.driver.get_mtu('physnet1'))

    def test_get_mtu_ipv4(self):
        self._test_get_mtu(4)

    def test_get_mtu_ipv6(self):
        self._test_get_mtu(6)


class TunnelTypeNetworkSegmentRangeTestMixin(object):

    DRIVER_CLASS = None

    def setUp(self):
        super(TunnelTypeNetworkSegmentRangeTestMixin, self).setUp()
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        self.context = context.Context()
        self.driver = self.DRIVER_CLASS()

    def test__populate_new_default_network_segment_ranges(self):
        # _populate_new_default_network_segment_ranges will be called when
        # the type driver initializes with `network_segment_range` loaded as
        # one of the `service_plugins`
        self.driver._initialize(RAW_TUNNEL_RANGES)
        self.driver.initialize_network_segment_range_support()
        self.driver.sync_allocations()
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(1, len(ret))
        network_segment_range = ret[0]
        self.assertTrue(network_segment_range.default)
        self.assertTrue(network_segment_range.shared)
        self.assertIsNone(network_segment_range.project_id)
        self.assertEqual(self.driver.get_type(),
                         network_segment_range.network_type)
        self.assertIsNone(network_segment_range.physical_network)
        self.assertEqual(TUN_MIN, network_segment_range.minimum)
        self.assertEqual(TUN_MAX, network_segment_range.maximum)

    def test__delete_expired_default_network_segment_ranges(self):
        self.driver.tunnel_ranges = TUNNEL_RANGES
        self.driver.sync_allocations()
        self.driver._delete_expired_default_network_segment_ranges()
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(0, len(ret))
