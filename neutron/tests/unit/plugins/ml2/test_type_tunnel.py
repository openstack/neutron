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

import contextlib
import mock
from six import moves
import testtools
from testtools import matchers

from neutron.common import exceptions as exc
from neutron.db import api as db
from neutron.plugins.ml2 import driver_api as api

TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"
HOST_ONE = 'fake_host_one'
HOST_TWO = 'fake_host_two'
TUN_MIN = 100
TUN_MAX = 109
TUNNEL_RANGES = [(TUN_MIN, TUN_MAX)]
UPDATED_TUNNEL_RANGES = [(TUN_MIN + 5, TUN_MAX + 5)]


class TunnelTypeTestMixin(object):
    DRIVER_CLASS = None
    TYPE = None

    def setUp(self):
        super(TunnelTypeTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()
        self.driver.tunnel_ranges = TUNNEL_RANGES
        self.driver.sync_allocations()
        self.session = db.get_session()

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
            self.driver.get_allocation(self.session, (TUN_MIN - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MIN)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MIN + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MAX - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MAX)).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.session, (TUN_MAX + 1)))

        self.driver.tunnel_ranges = UPDATED_TUNNEL_RANGES
        self.driver.sync_allocations()

        self.assertIsNone(
            self.driver.get_allocation(self.session, (TUN_MIN + 5 - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MIN + 5)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session,
                                       (TUN_MIN + 5 + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session,
                                       (TUN_MAX + 5 - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.session, (TUN_MAX + 5)).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.session, (TUN_MAX + 5 + 1)))

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
        observed = self.driver.reserve_provider_segment(self.session, segment)
        alloc = self.driver.get_allocation(self.session,
                                           observed[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        with testtools.ExpectedException(exc.TunnelIdInUse):
            self.driver.reserve_provider_segment(self.session, segment)

        self.driver.release_segment(self.session, segment)
        alloc = self.driver.get_allocation(self.session,
                                           observed[api.SEGMENTATION_ID])
        self.assertFalse(alloc.allocated)

        segment[api.SEGMENTATION_ID] = 1000
        observed = self.driver.reserve_provider_segment(self.session, segment)
        alloc = self.driver.get_allocation(self.session,
                                           observed[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        self.driver.release_segment(self.session, segment)
        alloc = self.driver.get_allocation(self.session,
                                           observed[api.SEGMENTATION_ID])
        self.assertIsNone(alloc)

    def test_reserve_provider_segment(self):
        tunnel_ids = set()
        specs = {api.NETWORK_TYPE: self.TYPE,
                 api.PHYSICAL_NETWORK: 'None',
                 api.SEGMENTATION_ID: None}

        for x in moves.xrange(TUN_MIN, TUN_MAX + 1):
            segment = self.driver.reserve_provider_segment(self.session,
                                                           specs)
            self.assertEqual(self.TYPE, segment[api.NETWORK_TYPE])
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.GreaterThan(TUN_MIN - 1))
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.LessThan(TUN_MAX + 1))
            tunnel_ids.add(segment[api.SEGMENTATION_ID])

        with testtools.ExpectedException(exc.NoNetworkAvailable):
            segment = self.driver.reserve_provider_segment(self.session,
                                                           specs)

        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: 'None',
                   api.SEGMENTATION_ID: tunnel_ids.pop()}
        self.driver.release_segment(self.session, segment)
        segment = self.driver.reserve_provider_segment(self.session, specs)
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.GreaterThan(TUN_MIN - 1))
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.LessThan(TUN_MAX + 1))
        tunnel_ids.add(segment[api.SEGMENTATION_ID])

        for tunnel_id in tunnel_ids:
            segment[api.SEGMENTATION_ID] = tunnel_id
            self.driver.release_segment(self.session, segment)

    def test_allocate_tenant_segment(self):
        tunnel_ids = set()
        for x in moves.xrange(TUN_MIN, TUN_MAX + 1):
            segment = self.driver.allocate_tenant_segment(self.session)
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.GreaterThan(TUN_MIN - 1))
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.LessThan(TUN_MAX + 1))
            tunnel_ids.add(segment[api.SEGMENTATION_ID])

        segment = self.driver.allocate_tenant_segment(self.session)
        self.assertIsNone(segment)

        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: 'None',
                   api.SEGMENTATION_ID: tunnel_ids.pop()}
        self.driver.release_segment(self.session, segment)
        segment = self.driver.allocate_tenant_segment(self.session)
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.GreaterThan(TUN_MIN - 1))
        self.assertThat(segment[api.SEGMENTATION_ID],
                        matchers.LessThan(TUN_MAX + 1))
        tunnel_ids.add(segment[api.SEGMENTATION_ID])

        for tunnel_id in tunnel_ids:
            segment[api.SEGMENTATION_ID] = tunnel_id
            self.driver.release_segment(self.session, segment)


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
        self.session = db.get_session()

    def test_release_segment(self):
        segments = [self.driver.allocate_tenant_segment(self.session)
                    for i in range(4)]

        # Release them in random order. No special meaning.
        for i in (0, 2, 1, 3):
            self.driver.release_segment(self.session, segments[i])

        for key in (self.TUN_MIN0, self.TUN_MAX0,
                    self.TUN_MIN1, self.TUN_MAX1):
            alloc = self.driver.get_allocation(self.session, key)
            self.assertFalse(alloc.allocated)


class TunnelRpcCallbackTestMixin(object):

    DRIVER_CLASS = None
    TYPE = None

    def setUp(self):
        super(TunnelRpcCallbackTestMixin, self).setUp()
        self.driver = self.DRIVER_CLASS()

    def _test_tunnel_sync(self, kwargs, delete_tunnel=False):
        with contextlib.nested(
            mock.patch.object(self.notifier, 'tunnel_update'),
            mock.patch.object(self.notifier, 'tunnel_delete')
        ) as (tunnel_update, tunnel_delete):
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
        with contextlib.nested(
            mock.patch.object(self.notifier, 'tunnel_update'),
            mock.patch.object(self.notifier, 'tunnel_delete')
        ) as (tunnel_update, tunnel_delete):
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

    def test_tunnel_sync_called_with_used_tunnel_ip_case_one(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, HOST_ONE)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_TWO}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_with_used_tunnel_ip_case_two(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, None)
        self.driver.add_endpoint(TUNNEL_IP_TWO, HOST_TWO)

        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'tunnel_type': self.TYPE,
                  'host': HOST_TWO}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_without_tunnel_ip(self):
        kwargs = {'tunnel_type': self.TYPE, 'host': None}
        self._test_tunnel_sync_raises(kwargs)

    def test_tunnel_sync_called_without_tunnel_type(self):
        kwargs = {'tunnel_ip': TUNNEL_IP_ONE, 'host': None}
        self._test_tunnel_sync_raises(kwargs)
