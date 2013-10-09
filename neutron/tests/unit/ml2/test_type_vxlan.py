# Copyright (c) 2013 OpenStack Foundation
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
# @author: Kyle Mestery, Cisco Systems, Inc.

from oslo.config import cfg
import testtools
from testtools import matchers

from neutron.common import exceptions as exc
from neutron.db import api as db
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_vxlan
from neutron.tests import base


TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"
TUN_MIN = 100
TUN_MAX = 109
TUNNEL_RANGES = [(TUN_MIN, TUN_MAX)]
UPDATED_TUNNEL_RANGES = [(TUN_MIN + 5, TUN_MAX + 5)]
INVALID_VXLAN_VNI = 7337
MULTICAST_GROUP = "239.1.1.1"
VXLAN_UDP_PORT_ONE = 9999
VXLAN_UDP_PORT_TWO = 8888


class VxlanTypeTest(base.BaseTestCase):
    def setUp(self):
        super(VxlanTypeTest, self).setUp()
        ml2_db.initialize()
        cfg.CONF.set_override('vni_ranges', [TUNNEL_RANGES],
                              group='ml2_type_vxlan')
        cfg.CONF.set_override('vxlan_group', MULTICAST_GROUP,
                              group='ml2_type_vxlan')
        self.driver = type_vxlan.VxlanTypeDriver()
        self.driver.vxlan_vni_ranges = TUNNEL_RANGES
        self.driver._sync_vxlan_allocations()
        self.session = db.get_session()
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(db.clear_db)

    def test_vxlan_tunnel_type(self):
        self.assertEqual(self.driver.get_type(), type_vxlan.TYPE_VXLAN)

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: 'vxlan',
                   api.PHYSICAL_NETWORK: 'phys_net',
                   api.SEGMENTATION_ID: None}

        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.validate_provider_segment(segment)

        segment[api.PHYSICAL_NETWORK] = None
        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.validate_provider_segment(segment)

    def test_sync_tunnel_allocations(self):
        self.assertIsNone(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MIN - 1))
        )
        self.assertFalse(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MIN)).allocated
        )
        self.assertFalse(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MIN + 1)).allocated
        )
        self.assertFalse(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MAX - 1)).allocated
        )
        self.assertFalse(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MAX)).allocated
        )
        self.assertIsNone(
            self.driver.get_vxlan_allocation(self.session,
                                             (TUN_MAX + 1))
        )

        self.driver.vxlan_vni_ranges = UPDATED_TUNNEL_RANGES
        self.driver._sync_vxlan_allocations()

        self.assertIsNone(self.driver.
                          get_vxlan_allocation(self.session,
                          (TUN_MIN + 5 - 1)))
        self.assertFalse(self.driver.
                         get_vxlan_allocation(self.session, (TUN_MIN + 5)).
                         allocated)
        self.assertFalse(self.driver.
                         get_vxlan_allocation(self.session, (TUN_MIN + 5 + 1)).
                         allocated)
        self.assertFalse(self.driver.
                         get_vxlan_allocation(self.session, (TUN_MAX + 5 - 1)).
                         allocated)
        self.assertFalse(self.driver.
                         get_vxlan_allocation(self.session, (TUN_MAX + 5)).
                         allocated)
        self.assertIsNone(self.driver.
                          get_vxlan_allocation(self.session,
                          (TUN_MAX + 5 + 1)))

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: 'vxlan',
                   api.PHYSICAL_NETWORK: 'None',
                   api.SEGMENTATION_ID: 101}
        self.driver.reserve_provider_segment(self.session, segment)
        alloc = self.driver.get_vxlan_allocation(self.session,
                                                 segment[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        with testtools.ExpectedException(exc.TunnelIdInUse):
            self.driver.reserve_provider_segment(self.session, segment)

        self.driver.release_segment(self.session, segment)
        alloc = self.driver.get_vxlan_allocation(self.session,
                                                 segment[api.SEGMENTATION_ID])
        self.assertFalse(alloc.allocated)

        segment[api.SEGMENTATION_ID] = 1000
        self.driver.reserve_provider_segment(self.session, segment)
        alloc = self.driver.get_vxlan_allocation(self.session,
                                                 segment[api.SEGMENTATION_ID])
        self.assertTrue(alloc.allocated)

        self.driver.release_segment(self.session, segment)
        alloc = self.driver.get_vxlan_allocation(self.session,
                                                 segment[api.SEGMENTATION_ID])
        self.assertIsNone(alloc)

    def test_allocate_tenant_segment(self):
        tunnel_ids = set()
        for x in xrange(TUN_MIN, TUN_MAX + 1):
            segment = self.driver.allocate_tenant_segment(self.session)
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.GreaterThan(TUN_MIN - 1))
            self.assertThat(segment[api.SEGMENTATION_ID],
                            matchers.LessThan(TUN_MAX + 1))
            tunnel_ids.add(segment[api.SEGMENTATION_ID])

        segment = self.driver.allocate_tenant_segment(self.session)
        self.assertIsNone(segment)

        segment = {api.NETWORK_TYPE: 'vxlan',
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

    def test_vxlan_endpoints(self):
        """Test VXLAN allocation/de-allocation."""

        # Set first endpoint, verify it gets VXLAN VNI 1
        vxlan1_endpoint = self.driver.add_endpoint(TUNNEL_IP_ONE,
                                                   VXLAN_UDP_PORT_ONE)
        self.assertEqual(TUNNEL_IP_ONE, vxlan1_endpoint.ip_address)
        self.assertEqual(VXLAN_UDP_PORT_ONE, vxlan1_endpoint.udp_port)

        # Set second endpoint, verify it gets VXLAN VNI 2
        vxlan2_endpoint = self.driver.add_endpoint(TUNNEL_IP_TWO,
                                                   VXLAN_UDP_PORT_TWO)
        self.assertEqual(TUNNEL_IP_TWO, vxlan2_endpoint.ip_address)
        self.assertEqual(VXLAN_UDP_PORT_TWO, vxlan2_endpoint.udp_port)

        # Get all the endpoints
        endpoints = self.driver.get_endpoints()
        for endpoint in endpoints:
            if endpoint['ip_address'] == TUNNEL_IP_ONE:
                self.assertEqual(VXLAN_UDP_PORT_ONE, endpoint['udp_port'])
            elif endpoint['ip_address'] == TUNNEL_IP_TWO:
                self.assertEqual(VXLAN_UDP_PORT_TWO, endpoint['udp_port'])
