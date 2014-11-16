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

import mock

from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_vxlan
from neutron.tests.unit.ml2 import test_type_tunnel
from neutron.tests.unit import testlib_api


TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"
VXLAN_UDP_PORT_ONE = 9999
VXLAN_UDP_PORT_TWO = 8888


class VxlanTypeTest(test_type_tunnel.TunnelTypeTestMixin,
                    testlib_api.SqlTestCase):
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver
    TYPE = p_const.TYPE_VXLAN

    def test_endpoints(self):
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

    def test_add_same_ip_endpoints(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, VXLAN_UDP_PORT_ONE)
        with mock.patch.object(type_vxlan.LOG, 'warning') as log_warn:
            observed = self.driver.add_endpoint(TUNNEL_IP_ONE,
                                                VXLAN_UDP_PORT_TWO)
            self.assertEqual(VXLAN_UDP_PORT_ONE, observed['udp_port'])
            log_warn.assert_called_once_with(mock.ANY, TUNNEL_IP_ONE)


class VxlanTypeMultiRangeTest(test_type_tunnel.TunnelTypeMultiRangeTestMixin,
                              testlib_api.SqlTestCase):
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver