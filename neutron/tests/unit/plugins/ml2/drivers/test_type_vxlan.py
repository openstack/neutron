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

from neutron_lib import constants as p_const

from neutron.plugins.ml2.drivers import type_vxlan
from neutron.tests.unit.plugins.ml2.drivers import base_type_tunnel
from neutron.tests.unit.plugins.ml2 import test_rpc
from neutron.tests.unit import testlib_api


VXLAN_UDP_PORT_ONE = 9999
VXLAN_UDP_PORT_TWO = 8888


class VxlanTypeTest(base_type_tunnel.TunnelTypeTestMixin,
                    base_type_tunnel.TunnelTypeNetworkSegmentRangeTestMixin,
                    testlib_api.SqlTestCase):
    DRIVER_MODULE = type_vxlan
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver
    TYPE = p_const.TYPE_VXLAN

    def add_endpoint(self, ip=base_type_tunnel.TUNNEL_IP_ONE,
                     host=base_type_tunnel.HOST_ONE):
        if ip == base_type_tunnel.TUNNEL_IP_ONE:
            port = VXLAN_UDP_PORT_ONE
        else:
            port = VXLAN_UDP_PORT_TWO
        return self.driver.add_endpoint(ip, host, port)

    def test_add_endpoint(self):
        endpoint = super(VxlanTypeTest, self).test_add_endpoint()
        self.assertEqual(VXLAN_UDP_PORT_ONE, endpoint.udp_port)

    def test_get_endpoint_by_host(self):
        endpoint = super(VxlanTypeTest, self).test_get_endpoint_by_host()
        self.assertEqual(VXLAN_UDP_PORT_ONE, endpoint.udp_port)

    def test_get_endpoint_by_ip(self):
        endpoint = super(VxlanTypeTest, self).test_get_endpoint_by_ip()
        self.assertEqual(VXLAN_UDP_PORT_ONE, endpoint.udp_port)

    def test_get_endpoints(self):
        self.add_endpoint()
        self.add_endpoint(base_type_tunnel.TUNNEL_IP_TWO,
                          base_type_tunnel.HOST_TWO)

        endpoints = self.driver.get_endpoints()
        for endpoint in endpoints:
            if endpoint['ip_address'] == base_type_tunnel.TUNNEL_IP_ONE:
                self.assertEqual(VXLAN_UDP_PORT_ONE, endpoint['udp_port'])
                self.assertEqual(base_type_tunnel.HOST_ONE, endpoint['host'])
            elif endpoint['ip_address'] == base_type_tunnel.TUNNEL_IP_TWO:
                self.assertEqual(VXLAN_UDP_PORT_TWO, endpoint['udp_port'])
                self.assertEqual(base_type_tunnel.HOST_TWO, endpoint['host'])


class VxlanTypeMultiRangeTest(base_type_tunnel.TunnelTypeMultiRangeTestMixin,
                              testlib_api.SqlTestCase):
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver


class VxlanTypeRpcCallbackTest(base_type_tunnel.TunnelRpcCallbackTestMixin,
                               test_rpc.RpcCallbacksTestCase,
                               testlib_api.SqlTestCase):
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver
    TYPE = p_const.TYPE_VXLAN


class VxlanTypeTunnelMTUTest(base_type_tunnel.TunnelTypeMTUTestMixin,
                             testlib_api.SqlTestCase):
    DRIVER_CLASS = type_vxlan.VxlanTypeDriver
    TYPE = p_const.TYPE_VXLAN
    ENCAP_OVERHEAD = p_const.VXLAN_ENCAP_OVERHEAD
