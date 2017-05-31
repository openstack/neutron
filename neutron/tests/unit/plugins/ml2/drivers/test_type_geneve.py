# Copyright (c) 2015 OpenStack Foundation
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

from neutron.plugins.ml2.drivers import type_geneve
from neutron.tests.unit.plugins.ml2.drivers import base_type_tunnel
from neutron.tests.unit.plugins.ml2 import test_rpc
from neutron.tests.unit import testlib_api


TUNNEL_IP_ONE = "10.10.10.77"
TUNNEL_IP_TWO = "10.10.10.78"
HOST_ONE = 'fake_host_one1'
HOST_TWO = 'fake_host_two2'


class GeneveTypeTest(base_type_tunnel.TunnelTypeTestMixin,
                     testlib_api.SqlTestCase):
    DRIVER_CLASS = type_geneve.GeneveTypeDriver
    TYPE = p_const.TYPE_GENEVE

    def test_get_endpoints(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE, HOST_ONE)
        self.driver.add_endpoint(TUNNEL_IP_TWO, HOST_TWO)

        endpoints = self.driver.get_endpoints()
        for endpoint in endpoints:
            if endpoint['ip_address'] == TUNNEL_IP_ONE:
                self.assertEqual(HOST_ONE, endpoint['host'])
            elif endpoint['ip_address'] == TUNNEL_IP_TWO:
                self.assertEqual(HOST_TWO, endpoint['host'])


class GeneveTypeMultiRangeTest(base_type_tunnel.TunnelTypeMultiRangeTestMixin,
                               testlib_api.SqlTestCase):
    DRIVER_CLASS = type_geneve.GeneveTypeDriver


class GeneveTypeRpcCallbackTest(base_type_tunnel.TunnelRpcCallbackTestMixin,
                                test_rpc.RpcCallbacksTestCase,
                                testlib_api.SqlTestCase):
    DRIVER_CLASS = type_geneve.GeneveTypeDriver
    TYPE = p_const.TYPE_GENEVE


class GeneveTypeTunnelMTUTest(base_type_tunnel.TunnelTypeMTUTestMixin,
                              testlib_api.SqlTestCase):
    DRIVER_CLASS = type_geneve.GeneveTypeDriver
    TYPE = p_const.TYPE_GENEVE
    ENCAP_OVERHEAD = p_const.GENEVE_ENCAP_MIN_OVERHEAD
