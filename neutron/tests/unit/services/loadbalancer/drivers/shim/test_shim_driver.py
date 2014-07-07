# Copyright 2014 Blue Box Group, Inc.
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
#
# @author: Dustin Lundquist, Blue Box Group

import mock

from neutron import context
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer.drivers.shim import driver as shim_driver
from neutron.tests import base
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer


class TestShimLoadBalancerDriver(base.BaseTestCase):

    def setUp(self):
        super(TestShimLoadBalancerDriver, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = mock.Mock()
        self.driver = shim_driver.LBShimDriver(self.plugin,
                                  test_db_loadbalancer.NoopLbaaSDriver)

    def runTest(self):
        pass

    def test_load_balancer_create(self):
        # TODO(mock SQLAlchemy objects)
        pool = {'id': '3204c891-3a4b-40c4-a547-b85bb3cf5272',
                'tanant_id': None,
                'name': 'app-pool',
                'description': '',
                'healthmonitor_id': None,
                'protocol': lb_const.PROTOCOL_HTTP,
                'lb_algorithm': lb_const.LB_METHOD_ROUND_ROBIN,
                'status': constants.ACTIVE,
                'admin_state_up': True,
                'members': []}
        listener = {'id': '040d1059-acff-4e90-b2cf-24f18e47697e',
                   'tenant_id': None,
                   'loadbalancer_id': '9cd91416-a76d-4d09-80f8-e79c27ba33ec',
                   'default_pool_id': '3204c891-3a4b-40c4-a547-b85bb3cf5272',
                   'default_pool': pool,
                   'protocol': lb_const.PROTOCOL_HTTP,
                   'protocol_port': 80,
                   'connection_limit': None,
                   'admin_state_up': True,
                   'status': constants.ACTIVE}
        load_balancer = {'id': '9cd91416-a76d-4d09-80f8-e79c27ba33ec',
                         'tenant_id': None,
                         'name': "foo",
                         'description': "Foo load balancer",
                         'vip_subnet_id': None,
                         'vip_address': None,
                         'vip_port_id': None,
                         'status': constants.ACTIVE,
                         'admin_state_up': True,
                         'listeners': [listener]}

        self.driver.load_balancer.create(self.context, load_balancer)
