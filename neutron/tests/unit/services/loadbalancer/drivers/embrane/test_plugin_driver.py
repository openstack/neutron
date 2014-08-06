# Copyright 2013 Embrane, Inc.
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

import sys

import mock
from oslo.config import cfg
from oslo.db import exception as n_exc

from neutron import context
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer

HELEOSAPIMOCK = mock.Mock()
sys.modules["heleosapi"] = HELEOSAPIMOCK
from neutron.services.loadbalancer.drivers.embrane import config  # noqa
from neutron.services.loadbalancer.drivers.embrane import constants as h_con
from neutron.services.loadbalancer.drivers.embrane import db as h_db
# Stop the mock from persisting indefinitely in the global modules space
del sys.modules["heleosapi"]

EMBRANE_PROVIDER = ('LOADBALANCER:lbaas:neutron.services.'
                    'loadbalancer.drivers.embrane.driver.'
                    'EmbraneLbaas:default')


class TestLoadBalancerPluginBase(
        test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        cfg.CONF.set_override('admin_password', "admin123", 'heleoslb')
        cfg.CONF.set_override('sync_interval', 0, 'heleoslb')
        mock.patch.dict(sys.modules, {'heleosapi': HELEOSAPIMOCK}).start()
        super(TestLoadBalancerPluginBase, self).setUp(
            lbaas_provider=EMBRANE_PROVIDER)
        self.driver = self.plugin.drivers['lbaas']
        # prevent module mock from saving calls between tests
        self.addCleanup(HELEOSAPIMOCK.reset_mock)


class TestLoadBalancerPlugin(test_db_loadbalancer.TestLoadBalancer,
                             TestLoadBalancerPluginBase):

    def test_create_vip_with_session_persistence_with_app_cookie(self):
        self.skip("App cookie persistence not supported.")

    def test_pool_port(self):
        with self.port() as port:
            with self.pool() as pool:
                h_db.add_pool_port(context.get_admin_context(),
                                   pool['pool']['id'], port['port']['id'])
                pool_port = h_db.get_pool_port(context.get_admin_context(),
                                               pool['pool']['id'])
                self.assertIsNotNone(pool_port)
            pool_port = h_db.get_pool_port(context.get_admin_context(),
                                           pool['pool']['id'])
            self.assertIsNone(pool_port)

    def test_create_pool_port_no_port(self):
        with self.pool() as pool:
            self.assertRaises(n_exc.DBError,
                              h_db.add_pool_port,
                              context.get_admin_context(),
                              pool['pool']['id'], None)

    def test_lb_operations_handlers(self):
        h = self.driver._dispatcher.handlers
        self.assertIsNotNone(h[h_con.Events.ADD_OR_UPDATE_MEMBER])
        self.assertIsNotNone(h[h_con.Events.CREATE_VIP])
        self.assertIsNotNone(h[h_con.Events.DELETE_MEMBER])
        self.assertIsNotNone(h[h_con.Events.DELETE_VIP])
        self.assertIsNotNone(h[h_con.Events.POLL_GRAPH])
        self.assertIsNotNone(h[h_con.Events.REMOVE_MEMBER])
        self.assertIsNotNone(h[h_con.Events.UPDATE_POOL])
        self.assertIsNotNone(h[h_con.Events.UPDATE_VIP])
        self.assertIsNotNone(h[h_con.Events.UPDATE_POOL_HM])
        self.assertIsNotNone(h[h_con.Events.DELETE_POOL_HM])
        self.assertIsNotNone(h[h_con.Events.ADD_POOL_HM])
