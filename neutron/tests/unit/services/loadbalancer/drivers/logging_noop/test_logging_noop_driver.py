# Copyright 2014, Doug Wiegley (dougwig), A10 Networks
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

from neutron import context
from neutron.services.loadbalancer.drivers.logging_noop import driver
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer

log_path = 'neutron.services.loadbalancer.drivers.logging_noop.driver.LOG'


class FakeModel(object):
    def __init__(self, id):
        self.id = id


def patch_manager(func):
    @mock.patch(log_path)
    def wrapper(*args):
        log_mock = args[-1]
        manager_test = args[0]
        model = args[1]
        parent = manager_test.parent
        driver = parent.driver
        driver.plugin.reset_mock()

        func(*args[:-1])

        s = str(log_mock.mock_calls[0])
        parent.assertEqual(s[:11], "call.debug(")
        parent.assertTrue(s.index(model.id) != -1,
                          msg="Model ID not found in log")

    return wrapper


class ManagerTest(object):
    def __init__(self, parent, manager, model):
        self.parent = parent
        self.manager = manager

        self.create(model)
        self.update(model, model)
        self.delete(model)

    @patch_manager
    def create(self, model):
        self.manager.create(self.parent.context, model)

    @patch_manager
    def update(self, old_model, model):
        self.manager.update(self.parent.context, old_model, model)

    @patch_manager
    def delete(self, model):
        self.manager.delete(self.parent.context, model)


class ManagerTestWithUpdates(ManagerTest):
    def __init__(self, parent, manager, model):
        self.parent = parent
        self.manager = manager

        self.create(model)
        self.update(model, model)
        self.delete(model)

    @patch_manager
    def create(self, model):
        self.manager.create(self.parent.context, model)
        if self.manager.model_class is not None:
            self.parent.assertEqual(
                             str(self.parent.driver.plugin.mock_calls[0])[:18],
                             "call.update_status")

    @patch_manager
    def update(self, old_model, model):
        self.manager.update(self.parent.context, old_model, model)
        if self.manager.model_class is not None:
            self.parent.assertEqual(
                             str(self.parent.driver.plugin.mock_calls[0])[:18],
                             "call.update_status")

    @patch_manager
    def delete(self, model):
        self.manager.delete(self.parent.context, model)


class LoadBalancerManagerTest(ManagerTestWithUpdates):
    def __init__(self, parent, manager, model):
        super(LoadBalancerManagerTest, self).__init__(parent, manager, model)

        self.refresh(model)
        self.stats(model)

    @patch_manager
    def refresh(self, model):
        self.manager.refresh(self.parent.context, model)

    @patch_manager
    def stats(self, model):
        dummy_stats = {
            "bytes_in": 0,
            "bytes_out": 0,
            "active_connections": 0,
            "total_connections": 0
        }
        h = self.manager.stats(self.parent.context, model)
        self.parent.assertEqual(h, dummy_stats)


class TestLoggingNoopLoadBalancerDriver(
        test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        super(TestLoggingNoopLoadBalancerDriver, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = mock.Mock()
        self.driver = driver.LoggingNoopLoadBalancerDriver(self.plugin)

    def test_load_balancer_ops(self):
        LoadBalancerManagerTest(self, self.driver.load_balancer,
                                FakeModel("loadbalancer-001"))

    def test_listener_ops(self):
        ManagerTest(self, self.driver.listener, FakeModel("listener-001"))

    def test_pool_ops(self):
        ManagerTestWithUpdates(self, self.driver.pool, FakeModel("pool-001"))

    def test_member_ops(self):
        ManagerTestWithUpdates(self, self.driver.member,
                               FakeModel("member-001"))

    def test_health_monitor_ops(self):
        ManagerTest(self, self.driver.health_monitor, FakeModel("hm-001"))
