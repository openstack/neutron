# Copyright 2014 OpenStack Foundation.
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

import gc
import os
import weakref

import mock
from oslo.config import cfg

from neutron.db import agentschedulers_db
from neutron import manager
from neutron.tests import base
from neutron.tests import fake_notifier


class PluginSetupHelper(object):
    """Mixin for use with testtools.TestCase."""

    def cleanup_core_plugin(self):
        """Ensure that the core plugin is deallocated."""
        nm = manager.NeutronManager
        if not nm.has_instance():
            return

        # TODO(marun) Fix plugins that do not properly initialize notifiers
        agentschedulers_db.AgentSchedulerDbMixin.agent_notifiers = {}

        # Perform a check for deallocation only if explicitly
        # configured to do so since calling gc.collect() after every
        # test increases test suite execution time by ~50%.
        check_plugin_deallocation = (
            os.environ.get('OS_CHECK_PLUGIN_DEALLOCATION') in base.TRUE_STRING)
        if check_plugin_deallocation:
            plugin = weakref.ref(nm._instance.plugin)

        nm.clear_instance()

        if check_plugin_deallocation:
            gc.collect()

            # TODO(marun) Ensure that mocks are deallocated?
            if plugin() and not isinstance(plugin(), mock.Base):
                self.fail('The plugin for this test was not deallocated.')

    def setup_coreplugin(self, core_plugin=None):
        # Plugin cleanup should be triggered last so that
        # test-specific cleanup has a chance to release references.
        self.addCleanup(self.cleanup_core_plugin)
        if core_plugin is not None:
            cfg.CONF.set_override('core_plugin', core_plugin)


class NotificationSetupHelper(object):
    """Mixin for use with testtools.TestCase."""

    def setup_notification_driver(self, notification_driver=None):
        self.addCleanup(fake_notifier.reset)
        if notification_driver is None:
            notification_driver = [fake_notifier.__name__]
        cfg.CONF.set_override("notification_driver", notification_driver)
