# Copyright (c) 2012 OpenStack Foundation.
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

import fixtures
from oslo_config import cfg
from oslo_log import log as logging

from neutron import manager
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit import dummy_plugin


LOG = logging.getLogger(__name__)
DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class MultiServiceCorePlugin(object):
    supported_extension_aliases = ['lbaas', 'dummy']


class CorePluginWithAgentNotifiers(object):
    agent_notifiers = {'l3': 'l3_agent_notifier',
                       'dhcp': 'dhcp_agent_notifier'}


class NeutronManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(NeutronManagerTestCase, self).setUp()
        self.config_parse()
        self.setup_coreplugin()
        self.useFixture(
            fixtures.MonkeyPatch('neutron.manager.NeutronManager._instance'))

    def test_service_plugin_is_loaded(self):
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        mgr = manager.NeutronManager.get_instance()
        plugin = mgr.get_service_plugins()[constants.DUMMY]

        self.assertIsInstance(
            plugin, dummy_plugin.DummyServicePlugin,
            "loaded plugin should be of type neutronDummyPlugin")

    def test_service_plugin_by_name_is_loaded(self):
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", ["dummy"])
        mgr = manager.NeutronManager.get_instance()
        plugin = mgr.get_service_plugins()[constants.DUMMY]

        self.assertIsInstance(
            plugin, dummy_plugin.DummyServicePlugin,
            "loaded plugin should be of type neutronDummyPlugin")

    def test_multiple_plugins_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin",
                               "neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        e = self.assertRaises(ValueError, manager.NeutronManager.get_instance)
        self.assertIn(constants.DUMMY, str(e))

    def test_multiple_plugins_by_name_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins", ["dummy", "dummy"])
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        self.assertRaises(ValueError, manager.NeutronManager.get_instance)

    def test_multiple_plugins_mixed_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin", "dummy"])
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        self.assertRaises(ValueError, manager.NeutronManager.get_instance)

    def test_service_plugin_conflicts_with_core_plugin(self):
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        cfg.CONF.set_override("core_plugin",
                              "neutron.tests.unit.test_manager."
                              "MultiServiceCorePlugin")
        e = self.assertRaises(ValueError, manager.NeutronManager.get_instance)
        self.assertIn(constants.DUMMY, str(e))

    def test_core_plugin_supports_services(self):
        cfg.CONF.set_override("core_plugin",
                              "neutron.tests.unit.test_manager."
                              "MultiServiceCorePlugin")
        mgr = manager.NeutronManager.get_instance()
        svc_plugins = mgr.get_service_plugins()
        self.assertEqual(4, len(svc_plugins))
        self.assertIn(constants.CORE, svc_plugins.keys())
        self.assertIn(constants.LOADBALANCER, svc_plugins.keys())
        self.assertIn(constants.DUMMY, svc_plugins.keys())

    def test_post_plugin_validation(self):
        cfg.CONF.import_opt('dhcp_agents_per_network',
                            'neutron.db.agentschedulers_db')

        self.assertIsNone(manager.validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        self.assertIsNone(manager.validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', 0)
        self.assertIsNotNone(manager.validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', -1)
        self.assertIsNotNone(manager.validate_post_plugin_load())

    def test_pre_plugin_validation(self):
        self.assertIsNotNone(manager.validate_pre_plugin_load())
        cfg.CONF.set_override('core_plugin', 'dummy.plugin')
        self.assertIsNone(manager.validate_pre_plugin_load())

    def test_manager_gathers_agent_notifiers_from_service_plugins(self):
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        cfg.CONF.set_override("core_plugin",
                              "neutron.tests.unit.test_manager."
                              "CorePluginWithAgentNotifiers")
        expected = {'l3': 'l3_agent_notifier',
                    'dhcp': 'dhcp_agent_notifier',
                    'dummy': 'dummy_agent_notifier'}
        core_plugin = manager.NeutronManager.get_plugin()
        self.assertEqual(expected, core_plugin.agent_notifiers)
