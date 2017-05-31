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

import weakref

import fixtures
from neutron_lib.plugins import constants as lib_const
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron import manager
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit import dummy_plugin
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class MultiServiceCorePlugin(object):
    supported_extension_aliases = ['lbaas', dummy_plugin.Dummy.get_alias()]


class CorePluginWithAgentNotifiers(object):
    agent_notifiers = {'l3': 'l3_agent_notifier',
                       'dhcp': 'dhcp_agent_notifier'}


class NeutronManagerTestCase(base.BaseTestCase):

    def setUp(self):
        ext_mapping = constants.EXT_TO_SERVICE_MAPPING
        if dummy_plugin.Dummy.get_alias() not in ext_mapping:
            ext_mapping[dummy_plugin.Dummy.get_alias()] = (
                dummy_plugin.DUMMY_SERVICE_TYPE)
        super(NeutronManagerTestCase, self).setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)
        self.useFixture(
            fixtures.MonkeyPatch('neutron.manager.NeutronManager._instance'))

    def tearDown(self):
        ext_mapping = constants.EXT_TO_SERVICE_MAPPING
        if dummy_plugin.Dummy.get_alias() in ext_mapping:
            del ext_mapping[dummy_plugin.Dummy.get_alias()]
        super(NeutronManagerTestCase, self).tearDown()

    def test_service_plugin_is_loaded(self):
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        manager.init()
        plugin = directory.get_plugin(dummy_plugin.DUMMY_SERVICE_TYPE)

        self.assertIsInstance(
            plugin, dummy_plugin.DummyServicePlugin,
            "loaded plugin should be of type neutronDummyPlugin")

    def test_service_plugin_by_name_is_loaded(self):
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins",
                              [dummy_plugin.Dummy.get_alias()])
        manager.init()
        plugin = directory.get_plugin(dummy_plugin.DUMMY_SERVICE_TYPE)

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
        self.assertIn(dummy_plugin.DUMMY_SERVICE_TYPE, str(e))

    def test_multiple_plugins_by_name_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              [dummy_plugin.Dummy.get_alias(),
                               dummy_plugin.Dummy.get_alias()])
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        self.assertRaises(ValueError, manager.NeutronManager.get_instance)

    def test_multiple_plugins_mixed_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              ["neutron.tests.unit.dummy_plugin."
                               "DummyServicePlugin",
                               dummy_plugin.Dummy.get_alias()])
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
        self.assertIn(dummy_plugin.DUMMY_SERVICE_TYPE, str(e))

    def test_core_plugin_supports_services(self):
        cfg.CONF.set_override("core_plugin",
                              "neutron.tests.unit.test_manager."
                              "MultiServiceCorePlugin")
        manager.init()
        svc_plugins = directory.get_plugins()
        self.assertEqual(3, len(svc_plugins))
        self.assertIn(lib_const.CORE, svc_plugins.keys())
        self.assertIn(lib_const.LOADBALANCER, svc_plugins.keys())
        self.assertIn(dummy_plugin.DUMMY_SERVICE_TYPE, svc_plugins.keys())

    def test_load_default_service_plugins(self):
        self.patched_default_svc_plugins.return_value = {
            'neutron.tests.unit.dummy_plugin.DummyServicePlugin':
                dummy_plugin.DUMMY_SERVICE_TYPE
        }
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        manager.init()
        svc_plugins = directory.get_plugins()
        self.assertIn(dummy_plugin.DUMMY_SERVICE_TYPE, svc_plugins)

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
                    dummy_plugin.Dummy.get_alias(): 'dummy_agent_notifier'}
        manager.init()
        core_plugin = directory.get_plugin()
        self.assertEqual(expected, core_plugin.agent_notifiers)

    def test_load_class_for_provider(self):
        manager.NeutronManager.load_class_for_provider(
            'neutron.core_plugins', 'ml2')

    def test_load_class_for_provider_wrong_plugin(self):
        with testlib_api.ExpectedException(ImportError):
            manager.NeutronManager.load_class_for_provider(
                    'neutron.core_plugins', 'ml2XXXXXX')

    def test_get_service_plugin_by_path_prefix_3(self):
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        nm = manager.NeutronManager.get_instance()

        class pclass(object):
            def __init__(self, path_prefix):
                self.path_prefix = path_prefix

        x_plugin, y_plugin = pclass('xpa'), pclass('ypa')
        directory.add_plugin('x', x_plugin)
        directory.add_plugin('y', y_plugin)
        self.assertEqual(weakref.proxy(x_plugin),
                         nm.get_service_plugin_by_path_prefix('xpa'))
        self.assertEqual(weakref.proxy(y_plugin),
                         nm.get_service_plugin_by_path_prefix('ypa'))
        self.assertIsNone(nm.get_service_plugin_by_path_prefix('abc'))
