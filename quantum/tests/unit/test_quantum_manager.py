# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os
import types

import fixtures

from oslo.config import cfg

from quantum.common import config
from quantum.common.test_lib import test_config
from quantum.manager import QuantumManager
from quantum.manager import validate_post_plugin_load
from quantum.manager import validate_pre_plugin_load
from quantum.openstack.common import log as logging
from quantum.plugins.common import constants
from quantum.tests import base
from quantum.tests.unit import dummy_plugin


LOG = logging.getLogger(__name__)
DB_PLUGIN_KLASS = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'
ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class MultiServiceCorePlugin(object):
    supported_extension_aliases = ['lbaas', 'dummy']


class QuantumManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(QuantumManagerTestCase, self).setUp()
        args = ['--config-file', etcdir('quantum.conf.test')]
        # If test_config specifies some config-file, use it, as well
        config.parse(args=args)
        QuantumManager._instance = None
        self.addCleanup(cfg.CONF.reset)
        self.useFixture(
            fixtures.MonkeyPatch('quantum.manager.QuantumManager._instance'))

    def test_service_plugin_is_loaded(self):
        cfg.CONF.set_override("core_plugin",
                              test_config.get('plugin_name_v2',
                                              DB_PLUGIN_KLASS))
        cfg.CONF.set_override("service_plugins",
                              ["quantum.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        mgr = QuantumManager.get_instance()
        plugin = mgr.get_service_plugins()[constants.DUMMY]

        self.assertTrue(
            isinstance(plugin,
                       (dummy_plugin.DummyServicePlugin, types.ClassType)),
            "loaded plugin should be of type QuantumDummyPlugin")

    def test_multiple_plugins_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              ["quantum.tests.unit.dummy_plugin."
                               "DummyServicePlugin",
                               "quantum.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        cfg.CONF.set_override("core_plugin",
                              test_config.get('plugin_name_v2',
                                              DB_PLUGIN_KLASS))
        self.assertRaises(ValueError, QuantumManager.get_instance)

    def test_service_plugin_conflicts_with_core_plugin(self):
        cfg.CONF.set_override("service_plugins",
                              ["quantum.tests.unit.dummy_plugin."
                               "DummyServicePlugin"])
        cfg.CONF.set_override("core_plugin",
                              "quantum.tests.unit.test_quantum_manager."
                              "MultiServiceCorePlugin")
        self.assertRaises(ValueError, QuantumManager.get_instance)

    def test_core_plugin_supports_services(self):
        cfg.CONF.set_override("core_plugin",
                              "quantum.tests.unit.test_quantum_manager."
                              "MultiServiceCorePlugin")
        mgr = QuantumManager.get_instance()
        svc_plugins = mgr.get_service_plugins()
        self.assertEqual(3, len(svc_plugins))
        self.assertIn(constants.CORE, svc_plugins.keys())
        self.assertIn(constants.LOADBALANCER, svc_plugins.keys())
        self.assertIn(constants.DUMMY, svc_plugins.keys())

    def test_post_plugin_validation(self):
        self.assertIsNone(validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        self.assertIsNone(validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', 0)
        self.assertIsNotNone(validate_post_plugin_load())
        cfg.CONF.set_override('dhcp_agents_per_network', -1)
        self.assertIsNotNone(validate_post_plugin_load())

    def test_pre_plugin_validation(self):
        self.assertIsNotNone(validate_pre_plugin_load())
        cfg.CONF.set_override('core_plugin', 'dummy.plugin')
        self.assertIsNone(validate_pre_plugin_load())
