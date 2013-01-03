# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
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

import types
import unittest2

from quantum.common import config
from quantum.common.test_lib import test_config
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.plugins.common import constants
from quantum.plugins.services.dummy.dummy_plugin import QuantumDummyPlugin


LOG = logging.getLogger(__name__)
DB_PLUGIN_KLASS = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'


class QuantumManagerTestCase(unittest2.TestCase):
    def setUp(self):
        super(QuantumManagerTestCase, self).setUp()

    def tearDown(self):
        unittest2.TestCase.tearDown(self)
        cfg.CONF.reset()
        QuantumManager._instance = None

    def test_service_plugin_is_loaded(self):
        cfg.CONF.set_override("core_plugin",
                              test_config.get('plugin_name_v2',
                                              DB_PLUGIN_KLASS))
        cfg.CONF.set_override("service_plugins",
                              ["quantum.plugins.services."
                               "dummy.dummy_plugin.QuantumDummyPlugin"])
        QuantumManager._instance = None
        mgr = QuantumManager.get_instance()
        plugin = mgr.get_service_plugins()[constants.DUMMY]

        self.assertTrue(
            isinstance(plugin,
                       (QuantumDummyPlugin, types.ClassType)),
            "loaded plugin should be of type QuantumDummyPlugin")

    def test_multiple_plugins_specified_for_service_type(self):
        cfg.CONF.set_override("service_plugins",
                              ["quantum.plugins.services."
                               "dummy.dummy_plugin.QuantumDummyPlugin",
                               "quantum.plugins.services."
                               "dummy.dummy_plugin.QuantumDummyPlugin"])
        QuantumManager._instance = None

        try:
            QuantumManager.get_instance().get_service_plugins()
            self.assertTrue(False,
                            "Shouldn't load multiple plugins "
                            "for the same type")
        except Exception as e:
            LOG.debug(str(e))
