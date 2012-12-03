# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

import inspect
import logging
import mock
import os
import webtest

from quantum.api.extensions import PluginAwareExtensionManager
from quantum.api.v2 import router
from quantum.common import config
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_api_v2


LOG = logging.getLogger(__name__)


def curdir(*p):
    return os.path.join(os.path.dirname(__file__), *p)


class APIv2TestCase(test_api_v2.APIv2TestCase):

    def setUp(self):
        plugin = 'quantum.plugins.cisco.network_plugin.PluginV2'
        # Ensure 'stale' patched copies of the plugin are never returned
        QuantumManager._instance = None
        # Ensure existing ExtensionManager is not used
        PluginAwareExtensionManager._instance = None
        # Create the default configurations
        args = ['--config-file', curdir('quantumv2.conf.cisco.test')]
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        api = router.APIRouter()
        self.api = webtest.TestApp(api)
        LOG.debug("%s.%s.%s done" % (__name__, self.__class__.__name__,
                                     inspect.stack()[0][3]))


class JSONV2TestCase(APIv2TestCase, test_api_v2.JSONV2TestCase):

    pass
