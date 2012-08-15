# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import inspect
import logging
import mock
import os

from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.db import api as db
from quantum.manager import QuantumManager
from quantum.plugins.cisco.db import network_models_v2
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.wsgi import JSONDeserializer

LOG = logging.getLogger(__name__)


def curdir(*p):
    return os.path.join(os.path.dirname(__file__), *p)


class NetworkPluginV2TestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    def setUp(self):
        db._ENGINE = None
        db._MAKER = None
        QuantumManager._instance = None
        self._tenant_id = 'test-tenant'

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        plugin = 'quantum.plugins.cisco.network_plugin.PluginV2'
        # Create the default configurations
        args = ['--config-file', curdir('quantumv2.conf.cisco.test')]
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")
        self.api = APIRouter()
        LOG.debug("%s.%s.%s done" % (__name__, self.__class__.__name__,
                                     inspect.stack()[0][3]))

    def tearDown(self):
        db.clear_db(network_models_v2.model_base.BASEV2)
        db._ENGINE = None
        db._MAKER = None

        cfg.CONF.reset()


class TestV2HTTPResponse(NetworkPluginV2TestCase,
                         test_db_plugin.TestV2HTTPResponse):

    pass


class TestPortsV2(NetworkPluginV2TestCase, test_db_plugin.TestPortsV2):

    pass


class TestNetworksV2(NetworkPluginV2TestCase, test_db_plugin.TestNetworksV2):

    pass


class TestSubnetsV2(NetworkPluginV2TestCase, test_db_plugin.TestSubnetsV2):

    pass
