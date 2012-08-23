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

import os

import mock

import quantum.common.test_lib as test_lib
from quantum.plugins.nicira.nicira_nvp_plugin.tests import fake_nvpapiclient
import quantum.tests.unit.test_db_plugin as test_plugin

NICIRA_PATH = '../../plugins/nicira/nicira_nvp_plugin'
NICIRA_PKG_PATH = 'quantum.plugins.nicira.nicira_nvp_plugin'


class NiciraPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.QuantumPlugin.NvpPluginV2' % NICIRA_PKG_PATH)

    def setUp(self):
        config_file_path = os.path.abspath('%s/tests/nvp.ini.test'
                                           % NICIRA_PATH)
        test_lib.test_config['config_files'] = [config_file_path]
        # mock nvp api client
        fc = fake_nvpapiclient.FakeClient(os.path.abspath('%s/tests'
                                                          % NICIRA_PATH))
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        super(NiciraPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(NiciraPluginV2TestCase, self).tearDown()
        self.mock_nvpapi.stop()


class TestNiciraBasicGet(test_plugin.TestBasicGet, NiciraPluginV2TestCase):
    pass


class TestNiciraV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                               NiciraPluginV2TestCase):
    pass


class TestNiciraPortsV2(test_plugin.TestPortsV2, NiciraPluginV2TestCase):
    pass


class TestNiciraNetworksV2(test_plugin.TestNetworksV2,
                           NiciraPluginV2TestCase):
    pass


class TestNiciraSubnetsV2(test_plugin.TestSubnetsV2, NiciraPluginV2TestCase):
    pass
