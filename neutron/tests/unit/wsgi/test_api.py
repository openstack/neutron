# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import importlib
import sys
from unittest import mock

from neutron import server
from neutron.server import api
from neutron.tests import base


class TestWsgiApi(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        sys.modules.pop('neutron.wsgi.api', None)
        self.addCleanup(sys.modules.pop, 'neutron.wsgi.api', None)

    def test_application_loaded(self):
        fake_app = mock.sentinel.wsgi_app
        with mock.patch.object(
                server, 'boot_server', return_value=fake_app) as mock_boot:
            wsgi_api = importlib.import_module('neutron.wsgi.api')

        self.assertEqual(fake_app, wsgi_api.application)
        mock_boot.assert_called_once_with(api.api_server, prog='neutron-api')

    def test_keyboard_interrupt_propagates(self):
        with mock.patch.object(
                server, 'boot_server', side_effect=KeyboardInterrupt):
            self.assertRaises(
                KeyboardInterrupt, importlib.import_module, 'neutron.wsgi.api')

        self.assertNotIn('neutron.wsgi.api', sys.modules)

    def test_none_application_raises_runtime_error(self):
        with mock.patch.object(server, 'boot_server', return_value=None):
            self.assertRaises(
                RuntimeError, importlib.import_module, 'neutron.wsgi.api')

        self.assertNotIn('neutron.wsgi.api', sys.modules)
