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

from unittest import mock

from neutron.common import config
from neutron import server
from neutron.tests import base


class TestBootServer(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_init_conf = mock.patch.object(
            server, '_init_configuration').start()
        self.mock_setup_gmr = mock.patch.object(config, 'setup_gmr').start()

    def test_boot_server(self):
        server_func = mock.Mock(return_value=mock.sentinel.app)
        res = server.boot_server(server_func, prog='neutron-api')

        self.assertEqual(mock.sentinel.app, res)
        self.mock_init_conf.assert_called_once_with(prog='neutron-api')
        self.mock_setup_gmr.assert_called_once_with()
        server_func.assert_called_once_with()

    def test_boot_server_propagates_keyboard_interrupt(self):
        server_func = mock.Mock(side_effect=KeyboardInterrupt)
        self.assertRaises(KeyboardInterrupt, server.boot_server, server_func)

    def test_boot_server_runtime_error_exits(self):
        server_func = mock.Mock(side_effect=RuntimeError('boom'))
        self.assertRaises(SystemExit, server.boot_server, server_func)
