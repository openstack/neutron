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

from neutron.cmd import server as cmd_server
from neutron import server
from neutron.server import ovn_maintenance
from neutron.server import periodic
from neutron.server import rpc
from neutron.tests import base


class TestCmdServer(base.BaseTestCase):

    def test_main_ovn_maintenance(self):
        with mock.patch.object(
                server, 'boot_server',
                return_value=mock.sentinel.ret) as mock_boot:
            res = cmd_server.main_ovn_maintenance()

        self.assertEqual(mock.sentinel.ret, res)
        mock_boot.assert_called_once_with(
            ovn_maintenance.ovn_maintenance_worker)

    def test_main_rpc(self):
        with mock.patch.object(server, 'boot_server') as mock_boot:
            cmd_server.main_rpc()

        mock_boot.assert_called_once_with(rpc.rpc_server)

    def test_main_periodic(self):
        with mock.patch.object(server, 'boot_server') as mock_boot:
            cmd_server.main_periodic()

        mock_boot.assert_called_once_with(periodic.periodic_workers)

    def test_keyboard_interrupt_handled(self):
        with mock.patch.object(
                server, 'boot_server', side_effect=KeyboardInterrupt):
            self.assertIsNone(cmd_server.main_ovn_maintenance())
            self.assertIsNone(cmd_server.main_rpc())
            self.assertIsNone(cmd_server.main_periodic())
