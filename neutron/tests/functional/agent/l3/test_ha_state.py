# Copyright (c) 2026 OpenStack Foundation
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
from unittest import mock

from neutron.agent.common import utils
from neutron.agent.l3 import ha_state
from neutron.tests.functional import base


class TestHaState(base.BaseSudoTestCase):

    def test_write_ha_state_file(self):
        state_path = self.get_temp_file_path('state')
        ha_state.write_ha_state_file(state_path, 'backup')
        with open(state_path) as state_file:
            self.assertEqual('backup', state_file.read())

    def test_write_ha_state_file_removes_root_owned_file(self):
        conf_dir = self.get_default_temp_dir().path
        state_path = os.path.join(conf_dir, ha_state.HA_STATE_FILENAME)
        with open(state_path, 'w') as state_file:
            state_file.write('primary')
        utils.execute(
            ['chown', 'root:root', state_path],
            run_as_root=True, privsep_exec=True)
        utils.execute(
            ['chmod', '600', state_path],
            run_as_root=True, privsep_exec=True)

        ha_state.write_ha_state_file(state_path, 'backup')

        with open(state_path) as state_file:
            self.assertEqual('backup', state_file.read())
        self.assertEqual(os.getuid(), os.stat(state_path).st_uid)

    @mock.patch('os.geteuid', return_value=0)
    def test_prepare_ha_state_path_fixes_ownership(self, mock_geteuid):
        conf_dir = self.get_default_temp_dir().path
        state_path = ha_state.get_ha_state_path(conf_dir)
        with open(state_path, 'w') as state_file:
            state_file.write('primary')
        utils.execute(
            ['chown', 'root:root', state_path],
            run_as_root=True, privsep_exec=True)

        ha_state.prepare_ha_state_path(
            state_path, os.getuid(), os.getgid())

        self.assertEqual(os.getuid(), os.stat(state_path).st_uid)
        self.assertEqual(os.getgid(), os.stat(state_path).st_gid)

    def test_prepare_ha_state_path_skipped_without_root(self):
        conf_dir = self.get_default_temp_dir().path
        state_path = ha_state.get_ha_state_path(conf_dir)
        with open(state_path, 'w') as state_file:
            state_file.write('primary')
        utils.execute(
            ['chown', 'root:root', state_path],
            run_as_root=True, privsep_exec=True)

        with mock.patch('os.geteuid', return_value=1000):
            ha_state.prepare_ha_state_path(
                state_path, os.getuid(), os.getgid())

        self.assertEqual(0, os.stat(state_path).st_uid)
