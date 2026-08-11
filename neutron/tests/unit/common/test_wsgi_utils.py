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
import tempfile
import types
from unittest import mock

from neutron.common import wsgi_utils
from neutron.tests import base


class TestGetApiWorkerCount(base.BaseTestCase):

    def test_get_api_worker_count_with_uwsgi(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.numproc = 4
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod):
            self.assertEqual(4, wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_with_mod_wsgi(self):
        mod_wsgi_mod = types.ModuleType('mod_wsgi')
        mod_wsgi_mod.maximum_processes = 6
        with mock.patch.dict('sys.modules', uwsgi=None,
                             mod_wsgi=mod_wsgi_mod):
            self.assertEqual(6, wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_no_wsgi_server(self):
        with mock.patch.dict('sys.modules', uwsgi=None, mod_wsgi=None):
            self.assertIsNone(wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_uwsgi_takes_precedence(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.numproc = 4
        mod_wsgi_mod = types.ModuleType('mod_wsgi')
        mod_wsgi_mod.maximum_processes = 6
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod,
                             mod_wsgi=mod_wsgi_mod):
            self.assertEqual(4, wsgi_utils.get_api_worker_count())


class TestGetStartTime(base.BaseTestCase):

    def test_get_start_time_with_uwsgi(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.opt = {'start-time': b'1700000000'}
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod):
            self.assertEqual(1700000000, wsgi_utils.get_start_time())

    def test_get_start_time_without_uwsgi(self):
        with mock.patch.dict('sys.modules', uwsgi=None):
            self.assertIsNone(wsgi_utils.get_start_time())

    def test_get_start_time_without_uwsgi_with_default(self):
        with mock.patch.dict('sys.modules', uwsgi=None):
            self.assertEqual(42, wsgi_utils.get_start_time(default=42))

    def test_get_start_time_no_opt_value(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.opt = {}
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod):
            self.assertIsNone(wsgi_utils.get_start_time())


class TestElectFirstWsgiWorker(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        wsgi_utils._first_worker_result = None
        self.addCleanup(self._reset_first_worker_result)

    @staticmethod
    def _reset_first_worker_result():
        wsgi_utils._first_worker_result = None

    def test_first_caller_wins(self):
        flag_path = os.path.join(tempfile.gettempdir(),
                                 'neutron_first_worker101')
        self.addCleanup(self._remove_flag, flag_path)
        with mock.patch('os.getppid', return_value=101):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())
            self.assertTrue(os.path.exists(flag_path))

    def test_second_caller_loses(self):
        flag_path = os.path.join(tempfile.gettempdir(),
                                 'neutron_first_worker102')
        self.addCleanup(self._remove_flag, flag_path)
        with mock.patch('os.getppid', return_value=102):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

        wsgi_utils._first_worker_result = None
        with mock.patch('os.getppid', return_value=102):
            self.assertFalse(wsgi_utils._elect_first_wsgi_worker())

    def test_result_is_cached(self):
        flag_path = os.path.join(tempfile.gettempdir(),
                                 'neutron_first_worker103')
        self.addCleanup(self._remove_flag, flag_path)
        with mock.patch('os.getppid', return_value=103):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

    def test_different_ppid_resets_election(self):
        flag_path_1 = os.path.join(tempfile.gettempdir(),
                                   'neutron_first_worker104')
        flag_path_2 = os.path.join(tempfile.gettempdir(),
                                   'neutron_first_worker105')
        self.addCleanup(self._remove_flag, flag_path_1)
        self.addCleanup(self._remove_flag, flag_path_2)

        with mock.patch('os.getppid', return_value=104):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

        wsgi_utils._first_worker_result = None
        with mock.patch('os.getppid', return_value=105):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

    @staticmethod
    def _remove_flag(path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
