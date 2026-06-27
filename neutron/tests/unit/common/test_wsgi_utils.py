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


def _temp_path(prefix, ppid):
    return os.path.join(tempfile.gettempdir(), prefix + str(ppid))


def _remove_file(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


class TestWriteTempFile(base.BaseTestCase):

    def test_creates_file_returns_true(self):
        path = _temp_path('neutron_test_wt_', 301)
        self.addCleanup(_remove_file, path)
        with mock.patch('os.getppid', return_value=301):
            created, result_path = wsgi_utils._write_temp_file(
                'neutron_test_wt_', 'hello')
        self.assertTrue(created)
        self.assertEqual(path, result_path)
        with open(path) as f:
            self.assertEqual('hello', f.read())

    def test_existing_file_returns_false(self):
        path = _temp_path('neutron_test_wt_', 302)
        self.addCleanup(_remove_file, path)
        with mock.patch('os.getppid', return_value=302):
            wsgi_utils._write_temp_file('neutron_test_wt_', 'first')
            created, result_path = wsgi_utils._write_temp_file(
                'neutron_test_wt_', 'second')
        self.assertFalse(created)
        self.assertEqual(path, result_path)
        with open(path) as f:
            self.assertEqual('first', f.read())

    def test_returns_path_with_ppid(self):
        path = _temp_path('neutron_test_wt_', 303)
        self.addCleanup(_remove_file, path)
        with mock.patch('os.getppid', return_value=303):
            _, result_path = wsgi_utils._write_temp_file(
                'neutron_test_wt_', 'x')
        self.assertTrue(result_path.endswith('neutron_test_wt_303'))


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

    def test_get_api_worker_count_asgi_env(self):
        with mock.patch.dict('sys.modules', uwsgi=None, mod_wsgi=None), \
                mock.patch.dict(os.environ, {'ASGI_WORKERS': '3'}):
            self.assertEqual(3, wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_uwsgi_over_asgi(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.numproc = 4
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod), \
                mock.patch.dict(os.environ, {'ASGI_WORKERS': '3'}):
            self.assertEqual(4, wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_no_server_no_env(self):
        with mock.patch.dict('sys.modules', uwsgi=None, mod_wsgi=None), \
                mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(wsgi_utils.get_api_worker_count())


class TestGetStartTime(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self._orig_start_time = wsgi_utils._start_time
        wsgi_utils._start_time = None
        self._paths = []

    def tearDown(self):
        wsgi_utils._start_time = self._orig_start_time
        for path in self._paths:
            _remove_file(path)
        super().tearDown()

    def _track(self, ppid):
        path = _temp_path('neutron_start_time', ppid)
        self._paths.append(path)
        return path

    def test_first_worker_creates_file(self):
        path = self._track(401)
        with mock.patch('os.getppid', return_value=401), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700000000):
            result = wsgi_utils.get_start_time()
        self.assertEqual(1700000000, result)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            self.assertEqual('1700000000', f.read())

    def test_second_worker_reads_file(self):
        self._track(402)
        with mock.patch('os.getppid', return_value=402), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700000000):
            first = wsgi_utils.get_start_time()

        wsgi_utils._start_time = None
        with mock.patch('os.getppid', return_value=402), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1799999999):
            second = wsgi_utils.get_start_time()

        self.assertEqual(1700000000, first)
        self.assertEqual(1700000000, second)

    def test_cached_value_returned(self):
        self._track(403)
        with mock.patch('os.getppid', return_value=403), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700000000) as ts_mock:
            first = wsgi_utils.get_start_time()
            second = wsgi_utils.get_start_time()
        self.assertEqual(first, second)
        ts_mock.assert_called_once()

    def test_different_ppid_creates_new_file(self):
        path1 = self._track(404)
        path2 = self._track(405)
        with mock.patch('os.getppid', return_value=404), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700000000):
            first = wsgi_utils.get_start_time()

        wsgi_utils._start_time = None
        with mock.patch('os.getppid', return_value=405), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700099999):
            second = wsgi_utils.get_start_time()

        self.assertEqual(1700000000, first)
        self.assertEqual(1700099999, second)
        self.assertTrue(os.path.exists(path1))
        self.assertTrue(os.path.exists(path2))

    def test_raises_runtime_error_on_unreadable_file(self):
        with mock.patch.object(wsgi_utils, '_write_temp_file',
                               return_value=(False, '/bad/path')), \
                mock.patch.object(wsgi_utils.utils, 'datetime_to_ts',
                                  return_value=1700000000):
            self.assertRaises(RuntimeError, wsgi_utils.get_start_time)


class TestElectFirstWsgiWorker(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self._orig = wsgi_utils._first_worker_result
        wsgi_utils._first_worker_result = None

    def tearDown(self):
        wsgi_utils._first_worker_result = self._orig
        super().tearDown()

    def test_first_caller_wins(self):
        flag_path = _temp_path('neutron_first_worker', 501)
        self.addCleanup(_remove_file, flag_path)
        with mock.patch('os.getppid', return_value=501):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())
            self.assertTrue(os.path.exists(flag_path))

    def test_second_caller_loses(self):
        flag_path = _temp_path('neutron_first_worker', 502)
        self.addCleanup(_remove_file, flag_path)
        with mock.patch('os.getppid', return_value=502):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

        wsgi_utils._first_worker_result = None
        with mock.patch('os.getppid', return_value=502):
            self.assertFalse(wsgi_utils._elect_first_wsgi_worker())

    def test_result_is_cached(self):
        flag_path = _temp_path('neutron_first_worker', 503)
        self.addCleanup(_remove_file, flag_path)
        with mock.patch('os.getppid', return_value=503):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

    def test_different_ppid_resets_election(self):
        path1 = _temp_path('neutron_first_worker', 504)
        path2 = _temp_path('neutron_first_worker', 505)
        self.addCleanup(_remove_file, path1)
        self.addCleanup(_remove_file, path2)

        with mock.patch('os.getppid', return_value=504):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())

        wsgi_utils._first_worker_result = None
        with mock.patch('os.getppid', return_value=505):
            self.assertTrue(wsgi_utils._elect_first_wsgi_worker())
