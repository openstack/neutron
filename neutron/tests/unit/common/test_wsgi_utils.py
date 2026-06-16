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
from unittest import mock

from neutron.common import wsgi_utils
from neutron.tests import base


class TestGetApiWorkerCount(base.BaseTestCase):

    def test_get_api_worker_count_with_uwsgi(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.numproc = 4
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod):
            self.assertEqual(4, wsgi_utils.get_api_worker_count())

    def test_get_api_worker_count_without_uwsgi(self):
        with mock.patch.dict('sys.modules', uwsgi=None):
            self.assertIsNone(wsgi_utils.get_api_worker_count())


class TestGetApiWorkerId(base.BaseTestCase):

    def test_get_api_worker_id_with_uwsgi(self):
        uwsgi_mod = types.ModuleType('uwsgi')
        uwsgi_mod.worker_id = mock.Mock(return_value=3)
        with mock.patch.dict('sys.modules', uwsgi=uwsgi_mod):
            self.assertEqual(3, wsgi_utils.get_api_worker_id())

    def test_get_api_worker_id_without_uwsgi(self):
        with mock.patch.dict('sys.modules', uwsgi=None):
            self.assertIsNone(wsgi_utils.get_api_worker_id())


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
