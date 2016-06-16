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

import eventlet
import os.path
import stat
import testtools

from neutron.common import utils
from neutron.tests import base


class TestReplaceFile(base.BaseTestCase):
    def setUp(self):
        super(TestReplaceFile, self).setUp()
        temp_dir = self.get_default_temp_dir().path
        self.file_name = os.path.join(temp_dir, "new_file")
        self.data = "data to copy"

    def _verify_result(self, file_mode):
        self.assertTrue(os.path.exists(self.file_name))
        with open(self.file_name) as f:
            content = f.read()
        self.assertEqual(self.data, content)
        mode = os.stat(self.file_name).st_mode
        self.assertEqual(file_mode, stat.S_IMODE(mode))

    def test_replace_file_default_mode(self):
        file_mode = 0o644
        utils.replace_file(self.file_name, self.data)
        self._verify_result(file_mode)

    def test_replace_file_custom_mode(self):
        file_mode = 0o722
        utils.replace_file(self.file_name, self.data, file_mode)
        self._verify_result(file_mode)

    def test_replace_file_custom_mode_twice(self):
        file_mode = 0o722
        utils.replace_file(self.file_name, self.data, file_mode)
        self.data = "new data to copy"
        file_mode = 0o777
        utils.replace_file(self.file_name, self.data, file_mode)
        self._verify_result(file_mode)


class TestWaitUntilTrue(base.BaseTestCase):
    def test_wait_until_true_predicate_succeeds(self):
        utils.wait_until_true(lambda: True)

    def test_wait_until_true_predicate_fails(self):
        with testtools.ExpectedException(eventlet.timeout.Timeout):
            utils.wait_until_true(lambda: False, 2)
