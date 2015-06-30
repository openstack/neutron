# Copyright 2014 Red Hat, Inc.
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

from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional import base


class TestRootHelperProcess(base.BaseSudoTestCase):

    def test_process_read_write(self):
        proc = helpers.RootHelperProcess(['tee'])
        proc.writeline('foo')
        output = proc.read_stdout(helpers.READ_TIMEOUT)
        self.assertEqual('foo\n', output)

    def test_process_kill(self):
        with self.assert_max_execution_time(100):
            proc = helpers.RootHelperProcess(['tee'])
            proc.kill()
            proc.wait()
            # sudo returns 137 and
            # rootwrap returns 247 (bug 1364822)
            self.assertIn(proc.returncode, [137, 247])
