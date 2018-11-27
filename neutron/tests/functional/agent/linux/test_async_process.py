# Copyright 2013 Red Hat, Inc.
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

import eventlet
import six

from neutron._i18n import _
from neutron.agent.common import async_process
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests.functional import base


class AsyncProcessTestFramework(base.BaseLoggingTestCase):

    def setUp(self):
        super(AsyncProcessTestFramework, self).setUp()
        self.test_file_path = self.get_temp_file_path('test_async_process.tmp')
        self.data = [six.text_type(x) for x in range(4)]
        with open(self.test_file_path, 'w') as f:
            f.writelines('%s\n' % item for item in self.data)

    def _check_stdout(self, proc):
        # Ensure that all the output from the file is read
        output = []
        while output != self.data:
            new_output = list(proc.iter_stdout())
            if new_output:
                output += new_output
            eventlet.sleep(0.01)


class TestAsyncProcess(AsyncProcessTestFramework):
    def _safe_stop(self, proc):
        try:
            proc.stop()
        except async_process.AsyncProcessException:
            pass

    def test_stopping_async_process_lifecycle(self):
        proc = async_process.AsyncProcess(['tail', '-f',
                                           self.test_file_path])
        self.addCleanup(self._safe_stop, proc)
        proc.start(block=True)
        self._check_stdout(proc)
        proc.stop(block=True)

        # Ensure that the process and greenthreads have stopped
        proc._process.wait()
        self.assertEqual(proc._process.returncode, -9)
        for watcher in proc._watchers:
            watcher.wait()

    def test_async_process_respawns(self):
        proc = async_process.AsyncProcess(['tail', '-f',
                                           self.test_file_path],
                                          respawn_interval=0)
        self.addCleanup(self._safe_stop, proc)
        proc.start()

        # Ensure that the same output is read twice
        self._check_stdout(proc)
        pid = proc.pid
        utils.execute(['kill', '-9', pid])
        common_utils.wait_until_true(
            lambda: proc.is_active() and pid != proc.pid,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Async process didn't respawn")))
        self._check_stdout(proc)
