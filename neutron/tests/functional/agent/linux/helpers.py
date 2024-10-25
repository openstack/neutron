# Copyright (c) 2014 Red Hat, Inc.
# All Rights Reserved.
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
import multiprocessing
import os
import time

import fixtures

from neutron.agent.linux import utils
from neutron.tests import tools


class RecursivePermDirFixture(fixtures.Fixture):
    """Ensure at least perms permissions on directory and ancestors."""

    def __init__(self, directory, perms):
        super().__init__()
        self.directory = directory
        self.least_perms = perms

    def _setUp(self):
        previous_directory = None
        current_directory = self.directory
        while previous_directory != current_directory:
            perms = os.stat(current_directory).st_mode
            if perms & self.least_perms != self.least_perms:
                os.chmod(current_directory, perms | self.least_perms)
            previous_directory = current_directory
            current_directory = os.path.dirname(current_directory)


class AdminDirFixture(fixtures.Fixture):
    """Handle directory create/delete with admin permissions required"""

    def __init__(self, directory):
        super().__init__()
        self.directory = directory

    def _setUp(self):
        # NOTE(cbrandily): Ensure we will not delete a directory existing
        # before test run during cleanup.
        if os.path.exists(self.directory):
            tools.fail('%s already exists' % self.directory)

        create_cmd = ['mkdir', '-p', self.directory]
        delete_cmd = ['rm', '-r', self.directory]
        utils.execute(create_cmd, run_as_root=True)
        self.addCleanup(utils.execute, delete_cmd, run_as_root=True)


class SleepyProcessFixture(fixtures.Fixture):
    """Process fixture to perform time.sleep for a given number of seconds."""

    def __init__(self, timeout=60):
        super().__init__()
        self.timeout = timeout

    @staticmethod
    def yawn(seconds):
        time.sleep(seconds)

    def _setUp(self):
        self.process = multiprocessing.Process(target=self.yawn,
                                               args=[self.timeout])
        self.process.start()
        self.addCleanup(self.destroy)

    def destroy(self):
        self.process.terminate()

    @property
    def pid(self):
        return self.process.pid
