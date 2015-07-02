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
import os

import fixtures


class RecursivePermDirFixture(fixtures.Fixture):
    """Ensure at least perms permissions on directory and ancestors."""

    def __init__(self, directory, perms):
        super(RecursivePermDirFixture, self).__init__()
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
