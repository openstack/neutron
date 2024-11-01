# Copyright 2016 Red Hat, Inc.
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

from neutron_lib.utils import helpers
import testtools

from neutron.tests.common.exclusive_resources import resource_allocator
from neutron.tests.functional import base


def safe_remove_file(file_path):
    try:
        os.remove(file_path)
    except OSError:
        pass


class TestResourceAllocator(base.BaseLoggingTestCase):
    def setUp(self):
        super().setUp()
        self.ra = resource_allocator.ResourceAllocator(
            helpers.get_random_string(6), lambda: 42)
        self.addCleanup(safe_remove_file, self.ra._state_file_path)

    def test_allocate_and_release(self):
        # Assert that we can allocate a resource
        resource = self.ra.allocate()
        self.assertEqual('42', resource)

        # Assert that we cannot allocate any more resources, since we're
        # using an allocator that always returns the same value
        with testtools.ExpectedException(ValueError):
            self.ra.allocate()

        # Assert that releasing the resource and allocating again works
        self.ra.release(resource)
        resource = self.ra.allocate()
        self.assertEqual('42', resource)

    def test_file_manipulation(self):
        # The file should not be created until the first allocation
        self.assertFalse(os.path.exists(self.ra._state_file_path))
        resource = self.ra.allocate()
        self.assertTrue(os.path.exists(self.ra._state_file_path))

        # Releasing the last resource should delete the file
        self.ra.release(resource)
        self.assertFalse(os.path.exists(self.ra._state_file_path))
