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

import fixtures
from neutron_lib.utils import runtime
from oslo_log import log as logging
from oslo_utils import fileutils


LOG = logging.getLogger(__name__)
MAX_ATTEMPTS = 100
TMP_DIR = '/tmp/neutron_exclusive_resources/'


class ExclusiveResource(fixtures.Fixture):
    def __init__(self, resource_name, allocator_function, validator=None):
        self.ra = ResourceAllocator(
            resource_name, allocator_function, validator)

    def _setUp(self):
        self.resource = self.ra.allocate()
        self.addCleanup(self.ra.release, self.resource)


class ResourceAllocator(object):
    """ResourceAllocator persists cross-process allocations of a resource.

    Allocations are persisted to a file determined by the 'resource_name',
    and are allocated via an allocator_function. The public interface
    (allocate and release) are guarded by a file lock. The intention
    is to allow atomic, cross-process allocation of shared resources
    such as ports and IP addresses. For usages of this class, please see
    ExclusiveIPAddress and its functional tests.

    Note that this class doesn't maintain in-memory state, and multiple
    instances of it may be initialized and used. A pool of resources
    is identified solely by the 'resource_name' argument.
    """
    def __init__(self, resource_name, allocator_function, validator=None):
        """Initialize a resource allocator.

        :param resource_name: A unique identifier for a pool of resources.
        :param allocator_function: A function with no parameters that generates
                                   a resource.
        :param validator: An optional function that accepts a resource and an
                          existing pool and returns if the generated resource
                          is valid.
        """
        def is_valid(new_resource, allocated_resources):
            return new_resource not in allocated_resources

        self._allocator_function = allocator_function
        self._state_file_path = os.path.join(TMP_DIR, resource_name)
        self._validator = validator if validator else is_valid
        self._resource_name = resource_name

    @runtime.synchronized('resource_allocator', external=True,
                          lock_path='/tmp')
    def allocate(self):
        allocations = self._get_allocations()

        for i in range(MAX_ATTEMPTS):
            resource = str(self._allocator_function())
            if self._validator(resource, allocations):
                allocations.add(resource)
                self._write_allocations(allocations)
                LOG.debug('Allocated exclusive resource %s of type %s. '
                          'The allocations are now: %s',
                          resource, self._resource_name, allocations)
                return resource

        raise ValueError(
            'Could not allocate a new resource of type %s from pool %s' %
            (self._resource_name, allocations))

    @runtime.synchronized('resource_allocator', external=True,
                          lock_path='/tmp')
    def release(self, resource):
        allocations = self._get_allocations()
        allocations.remove(resource)
        if allocations:
            self._write_allocations(allocations)
        else:  # Clean up the file if we're releasing the last allocation
            os.remove(self._state_file_path)
        LOG.debug('Released exclusive resource %s of type %s. The allocations '
                  'are now: %s',
                  resource, self._resource_name, allocations)

    def _get_allocations(self):
        fileutils.ensure_tree(TMP_DIR, mode=0o755)

        try:
            with open(self._state_file_path, 'r') as allocations_file:
                contents = allocations_file.read()
        except IOError:
            contents = None

        # If the file was empty, we want to return an empty set, not {''}
        return set(contents.split(',')) if contents else set()

    def _write_allocations(self, allocations):
        with open(self._state_file_path, 'w') as allocations_file:
            allocations_file.write(','.join(allocations))
