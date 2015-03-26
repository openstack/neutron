# Copyright 2015 Red Hat, Inc.
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

import neutron


def find_file(filename, path):
    """Find a file with name 'filename' located in 'path'."""
    for root, _, files in os.walk(path):
        if filename in files:
            return os.path.abspath(os.path.join(root, filename))


def find_sample_file(filename):
    """Find a file with name 'filename' located in the sample directory."""
    return find_file(
        filename,
        path=os.path.join(neutron.__path__[0], '..', 'etc'))
