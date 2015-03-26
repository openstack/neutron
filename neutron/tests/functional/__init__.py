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

"""
Previously, running 'tox -e dsvm-functional' simply ran a normal test discovery
of the ./neutron/tests/functional tree. In order to save gate resources, we
decided to forgo adding a new gate job specifically for the full-stack
framework, and instead discover tests that are present in
./neutron/tests/fullstack.

In short, running 'tox -e dsvm-functional' now runs both functional tests and
full-stack tests, and this code allows for the test discovery needed.
"""

import os
import unittest


def _discover(loader, path, pattern):
    return loader.discover(path, pattern=pattern, top_level_dir=".")


def load_tests(_, tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(tests)

    loader = unittest.loader.TestLoader()
    suite.addTests(_discover(loader, "./neutron/tests/functional", pattern))

    if os.getenv('OS_RUN_FULLSTACK') == '1':
        suite.addTests(_discover(loader, "./neutron/tests/fullstack", pattern))

    return suite
