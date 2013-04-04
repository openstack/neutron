#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


"""Unittest runner for quantum

To run all test::
    python run_tests.py

To run all unit tests::
    python run_tests.py unit

To run all functional tests::
    python run_tests.py functional

To run a single unit test::
    python run_tests.py unit.test_stores:TestSwiftBackend.test_get

To run a single functional test::
    python run_tests.py functional.test_service:TestController.test_create

To run a single unit test module::
    python run_tests.py unit.test_stores

To run a single functional test module::
    python run_tests.py functional.test_stores
"""

import os
import sys

from quantum.common.test_lib import run_tests
from nose import config
from nose import core

import quantum.tests.unit


def main():
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      includeExe=True,
                      traverseNamespace=True,
                      plugins=core.DefaultPluginManager())
    c.configureWhere(quantum.tests.unit.__path__)
    sys.exit(run_tests(c))

if __name__ == "__main__":
    main()
