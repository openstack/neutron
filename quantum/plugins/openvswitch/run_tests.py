#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack, LLC
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


"""Unittest runner for quantum OVS plugin

This file should be run from the top dir in the quantum directory

To run all test::
    python quantum/plugins/openvswitch/run_tests.py

To run all unit tests::
    python quantum/plugins/openvswitch/run_tests.py unit

To run all functional tests::
    python quantum/plugins/openvswitch/run_tests.py functional

To run a single unit test::
    python  quantum/plugins/openvswitch/run_tests.py \
        unit.test_stores:TestSwiftBackend.test_get

To run a single functional test::
    python  quantum/plugins/openvswitch/run_tests.py \
        functional.test_service:TestController.test_create

To run a single unit test module::
    python  quantum/plugins/openvswitch/run_tests.py unit.test_stores

To run a single functional test module::
    python quantum/plugins/openvswitch/run_tests.py functional.test_stores
"""

import gettext
import logging
import os
import unittest
import sys

from nose import config

sys.path.append(os.getcwd())

from quantum.common.test_lib import run_tests, test_config
from quantum.plugins.openvswitch.tests.test_vlan_map import VlanMapTest

if __name__ == '__main__':
    exit_status = False

    # if a single test case was specified,
    # we should only invoked the tests once
    invoke_once = len(sys.argv) > 1

    test_config['plugin_name'] = "quantum.plugins.openvswitch." + \
                "ovs_quantum_plugin.OVSQuantumPlugin"

    cwd = os.getcwd()

    working_dir = os.path.abspath("tests")
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    exit_status = run_tests(c)

    if invoke_once:
        sys.exit(0)

    os.chdir(cwd)

    working_dir = os.path.abspath("quantum/plugins/openvswitch/tests")
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    exit_status = exit_status or run_tests(c)

    sys.exit(exit_status)
