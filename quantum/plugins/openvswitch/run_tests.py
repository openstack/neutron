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

To run all tests::
    PLUGIN_DIR=quantum/plugins/openvswitch ./run_tests.sh
"""

import gettext
import logging
import os
import unittest
import sys

from nose import config
from nose import core

sys.path.append(os.getcwd())
sys.path.append(os.path.dirname(__file__))


from quantum.api.api_common import OperationalStatus
from quantum.common.test_lib import run_tests, test_config
import quantum.tests.unit
from tests.unit.test_vlan_map import VlanMapTest

if __name__ == '__main__':
    exit_status = False

    # if a single test case was specified,
    # we should only invoked the tests once
    invoke_once = len(sys.argv) > 1

    test_config['plugin_name'] = "ovs_quantum_plugin.OVSQuantumPlugin"
    test_config['default_net_op_status'] = OperationalStatus.UP
    test_config['default_port_op_status'] = OperationalStatus.DOWN

    cwd = os.getcwd()
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      includeExe=True,
                      traverseNamespace=True,
                      plugins=core.DefaultPluginManager())
    c.configureWhere(quantum.tests.unit.__path__)
    exit_status = run_tests(c)

    if invoke_once:
        sys.exit(0)

    os.chdir(cwd)

    working_dir = os.path.abspath("quantum/plugins/openvswitch")
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    exit_status = exit_status or run_tests(c)

    sys.exit(exit_status)
