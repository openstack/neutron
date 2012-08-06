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


"""Unittest runner for Nicira NVP plugin

This file should be run from the top dir in the quantum directory

To run all tests::
    PLUGIN_DIR=quantum/plugins/nicira ./run_tests.sh
"""

import os
import sys

import mock
from nose import config
from nose import core

CONFIG_FILE_OPT = "--config-file"
NICIRA_PATH = "quantum/plugins/nicira/nicira_nvp_plugin"

sys.path.append(os.getcwd())
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.abspath(NICIRA_PATH))

from quantum.common.test_lib import run_tests, test_config
from quantum.openstack.common import cfg
import quantum.tests.unit
from quantum import version

from tests import fake_nvpapiclient

if __name__ == '__main__':
    exit_status = False
    do_mock = False
    # remove the value
    test_config['config_files'] = []

    # if a single test case was specified,
    # we should only invoked the tests once
    invoke_once = len(sys.argv) > 1
    # this will allow us to pass --config-file to run_tests.sh for
    # running the unit tests against a real backend
    # if --config-file has been specified, remove it from sys.argv
    # otherwise nose will complain
    while CONFIG_FILE_OPT in sys.argv:
        test_config['config_files'].append(
            sys.argv.pop(sys.argv.index(CONFIG_FILE_OPT) + 1))
        # and the option itself
        sys.argv.remove(CONFIG_FILE_OPT)

    # if no config file available, inject one for fake backend tests
    if not test_config.get('config_files'):
        do_mock = True
        test_config['config_files'] = [os.path.abspath('%s/tests/nvp.ini.test'
                                                       % NICIRA_PATH)]

    test_config['plugin_name_v2'] = "QuantumPlugin.NvpPluginV2"
    cwd = os.getcwd()
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      includeExe=True,
                      traverseNamespace=True,
                      plugins=core.DefaultPluginManager())
    c.configureWhere(quantum.tests.unit.__path__)

    # patch nvpapi client if not running against "real" back end
    if do_mock:
        fc = fake_nvpapiclient.FakeClient(os.path.abspath('%s/tests'
                                                          % NICIRA_PATH))
        mock_nvpapi = mock.patch('NvpApiClient.NVPApiHelper', autospec=True)
        instance = mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request

    exit_status = run_tests(c)
    if invoke_once:
        sys.exit(0)

    os.chdir(cwd)

    working_dir = os.path.abspath(NICIRA_PATH)
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    exit_status = exit_status or run_tests(c)

    # restore original nvpapi client (probably pleonastic here)
    if do_mock:
        mock_nvpapi.stop()
    sys.exit(exit_status)
