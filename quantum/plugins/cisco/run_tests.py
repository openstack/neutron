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


"""
Unittest runner for quantum Cisco plugin

export PLUGIN_DIR=quantum/plugins/cisco
./run_tests.sh -N
"""

import os
import sys

from nose import config

sys.path.append(os.getcwd())
sys.path.append(os.path.dirname(__file__))

from quantum.common.test_lib import run_tests, test_config


def main():

    test_config['plugin_name'] = "l2network_plugin.L2Network"
    cwd = os.getcwd()
    os.chdir(cwd)
    working_dir = os.path.abspath("quantum/plugins/cisco")
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    sys.exit(run_tests(c))

if __name__ == '__main__':
    main()
