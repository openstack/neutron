# Copyright 2026 OpenStack Foundation
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

import subprocess
import sys

from neutron.tests import base

# Modules a privsep daemon imports when it serves neutron entrypoints.
PRIVILEGED_MODULES = (
    'neutron.privileged.agent.linux.ip_lib',
    'neutron.privileged.agent.linux.utils',
    'neutron.privileged.agent.linux.tc_lib',
    'neutron.privileged.agent.linux.ethtool',
    'neutron.privileged.agent.linux.devlink',
    'neutron.privileged.agent.linux.dhcp',
    'neutron.privileged.agent.linux.svd',
    'neutron.privileged.agent.ovsdb.native.helpers',
)
FORBIDDEN_MODULES = ('neutron.common.utils',)


class PrivilegedImportsTestCase(base.BaseTestCase):

    def test_privileged_modules_stay_lightweight(self):
        # Run in a fresh interpreter: the test process has already imported
        # most of neutron.
        code = ('import importlib, sys\n'
                'for m in %r:\n'
                '    importlib.import_module(m)\n'
                'print(",".join(m for m in %r if m in sys.modules))\n'
                % (PRIVILEGED_MODULES, FORBIDDEN_MODULES))
        cmd = [sys.executable, '-c', code]
        out = subprocess.check_output(cmd, text=True)  # noqa: S603
        self.assertEqual('', out.strip())
