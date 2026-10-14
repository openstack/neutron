# Copyright 2023 Canonical
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

from unittest import mock

from neutron_lib import exceptions

from neutron.agent.linux import utils as agent_utils
from neutron.cmd import runtime_checks
from neutron.tests import base


class TestRuntimeChecks(base.BaseTestCase):

    def test_get_keepalived_version(self):
        exec_keepalived_version = ['', 'Keepalived v2.2.8 (04/04,2023)']
        with mock.patch.object(agent_utils, 'execute') as mock_exec:
            mock_exec.return_value = exec_keepalived_version
            keepalived_version = runtime_checks.get_keepalived_version()
            self.assertEqual(keepalived_version, (2, 2, 8))

    def test_get_keepalived_version_fail(self):
        with mock.patch.object(agent_utils, 'execute') as mock_exec:
            mock_exec.side_effect = (
                exceptions.ProcessExecutionError('', returncode=0))
            keepalived_version = runtime_checks.get_keepalived_version()
            self.assertFalse(keepalived_version)

    def _test_keepalived_bfd_support(self, config_options):
        exec_keepalived_version = [
            '', 'Keepalived v2.4.3 (07/20,2026)\n\n'
                'Copyright(C) 2001-2026 Alexandre Cassen\n\n'
                'configure options: --enable-bfd\n\n'
                'Config options:  %s\n\n'
                'System options:  VSYSLOG MEMFD_CREATE\n' % config_options]
        with mock.patch.object(agent_utils, 'execute') as mock_exec:
            mock_exec.return_value = exec_keepalived_version
            return runtime_checks.keepalived_bfd_support()

    def test_keepalived_bfd_support(self):
        self.assertTrue(self._test_keepalived_bfd_support(
            'NFTABLES LVS VRRP VRRP_AUTH JSON BFD SNMP_VRRP'))

    def test_keepalived_bfd_support_not_built(self):
        self.assertFalse(self._test_keepalived_bfd_support(
            'NFTABLES LVS VRRP VRRP_AUTH JSON SNMP_VRRP'))

    def test_keepalived_bfd_support_no_config_options(self):
        exec_keepalived_version = ['', 'Keepalived v1.3.9 (10/21,2017)\n']
        with mock.patch.object(agent_utils, 'execute') as mock_exec:
            mock_exec.return_value = exec_keepalived_version
            self.assertFalse(runtime_checks.keepalived_bfd_support())

    def test_keepalived_bfd_support_fail(self):
        with mock.patch.object(agent_utils, 'execute') as mock_exec:
            mock_exec.side_effect = (
                exceptions.ProcessExecutionError('', returncode=0))
            self.assertFalse(runtime_checks.keepalived_bfd_support())
