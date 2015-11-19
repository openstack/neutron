# Copyright (c) 2015 IBM Corp.
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

import argparse
import logging
import sys

import fixtures
import mock
from neutronclient import shell as openstack_shell
import six
from testtools import matchers

from neutron.debug import shell as debug_shell
from neutron.tests import base


class ShellTest(base.BaseTestCase):

    def shell(self, argstr, check=False):
        with mock.patch.dict('os.environ', clear=True):
            with mock.patch('sys.stdout', new=six.moves.StringIO()) as \
                    stdout_io:
                with mock.patch('sys.stderr', new=six.moves.StringIO()) as \
                        stderr_io:
                    try:
                        _shell = debug_shell.NeutronDebugShell(
                                openstack_shell.NEUTRON_API_VERSION)
                        _shell.run(argstr.split())
                    except SystemExit:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        self.assertEqual(0, exc_value.code)
        return stdout_io.getvalue(), stderr_io.getvalue()

    def test_run_unknown_command(self):
        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        stdout, stderr = self.shell('fake', check=True)
        self.assertFalse(stdout)

    def test_help(self):
        help_text, stderr = self.shell('help')
        self.assertFalse(stderr)

    def test_bash_completion(self):
        required = '.*os_user_domain_id.*'
        bash_completion, stderr = self.shell('bash-completion')
        self.assertThat(
            bash_completion,
            matchers.MatchesRegex(required))
        self.assertFalse(stderr)

    def test_help_on_subcommand(self):
        stdout, stderr = self.shell('help probe-list')
        self.assertFalse(stderr)

    def test_help_command(self):
        stdout, stderr = self.shell('help network-create')
        self.assertFalse(stderr)

    def test_bash_completion_command(self):
        bash_completion, stderr = self.shell('neutron bash-completion')
        self.assertFalse(stderr)

    def test_unknown_auth_strategy(self):
        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        stdout, stderr = self.shell('--os-auth-strategy fake probe-list')
        self.assertFalse(stdout)

    def test_build_option_parser(self):
        neutron_shell = debug_shell.NeutronDebugShell(
                openstack_shell.NEUTRON_API_VERSION)
        result = neutron_shell.build_option_parser('descr', '2.0')
        self.assertTrue(isinstance(result, argparse.ArgumentParser))

    def test_endpoint_option(self):
        shell = debug_shell.NeutronDebugShell(
                openstack_shell.NEUTRON_API_VERSION)
        parser = shell.build_option_parser('descr', '2.0')
        os_endpoints = ['public', 'publicURL']

        # Neither $OS_ENDPOINT_TYPE nor --os-endpoint-type
        namespace = parser.parse_args([])
        self.assertIn(namespace.os_endpoint_type, os_endpoints)

        # --endpoint-type but not $OS_ENDPOINT_TYPE
        namespace = parser.parse_args(['--os-endpoint-type=admin'])
        self.assertEqual('admin', namespace.os_endpoint_type)

    def test_endpoint_environment_variable(self):
        fixture = fixtures.EnvironmentVariable("OS_ENDPOINT_TYPE",
                                               "public")
        self.useFixture(fixture)

        shell = debug_shell.NeutronDebugShell(
                openstack_shell.NEUTRON_API_VERSION)
        parser = shell.build_option_parser('descr', '2.0')

        # $OS_ENDPOINT_TYPE but not --endpoint-type
        namespace = parser.parse_args([])
        self.assertEqual("public", namespace.os_endpoint_type)

        # --endpoint-type and $OS_ENDPOINT_TYPE
        namespace = parser.parse_args(['--endpoint-type=admin'])
        self.assertEqual('admin', namespace.endpoint_type)

    def test_timeout_option(self):
        shell = debug_shell.NeutronDebugShell(
                openstack_shell.NEUTRON_API_VERSION)
        parser = shell.build_option_parser('descr', '2.0')

        # Neither $OS_ENDPOINT_TYPE nor --endpoint-type
        namespace = parser.parse_args([])
        self.assertIsNone(namespace.http_timeout)

        # --endpoint-type but not $OS_ENDPOINT_TYPE
        namespace = parser.parse_args(['--http-timeout=50'])
        self.assertEqual(50, namespace.http_timeout)

    def test_timeout_environment_variable(self):
        fixture = fixtures.EnvironmentVariable("OS_NETWORK_TIMEOUT",
                                               "50")
        self.useFixture(fixture)

        shell = debug_shell.NeutronDebugShell(
                openstack_shell.NEUTRON_API_VERSION)
        parser = shell.build_option_parser('descr', '2.0')

        namespace = parser.parse_args([])
        self.assertEqual(50, namespace.http_timeout)
