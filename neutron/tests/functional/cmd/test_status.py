# Copyright (c) 2019 Red Hat, Inc.
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

from neutron_lib import exceptions
from oslo_upgradecheck import upgradecheck

from neutron.agent.linux import utils
from neutron.tests.functional import base


class StatusTest(base.BaseLoggingTestCase):

    def test_neutron_status_cli(self):
        """This test runs "neutron-status upgrade check" command and check if
        stdout contains header "Upgrade Check Results". It also checks if
        stderr is empty.
        Example output from this CLI tool looks like:

        +----------------------------------------------------------------+
        | Upgrade Check Results                                          |
        +----------------------------------------------------------------+
        | Check: Worker counts configured                                |
        | Result: Warning                                                |
        | Details: The default number of workers has changed. Please see |
        |   release notes for the new values, but it is strongly         |
        |   encouraged for deployers to manually set the values for      |
        |   api_workers and rpc_workers.                                 |
        +----------------------------------------------------------------+

        Error codes which might be returned by this command:
        - Code.SUCCESS,
        - Code.WARNING,
        - Code.FAILURE
        are all accepted as we don't want to test here if there are any
        potential problems with upgrade or all is fine. This depends on
        deployment's configuration.
        """

        expected_result_title = "Upgrade Check Results"
        try:
            stdout, stderr = utils.execute(
                cmd=["neutron-status", "upgrade", "check"],
                extra_ok_codes=[upgradecheck.Code.SUCCESS,
                                upgradecheck.Code.WARNING,
                                upgradecheck.Code.FAILURE],
                return_stderr=True)
            self.assertEqual('', stderr)
            self.assertTrue(expected_result_title in stdout)
        except exceptions.ProcessExecutionError as error:
            self.fail("neutron-status upgrade check command failed to run. "
                      "Error: %s" % error)
