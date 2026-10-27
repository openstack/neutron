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

from oslo_config import cfg

from neutron.agent.ovsdb.native import helpers
from neutron.tests import base

CONN_URI = 'tcp:127.0.0.1:6640'


class EnableConnectionUriTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_priv = mock.patch.object(
            helpers.priv_helpers, 'enable_connection_uri').start()

    def test_reads_configuration_when_called(self):
        # Set after the module has been imported, as an agent that imports
        # it before parsing its configuration files would.
        cfg.CONF.set_override('ovsdb_timeout', 42, 'OVS')
        cfg.CONF.set_override('of_inactivity_probe', 7, 'OVS')
        helpers.enable_connection_uri(CONN_URI)
        self.mock_priv.assert_called_once_with(
            CONN_URI, log_fail_as_error=False, check_exit_code=True,
            timeout=42, inactivity_probe=7000)

    def test_arguments_override_configuration(self):
        helpers.enable_connection_uri(CONN_URI, inactivity_probe=10)
        self.mock_priv.assert_called_once_with(
            CONN_URI, log_fail_as_error=False, check_exit_code=True,
            timeout=cfg.CONF.OVS.ovsdb_timeout, inactivity_probe=10)
