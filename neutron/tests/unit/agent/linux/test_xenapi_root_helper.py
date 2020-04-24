# Copyright 2016 Citrix System.
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

from oslo_config import cfg
from oslo_rootwrap import cmd as oslo_rootwrap_cmd

from neutron.agent.linux import xenapi_root_helper as helper
from neutron.conf.agent import xenapi_conf
from neutron.tests import base


class TestXenapiRootHelper(base.BaseTestCase):
    def _get_fake_xenapi_client(self):
        class FakeXenapiClient(helper.XenAPIClient):
            def __init__(self):
                self._session = mock.MagicMock()

        return FakeXenapiClient()

    def setUp(self):
        super(TestXenapiRootHelper, self).setUp()
        conf = cfg.CONF
        xenapi_conf.register_xenapi_opts(conf)

    def test_get_return_code_unauthourized(self):
        failure_details = [helper.XENAPI_PLUGIN_FAILURE_ID,
                           'run_command',
                           'PluginError',
                           helper.MSG_UNAUTHORIZED]
        xenapi_client = self._get_fake_xenapi_client()
        rc = xenapi_client._get_return_code(failure_details)
        self.assertEqual(oslo_rootwrap_cmd.RC_UNAUTHORIZED, rc)

    def test_get_return_code_noexecfound(self):
        failure_details = [helper.XENAPI_PLUGIN_FAILURE_ID,
                           'run_command',
                           'PluginError',
                           helper.MSG_NOT_FOUND]
        xenapi_client = self._get_fake_xenapi_client()
        rc = xenapi_client._get_return_code(failure_details)
        self.assertEqual(oslo_rootwrap_cmd.RC_NOEXECFOUND, rc)

    def test_get_return_code_unknown_error(self):
        failure_details = [helper.XENAPI_PLUGIN_FAILURE_ID,
                           'run_command',
                           'PluginError',
                           'Any unknown error']
        xenapi_client = self._get_fake_xenapi_client()
        rc = xenapi_client._get_return_code(failure_details)
        self.assertEqual(helper.RC_UNKNOWN_XENAPI_ERROR, rc)

    def test_execute(self):
        cmd = ["ovs-vsctl", "list-ports", "xapi2"]
        expect_cmd_args = {'cmd': '["ovs-vsctl", "list-ports", "xapi2"]',
                           'cmd_input': 'null'}
        raw_result = '{"returncode": 0, "err": "", "out": "vif158.2"}'

        with mock.patch.object(helper.XenAPIClient, "_call_plugin",
                               return_value=raw_result) as mock_call_plugin:
            xenapi_client = self._get_fake_xenapi_client()
            rc, out, err = xenapi_client.execute(cmd)

            mock_call_plugin.assert_called_once_with(
                'netwrap.py', 'run_command', expect_cmd_args)
            self.assertEqual(0, rc)
            self.assertEqual("vif158.2", out)
            self.assertEqual("", err)

    def test_execute_nocommand(self):
        cmd = []
        xenapi_client = self._get_fake_xenapi_client()
        rc, out, err = xenapi_client.execute(cmd)
        self.assertEqual(oslo_rootwrap_cmd.RC_NOCOMMAND, rc)
