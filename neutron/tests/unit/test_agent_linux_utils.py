# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Nicira, Inc.
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
# @author: Dan Wendlandt, Nicira, Inc.

import fixtures
import mock

from neutron.agent.linux import utils
from neutron.tests import base


class AgentUtilsExecuteTest(base.BaseTestCase):
    def setUp(self):
        super(AgentUtilsExecuteTest, self).setUp()
        self.root_helper = "echo"
        self.test_file = self.useFixture(
            fixtures.TempDir()).join("test_execute.tmp")
        open(self.test_file, 'w').close()

    def test_without_helper(self):
        result = utils.execute(["ls", self.test_file])
        self.assertEqual(result, "%s\n" % self.test_file)

    def test_with_helper(self):
        result = utils.execute(["ls", self.test_file],
                               self.root_helper)
        self.assertEqual(result, "ls %s\n" % self.test_file)

    def test_stderr(self):
        stdout, stderr = utils.execute(["ls", self.test_file],
                                       return_stderr=True)
        self.assertEqual(stdout, "%s\n" % self.test_file)
        self.assertEqual(stderr, "")

    def test_check_exit_code(self):
        stdout = utils.execute(["ls", self.test_file[:-1]],
                               check_exit_code=False)
        self.assertEqual(stdout, "")
        self.assertRaises(RuntimeError, utils.execute,
                          ["ls", self.test_file[:-1]])

    def test_process_input(self):
        result = utils.execute(["cat"], process_input="%s\n" %
                               self.test_file[:-1])
        self.assertEqual(result, "%s\n" % self.test_file[:-1])

    def test_with_addl_env(self):
        result = utils.execute(["ls", self.test_file],
                               addl_env={'foo': 'bar'})
        self.assertEqual(result, "%s\n" % self.test_file)


class AgentUtilsGetInterfaceMAC(base.BaseTestCase):
    def test_get_interface_mac(self):
        expect_val = '01:02:03:04:05:06'
        with mock.patch('fcntl.ioctl') as ioctl:
            ioctl.return_value = ''.join(['\x00' * 18,
                                          '\x01\x02\x03\x04\x05\x06',
                                          '\x00' * 232])
            actual_val = utils.get_interface_mac('eth0')
        self.assertEqual(actual_val, expect_val)


class AgentUtilsReplaceFile(base.BaseTestCase):
    def test_replace_file(self):
        # make file to replace
        with mock.patch('tempfile.NamedTemporaryFile') as ntf:
            ntf.return_value.name = '/baz'
            with mock.patch('os.chmod') as chmod:
                with mock.patch('os.rename') as rename:
                    utils.replace_file('/foo', 'bar')

                    expected = [mock.call('w+', dir='/', delete=False),
                                mock.call().write('bar'),
                                mock.call().close()]

                    ntf.assert_has_calls(expected)
                    chmod.assert_called_once_with('/baz', 0o644)
                    rename.assert_called_once_with('/baz', '/foo')
