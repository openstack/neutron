# Copyright (c) 2013 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.plugins.cisco.common import config as cisco_config
from neutron.tests import base


class TestCiscoNexusPluginConfig(base.BaseTestCase):

    def setUp(self):
        # Point neutron config file to: neutron/tests/etc/neutron.conf.test
        self.config_parse()

        super(TestCiscoNexusPluginConfig, self).setUp()

    def test_config_parse_error(self):
        """Check that config error is raised upon config parser failure."""
        with mock.patch.object(cfg, 'MultiConfigParser') as parser:
            parser.return_value.read.return_value = []
            self.assertRaises(cfg.Error, cisco_config.CiscoConfigOptions)

    def test_create_device_dictionary(self):
        """Test creation of the device dictionary based on nexus config."""
        test_config = {
            'NEXUS_SWITCH:1.1.1.1': {
                'username': ['admin'],
                'password': ['mySecretPassword'],
                'ssh_port': [22],
                'compute1': ['1/1'],
                'compute2': ['1/2'],
            },
            'NEXUS_SWITCH:2.2.2.2': {
                'username': ['admin'],
                'password': ['mySecretPassword'],
                'ssh_port': [22],
                'compute3': ['1/1'],
                'compute4': ['1/2'],
            },
        }
        expected_dev_dict = {
            ('NEXUS_SWITCH', '1.1.1.1', 'username'): 'admin',
            ('NEXUS_SWITCH', '1.1.1.1', 'password'): 'mySecretPassword',
            ('NEXUS_SWITCH', '1.1.1.1', 'ssh_port'): 22,
            ('NEXUS_SWITCH', '1.1.1.1', 'compute1'): '1/1',
            ('NEXUS_SWITCH', '1.1.1.1', 'compute2'): '1/2',
            ('NEXUS_SWITCH', '2.2.2.2', 'username'): 'admin',
            ('NEXUS_SWITCH', '2.2.2.2', 'password'): 'mySecretPassword',
            ('NEXUS_SWITCH', '2.2.2.2', 'ssh_port'): 22,
            ('NEXUS_SWITCH', '2.2.2.2', 'compute3'): '1/1',
            ('NEXUS_SWITCH', '2.2.2.2', 'compute4'): '1/2',
        }
        with mock.patch.object(cfg, 'MultiConfigParser') as parser:
            parser.return_value.read.return_value = cfg.CONF.config_file
            parser.return_value.parsed = [test_config]
            cisco_config.CiscoConfigOptions()
            self.assertEqual(cisco_config.device_dictionary,
                             expected_dev_dict)
