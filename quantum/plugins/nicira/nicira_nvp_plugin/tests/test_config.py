# Copyright 2012 Nicira Networks, Inc.
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


import unittest
import StringIO
import ConfigParser
from nicira_nvp_plugin.QuantumPlugin import parse_config
from nicira_nvp_plugin.QuantumPlugin import NVPCluster


class ConfigParserTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_nvp_config_000(self):
        nvpc = NVPCluster('cluster1')
        for f in [
            (
                'default_tz_id1', 'ip1', 'port1', 'user1', 'passwd1', 42, 43,
                44, 45),
            (
                'default_tz_id1', 'ip2', 'port2', 'user2', 'passwd2', 42, 43,
                44, 45),
            (
                'default_tz_id1', 'ip3', 'port3', 'user3', 'passwd3', 42, 43,
                44, 45),
        ]:
            nvpc.add_controller(*f)

        self.assertTrue(nvpc.name == 'cluster1')
        self.assertTrue(len(nvpc.controllers) == 3)

    def test_old_config_parser_old_style(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_IP = <controller ip>
PORT = <port>
USER = <user>
PASSWORD = <pass>
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)

        self.assertTrue(cluster1.name == 'cluster1')
        self.assertTrue(
            cluster1.controllers[0]['default_tz_uuid'] == '<default uuid>')
        self.assertTrue(
            cluster1.controllers[0]['port'] == '<port>')
        self.assertTrue(
            cluster1.controllers[0]['user'] == '<user>')
        self.assertTrue(
            cluster1.controllers[0]['password'] == '<pass>')
        self.assertTrue(
            cluster1.controllers[0]['request_timeout'] == 30)
        self.assertTrue(
            cluster1.controllers[0]['http_timeout'] == 10)
        self.assertTrue(
            cluster1.controllers[0]['retries'] == 2)
        self.assertTrue(
            cluster1.controllers[0]['redirects'] == 2)

    def test_old_config_parser_new_style(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_CONNECTIONS = CONNECTION1
CONNECTION1 = 10.0.0.1:4242:admin:admin:42:43:44:45
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)

        self.assertTrue(cluster1.name == 'cluster1')
        self.assertTrue(
            cluster1.controllers[0]['default_tz_uuid'] == '<default uuid>')
        self.assertTrue(
            cluster1.controllers[0]['port'] == '4242')
        self.assertTrue(
            cluster1.controllers[0]['user'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['password'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['request_timeout'] == 42)
        self.assertTrue(
            cluster1.controllers[0]['http_timeout'] == 43)
        self.assertTrue(
            cluster1.controllers[0]['retries'] == 44)
        self.assertTrue(
            cluster1.controllers[0]['redirects'] == 45)

    def test_old_config_parser_both_styles(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
NVP_CONTROLLER_IP = <controller ip>
PORT = <port>
USER = <user>
PASSWORD = <pass>
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_CONNECTIONS = CONNECTION1
CONNECTION1 = 10.0.0.1:4242:admin:admin:42:43:44:45
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)

        self.assertTrue(cluster1.name == 'cluster1')
        self.assertTrue(
            cluster1.controllers[0]['default_tz_uuid'] == '<default uuid>')
        self.assertTrue(
            cluster1.controllers[0]['port'] == '4242')
        self.assertTrue(
            cluster1.controllers[0]['user'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['password'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['request_timeout'] == 42)
        self.assertTrue(
            cluster1.controllers[0]['http_timeout'] == 43)
        self.assertTrue(
            cluster1.controllers[0]['retries'] == 44)
        self.assertTrue(
            cluster1.controllers[0]['redirects'] == 45)

    def test_old_config_parser_both_styles(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
NVP_CONTROLLER_IP = <controller ip>
PORT = <port>
USER = <user>
PASSWORD = <pass>
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_CONNECTIONS = CONNECTION1
CONNECTION1 = 10.0.0.1:4242:admin:admin:42:43:44:45
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)

        self.assertTrue(cluster1.name == 'cluster1')
        self.assertTrue(
            cluster1.controllers[0]['default_tz_uuid'] == '<default uuid>')
        self.assertTrue(
            cluster1.controllers[0]['port'] == '4242')
        self.assertTrue(
            cluster1.controllers[0]['user'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['password'] == 'admin')
        self.assertTrue(
            cluster1.controllers[0]['request_timeout'] == 42)
        self.assertTrue(
            cluster1.controllers[0]['http_timeout'] == 43)
        self.assertTrue(
            cluster1.controllers[0]['retries'] == 44)
        self.assertTrue(
            cluster1.controllers[0]['redirects'] == 45)

    def test_failover_time(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_IP = <controller ip>
PORT = 443
USER = admin
PASSWORD = admin
FAILOVER_TIME = 10
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)
        self.assertTrue(plugin_config['failover_time'] == '10')

    def test_failover_time_new_style(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_CONNECTIONS = CONNECTION1
CONNECTION1 = 10.0.0.1:4242:admin:admin:42:43:44:45
FAILOVER_TIME = 10
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)
        self.assertTrue(plugin_config['failover_time'] == '10')

    def test_concurrent_connections_time(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_IP = <controller ip>
PORT = 443
USER = admin
PASSWORD = admin
CONCURRENT_CONNECTIONS = 5
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)
        self.assertTrue(plugin_config['concurrent_connections'] == '5')

    def test_concurrent_connections_time_new_style(self):
        config = StringIO.StringIO('''
[DEFAULT]
[NVP]
DEFAULT_TZ_UUID = <default uuid>
NVP_CONTROLLER_CONNECTIONS = CONNECTION1
CONNECTION1 = 10.0.0.1:4242:admin:admin:42:43:44:45
CONCURRENT_CONNECTIONS = 5
''')
        cp = ConfigParser.ConfigParser()
        cp.readfp(config)
        cluster1, plugin_config = parse_config(cp)
        self.assertTrue(plugin_config['concurrent_connections'] == '5')

if __name__ == '__main__':
    unittest.main()
