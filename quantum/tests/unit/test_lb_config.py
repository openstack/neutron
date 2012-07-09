# Copyright (c) 2012 OpenStack, LLC.
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

import os
import tempfile
import unittest

from quantum.openstack.common import cfg
from quantum.plugins.linuxbridge.common import config


class LinuxBridgeConfigTestCase(unittest.TestCase):
    def test_dummy(self):
        configs = """[DATABASE]
sql_connection = testlink
sql_max_retries = 200
reconnect_interval=100
[AGENT]
root_helper = mysudo
polling_interval=50
"""

        (fd, path) = tempfile.mkstemp(prefix='lb_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)

            conf = config.parse(path)
            self.assertEqual('testlink', conf.DATABASE.sql_connection)
            self.assertEqual(200, conf.DATABASE.sql_max_retries)
            self.assertEqual(100, conf.DATABASE.reconnect_interval)
            self.assertEqual(50, conf.AGENT.polling_interval)
            self.assertEqual('mysudo', conf.AGENT.root_helper)
            self.assertEqual(conf.AGENT.polling_interval,
                             cfg.CONF.AGENT.polling_interval)
        finally:
            os.remove(path)

    def test_defaults(self):
        configs = """
"""

        (fd, path) = tempfile.mkstemp(prefix='lb_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)

            conf = config.parse(path)
            self.assertEqual('sqlite://', conf.DATABASE.sql_connection)
            self.assertEqual(-1, conf.DATABASE.sql_max_retries)
            self.assertEqual(2, conf.DATABASE.reconnect_interval)
            self.assertEqual(2, conf.AGENT.polling_interval)
            self.assertEqual('sudo', conf.AGENT.root_helper)
            self.assertEqual(1000, conf.VLANS.vlan_start)
            self.assertEqual(3000, conf.VLANS.vlan_end)
            self.assertEqual('eth1', conf.LINUX_BRIDGE.physical_interface)
            self.assertEqual(conf.DATABASE.sql_connection,
                             cfg.CONF.DATABASE.sql_connection)
            self.assertEqual(conf.AGENT.root_helper,
                             cfg.CONF.AGENT.root_helper)
        finally:
            os.remove(path)

    def tearDown(self):
        """Clear the test environment"""
        cfg.CONF.reset()
        cfg.CONF.unregister_opts(config.vlan_opts, "VLANS")
        cfg.CONF.unregister_opts(config.database_opts, "DATABASE")
        cfg.CONF.unregister_opts(config.bridge_opts, "LINUX_BRIDGE")
        cfg.CONF.unregister_opts(config.agent_opts, "AGENT")
