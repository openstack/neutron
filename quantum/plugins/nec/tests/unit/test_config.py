# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import unittest

from quantum.plugins.nec.common import config


class ConfigurationTest(unittest.TestCase):

    def test_defaults(self):
        self.assertEqual('sqlite://', config.DATABASE.sql_connection)
        self.assertEqual('sqlite://', config.CONF.DATABASE.sql_connection)
        self.assertEqual(-1, config.CONF.DATABASE.sql_max_retries)
        self.assertEqual(2, config.CONF.DATABASE.reconnect_interval)
        self.assertEqual('br-int', config.CONF.OVS.integration_bridge)
        self.assertEqual(2, config.CONF.AGENT.polling_interval)
        self.assertEqual('sudo', config.CONF.AGENT.root_helper)
        self.assertEqual('127.0.0.1', config.CONF.OFC.host)
        self.assertEqual('8888', config.CONF.OFC.port)
        self.assertEqual('trema', config.CONF.OFC.driver)
        self.assertTrue(config.CONF.OFC.enable_packet_filter)
        self.assertFalse(config.CONF.OFC.use_ssl)
        self.assertEqual(None, config.CONF.OFC.key_file)
        self.assertEqual(None, config.CONF.OFC.cert_file)
