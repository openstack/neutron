# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import unittest2

from quantum.openstack.common import cfg
from quantum.plugins.ryu.common import config


class ConfigurationTest(unittest2.TestCase):
    """Configuration file Tests"""
    def test_defaults(self):
        self.assertEqual('br-int', cfg.CONF.OVS.integration_bridge)
        self.assertEqual('sqlite://', cfg.CONF.DATABASE.sql_connection)
        self.assertEqual(-1, cfg.CONF.DATABASE.sql_max_retries)
        self.assertEqual(2, cfg.CONF.DATABASE.reconnect_interval)
        self.assertEqual(2, cfg.CONF.AGENT.polling_interval)
        self.assertEqual('sudo', cfg.CONF.AGENT.root_helper)
        self.assertEqual('127.0.0.1:6633', cfg.CONF.OVS.openflow_controller)
        self.assertEqual('127.0.0.1:8080', cfg.CONF.OVS.openflow_rest_api)
