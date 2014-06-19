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

from oslo.config import cfg

from neutron.plugins.ryu.common import config  # noqa
from neutron.tests import base


class ConfigurationTest(base.BaseTestCase):
    """Configuration file Tests."""
    def test_defaults(self):
        self.assertEqual('br-int', cfg.CONF.OVS.integration_bridge)
        self.assertEqual(2, cfg.CONF.AGENT.polling_interval)
        self.assertEqual('sudo', cfg.CONF.AGENT.root_helper)
        self.assertEqual('127.0.0.1:8080', cfg.CONF.OVS.openflow_rest_api)
        self.assertEqual(1, cfg.CONF.OVS.tunnel_key_min)
        self.assertEqual(0xffffff, cfg.CONF.OVS.tunnel_key_max)
        self.assertEqual(6634, cfg.CONF.OVS.ovsdb_port)
