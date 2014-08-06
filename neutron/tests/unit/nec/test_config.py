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

from neutron.plugins.nec.common import config
from neutron.tests import base


class ConfigurationTest(base.BaseTestCase):

    def test_defaults(self):
        self.assertEqual('br-int', config.CONF.OVS.integration_bridge)
        self.assertEqual(2, config.CONF.AGENT.polling_interval)
        self.assertEqual('sudo', config.CONF.AGENT.root_helper)

        self.assertEqual('127.0.0.1', config.CONF.OFC.host)
        self.assertEqual('8888', config.CONF.OFC.port)
        # Check path_prefix is an empty string explicitly.
        self.assertEqual('', config.CONF.OFC.path_prefix)
        self.assertEqual('trema', config.CONF.OFC.driver)
        self.assertTrue(config.CONF.OFC.enable_packet_filter)
        self.assertFalse(config.CONF.OFC.use_ssl)
        self.assertIsNone(config.CONF.OFC.key_file)
        self.assertIsNone(config.CONF.OFC.cert_file)

    def test_shortcuts(self):
        self.assertEqual(config.CONF.OVS.integration_bridge,
                         config.OVS.integration_bridge)
        self.assertEqual(config.CONF.AGENT.polling_interval,
                         config.AGENT.polling_interval)
        self.assertEqual(config.CONF.OFC.host, config.OFC.host)
