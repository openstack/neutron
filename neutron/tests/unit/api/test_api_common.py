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

from oslo_config import cfg

from neutron.api import api_common
from neutron.tests import base


class PrepareUrlTestCase(base.BaseTestCase):

    def test_no_configured_prefix(self):
        self.assertFalse(cfg.CONF.network_link_prefix)
        requrl = 'http://neutron.example/sub/ports.json?test=1'
        # should be unchanged
        self.assertEqual(requrl, api_common.prepare_url(requrl))

    def test_configured_prefix(self):
        cfg.CONF.set_override('network_link_prefix', 'http://quantum.example')
        requrl = 'http://neutron.example/sub/ports.json?test=1'
        expected = 'http://quantum.example/sub/ports.json?test=1'
        self.assertEqual(expected, api_common.prepare_url(requrl))
