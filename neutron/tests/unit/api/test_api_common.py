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
import webob

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


class GetPathUrlTestCase(base.BaseTestCase):

    def test_no_headers(self):
        base_http_url = 'http://neutron.example/sub/ports.json'
        base_https_url = 'https://neutron.example/sub/ports.json'
        path = ''

        http_req = webob.Request.blank(path, base_url=base_http_url)
        https_req = webob.Request.blank(path, base_url=base_https_url)

        # should be unchanged
        self.assertEqual(base_http_url, api_common.get_path_url(http_req))
        self.assertEqual(base_https_url, api_common.get_path_url(https_req))

    def test_http_to_https(self):
        base_url = 'http://neutron.example/sub/ports.json'
        path = ''

        request = webob.Request.blank(
            path, base_url=base_url, headers={'X-Forwarded-Proto': 'https'})

        path_url = api_common.get_path_url(request)
        # should replace http:// with https://
        self.assertTrue(path_url.startswith("https://"))

    def test_https_to_http(self):
        base_url = 'https://neutron.example/sub/ports.json'
        path = ''

        request = webob.Request.blank(
            path, base_url=base_url, headers={'X-Forwarded-Proto': 'http'})

        path_url = api_common.get_path_url(request)
        # should replace https:// with http://
        self.assertTrue(path_url.startswith("http://"))
