# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis, Inc.
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
#
# @author: Oleg Bondarev (obondarev@mirantis.com)

import testtools

from quantum.plugins.services.agent_loadbalancer.drivers.haproxy import cfg


class TestHaproxyCfg(testtools.TestCase):

    def test_has_http_cookie_persistence(self):
        config = {'vip': {'session_persistence': {'type': 'HTTP_COOKIE'}}}
        self.assertTrue(cfg._has_http_cookie_persistence(config))

        config = {'vip': {'session_persistence': {'type': 'SOURCE_IP'}}}
        self.assertFalse(cfg._has_http_cookie_persistence(config))

        config = {'vip': {'session_persistence': {}}}
        self.assertFalse(cfg._has_http_cookie_persistence(config))

    def test_get_session_persistence(self):
        config = {'vip': {'session_persistence': {'type': 'SOURCE_IP'}}}
        self.assertEqual(cfg._get_session_persistence(config),
                         ['stick-table type ip size 10k', 'stick on src'])

        config = {'vip': {'session_persistence': {'type': 'HTTP_COOKIE'}}}
        self.assertEqual(cfg._get_session_persistence(config),
                         ['cookie SRV insert indirect nocache'])

        config = {'vip': {'session_persistence': {'type': 'APP_COOKIE',
                                                  'cookie_name': 'test'}}}
        self.assertEqual(cfg._get_session_persistence(config),
                         ['appsession test len 56 timeout 3h'])

        config = {'vip': {'session_persistence': {'type': 'APP_COOKIE'}}}
        self.assertEqual(cfg._get_session_persistence(config), [])

        config = {'vip': {'session_persistence': {'type': 'UNSUPPORTED'}}}
        self.assertEqual(cfg._get_session_persistence(config), [])
