# Copyright 2016 Intel Corporation.
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

from unittest import mock

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge
from neutron.tests import base


class TestBRCookieOpenflow(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.br = ovs_bridge.OVSAgentBridge('br-int', os_ken_app=mock.Mock())

    def test_reserved_cookies(self):
        def_cookie = self.br.default_cookie
        self.assertIn(def_cookie, self.br.reserved_cookies)

    def test_request_cookie(self):
        default_cookie = self.br.default_cookie
        requested_cookie = self.br.request_cookie()
        self.assertEqual(default_cookie, self.br.default_cookie)
        self.assertIn(default_cookie, self.br.reserved_cookies)
        self.assertIn(requested_cookie, self.br.reserved_cookies)

    def test_unset_cookie(self):
        requested_cookie = self.br.request_cookie()
        self.assertIn(requested_cookie, self.br.reserved_cookies)
        self.br.unset_cookie(requested_cookie)
        self.assertNotIn(requested_cookie, self.br.reserved_cookies)

    def test_set_agent_uuid_stamp(self):
        self.br = ovs_bridge.OVSAgentBridge('br-int', os_ken_app=mock.Mock())
        def_cookie = self.br.default_cookie
        new_cookie = ovs_lib.generate_random_cookie()

        self.br.set_agent_uuid_stamp(new_cookie)

        self.assertEqual(new_cookie, self.br.default_cookie)
        self.assertIn(new_cookie, self.br.reserved_cookies)
        self.assertNotIn(def_cookie, self.br.reserved_cookies)

    def test_set_agent_uuid_stamp_with_reserved_cookie(self):
        self.br = ovs_bridge.OVSAgentBridge('br-int', os_ken_app=mock.Mock())
        def_cookie = self.br.default_cookie
        new_cookie = self.br.request_cookie()

        self.br.set_agent_uuid_stamp(new_cookie)

        self.assertEqual(new_cookie, self.br.default_cookie)
        self.assertIn(new_cookie, self.br.reserved_cookies)
        self.assertNotIn(def_cookie, self.br.reserved_cookies)
        self.assertEqual({new_cookie}, self.br.reserved_cookies)
