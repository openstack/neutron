# Copyright 2011 VMware, Inc.
#
# All Rights Reserved
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

import httplib

from neutron.plugins.vmware import api_client
from neutron.tests import base


class ApiCommonTest(base.BaseTestCase):

    def test_ctrl_conn_to_str(self):
        conn = httplib.HTTPSConnection('localhost', 4242, timeout=0)
        self.assertTrue(
            api_client.ctrl_conn_to_str(conn) == 'https://localhost:4242')

        conn = httplib.HTTPConnection('localhost', 4242, timeout=0)
        self.assertTrue(
            api_client.ctrl_conn_to_str(conn) == 'http://localhost:4242')

        self.assertRaises(TypeError, api_client.ctrl_conn_to_str,
                          ('not an httplib.HTTPSConnection'))
