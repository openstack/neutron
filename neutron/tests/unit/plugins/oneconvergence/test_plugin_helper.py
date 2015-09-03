# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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

import mock
from oslo_serialization import jsonutils
import requests

from neutron.plugins.oneconvergence.lib import config  # noqa
from neutron.plugins.oneconvergence.lib import plugin_helper as client
from neutron.tests import base


class TestPluginHelper(base.BaseTestCase):
    def setUp(self):
        super(TestPluginHelper, self).setUp()
        self.nvsdcontroller = client.NVSDController()

    def get_response(self, *args, **kwargs):
        response = mock.Mock()
        response.status_code = requests.codes.ok
        response.content = jsonutils.dumps({'session_uuid': 'new_auth_token'})
        return response

    def test_login(self):
        login_url = ('http://127.0.0.1:8082/pluginhandler/ocplugin/'
                     'authmgmt/login')
        headers = {'Content-Type': 'application/json'}
        data = jsonutils.dumps({"user_name": "ocplugin", "passwd": "oc123"})
        timeout = 30.0

        with mock.patch.object(self.nvsdcontroller.pool, 'request',
                               side_effect=self.get_response) as request:
            self.nvsdcontroller.login()
            request.assert_called_once_with('POST', url=login_url,
                                            headers=headers, data=data,
                                            timeout=timeout)

    def test_request(self):
        with mock.patch.object(self.nvsdcontroller.pool, 'request',
                               side_effect=self.get_response) as request:
            self.nvsdcontroller.login()
            self.nvsdcontroller.request("POST", "/some_url")
            self.assertEqual(request.call_count, 2)
            request.assert_called_with(
                'POST',
                url='http://127.0.0.1:8082/some_url?authToken=new_auth_token',
                headers={'Content-Type': 'application/json'}, data='',
                timeout=30.0)
