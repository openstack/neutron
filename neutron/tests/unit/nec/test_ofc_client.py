# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 NEC Corporation.  All rights reserved.
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
# @author: Akihiro Motoki

import json
import socket

import mock

from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.common import ofc_client
from neutron.tests import base


class OFCClientTest(base.BaseTestCase):

    def _test_do_request(self, status, resbody, data, exctype=None,
                         exc_checks=None):
        res = mock.Mock()
        res.status = status
        res.read.return_value = resbody

        conn = mock.Mock()
        conn.getresponse.return_value = res

        with mock.patch.object(ofc_client.OFCClient, 'get_connection',
                               return_value=conn):
            client = ofc_client.OFCClient()

            if exctype:
                e = self.assertRaises(exctype, client.do_request,
                                      'GET', '/somewhere', body={})
                self.assertEqual(data, str(e))
                if exc_checks:
                    for k, v in exc_checks.items():
                        self.assertEqual(v, getattr(e, k))
            else:
                response = client.do_request('GET', '/somewhere', body={})
                self.assertEqual(response, data)

            headers = {"Content-Type": "application/json"}
            expected = [
                mock.call.request('GET', '/somewhere', '{}', headers),
                mock.call.getresponse(),
            ]
            conn.assert_has_calls(expected)

    def test_do_request_200_json_value(self):
        self._test_do_request(200, json.dumps([1, 2, 3]), [1, 2, 3])

    def test_do_request_200_string(self):
        self._test_do_request(200, 'abcdef', 'abcdef')

    def test_do_request_200_no_body(self):
        self._test_do_request(200, None, None)

    def test_do_request_other_success_codes(self):
        for status in [201, 202, 204]:
            self._test_do_request(status, None, None)

    def test_do_request_returns_404(self):
        resbody = ''
        errmsg = _("The specified OFC resource (/somewhere) is not found.")
        self._test_do_request(404, resbody, errmsg, nexc.OFCResourceNotFound)

    def test_do_request_error_no_body(self):
        errmsg = _("An OFC exception has occurred: Operation on OFC failed")
        exc_checks = {'status': 400, 'err_code': None, 'err_msg': None}
        self._test_do_request(400, None, errmsg, nexc.OFCException, exc_checks)

    def test_do_request_error_string_body(self):
        resbody = 'This is an error.'
        errmsg = _("An OFC exception has occurred: Operation on OFC failed")
        exc_checks = {'status': 400, 'err_code': None,
                      'err_msg': 'This is an error.'}
        self._test_do_request(400, resbody, errmsg, nexc.OFCException,
                              exc_checks)

    def test_do_request_error_json_body(self):
        resbody = json.dumps({'err_code': 40022,
                              'err_msg': 'This is an error.'})
        errmsg = _("An OFC exception has occurred: Operation on OFC failed")
        exc_checks = {'status': 400, 'err_code': 40022,
                      'err_msg': 'This is an error.'}
        self._test_do_request(400, resbody, errmsg, nexc.OFCException,
                              exc_checks)

    def test_do_request_socket_error(self):
        conn = mock.Mock()
        conn.request.side_effect = socket.error

        data = _("An OFC exception has occurred: Failed to connect OFC : ")

        with mock.patch.object(ofc_client.OFCClient, 'get_connection',
                               return_value=conn):
            client = ofc_client.OFCClient()

            e = self.assertRaises(nexc.OFCException, client.do_request,
                                  'GET', '/somewhere', body={})
            self.assertEqual(data, str(e))
            for k in ['status', 'err_code', 'err_msg']:
                self.assertIsNone(getattr(e, k))

            headers = {"Content-Type": "application/json"}
            expected = [
                mock.call.request('GET', '/somewhere', '{}', headers),
            ]
            conn.assert_has_calls(expected)
