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

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
import requests

from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.common import ofc_client
from neutron.tests import base


class FakeResponse(requests.Response):
    def __init__(self, status_code=None, text=None, headers=None):
        self._text = text
        self.status_code = status_code
        if headers is not None:
            self.headers = headers

    @property
    def text(self):
        return self._text


class OFCClientTest(base.BaseTestCase):

    def _test_do_request(self, status, resbody, expected_data, exctype=None,
                         exc_checks=None, path_prefix=None):
        req = mock.Mock(return_value=(FakeResponse(status, resbody)))

        with mock.patch.object(requests, 'request', req):
            client = ofc_client.OFCClient()
            path = '/somewhere'
            realpath = path_prefix + path if path_prefix else path
            if exctype:
                e = self.assertRaises(exctype, client.do_request,
                                      'GET', path, body={})
                self.assertEqual(expected_data, str(e))
                if exc_checks:
                    for k, v in exc_checks.items():
                        self.assertEqual(v, getattr(e, k))
            else:
                response = client.do_request('GET', path, body={})
                self.assertEqual(response, expected_data)

            headers = {"Content-Type": "application/json"}
            req.assert_called_with('GET', 'http://127.0.0.1:8888' + realpath,
                                   verify=True, cert={}, data='{}',
                                   headers=headers)

    def test_do_request_200_json_value(self):
        self._test_do_request(200, jsonutils.dumps([1, 2, 3]), [1, 2, 3])

    def test_do_request_200_string(self):
        self._test_do_request(200, 'abcdef', 'abcdef')

    def test_do_request_200_no_body(self):
        self._test_do_request(200, None, None)

    def test_do_request_other_success_codes(self):
        for status in [201, 202, 204]:
            self._test_do_request(status, None, None)

    def test_do_request_with_path_prefix(self):
        config.CONF.set_override('path_prefix', '/dummy', group='OFC')
        self._test_do_request(200, jsonutils.dumps([1, 2, 3]), [1, 2, 3],
                              path_prefix='/dummy')

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
        resbody = jsonutils.dumps({'err_code': 40022,
                              'err_msg': 'This is an error.'})
        errmsg = _("An OFC exception has occurred: Operation on OFC failed")
        exc_checks = {'status': 400, 'err_code': 40022,
                      'err_msg': 'This is an error.'}
        self._test_do_request(400, resbody, errmsg, nexc.OFCException,
                              exc_checks)

    def test_do_request_socket_error(self):
        data = _("An OFC exception has occurred: Failed to connect OFC : ")

        req = mock.Mock()
        req.side_effect = requests.exceptions.RequestException

        with mock.patch.object(requests, 'request', req):
            client = ofc_client.OFCClient()

            e = self.assertRaises(nexc.OFCException, client.do_request,
                                  'GET', '/somewhere', body={})
            self.assertEqual(data, str(e))
            for k in ['status', 'err_code', 'err_msg']:
                self.assertIsNone(getattr(e, k))

            headers = {"Content-Type": "application/json"}
            req.assert_called_with('GET', 'http://127.0.0.1:8888/somewhere',
                                   verify=True, cert={}, data='{}',
                                   headers=headers)

    def test_do_request_retry_fail_after_one_attempts(self):
        self._test_do_request_retry_after(1, api_max_attempts=1)

    def test_do_request_retry_fail_with_max_attempts(self):
        self._test_do_request_retry_after(3)

    def test_do_request_retry_succeed_with_2nd_attempt(self):
        self._test_do_request_retry_after(2, succeed_final=True)

    def test_do_request_retry_succeed_with_1st_attempt(self):
        self._test_do_request_retry_after(1, succeed_final=True)

    def _test_do_request_retry_after(self, exp_request_count,
                                     api_max_attempts=None,
                                     succeed_final=False):
        if api_max_attempts is not None:
            cfg.CONF.set_override('api_max_attempts', api_max_attempts,
                                  group='OFC')

        res_unavail = FakeResponse(503, headers={'retry-after': '10'})
        res_ok = FakeResponse(200)

        req = mock.Mock()
        if succeed_final:
            req.side_effect = ([res_unavail] * (exp_request_count - 1)
                               + [res_ok])
        else:
            req.side_effect = [res_unavail] * exp_request_count

        with mock.patch.object(requests, 'request', req):
            with mock.patch('time.sleep') as sleep:
                client = ofc_client.OFCClient()
                if succeed_final:
                    ret = client.do_request('GET', '/somewhere')
                    self.assertIsNone(ret)
                else:
                    e = self.assertRaises(nexc.OFCServiceUnavailable,
                                          client.do_request,
                                          'GET', '/somewhere')
                    self.assertEqual('10', e.retry_after)

        headers = {"Content-Type": "application/json"}
        req.assert_called_with('GET', 'http://127.0.0.1:8888/somewhere',
                               verify=True, cert={}, data=None,
                               headers=headers)
        self.assertEqual(exp_request_count, req.call_count)
        self.assertEqual(exp_request_count - 1, sleep.call_count)
