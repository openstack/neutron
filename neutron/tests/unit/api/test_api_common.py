# Copyright (c) 2013 Intel Corporation.
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

from neutron_lib import exceptions
from oslo_serialization import jsonutils
from testtools import matchers
from webob import exc

from neutron.api import api_common as common
from neutron.api.v2 import base as base_v2
from neutron.common import exceptions as n_exc
from neutron.tests import base


class FakeController(common.NeutronController):
    _resource_name = 'fake'


class APICommonTestCase(base.BaseTestCase):
    def setUp(self):
        super(APICommonTestCase, self).setUp()
        self.controller = FakeController(None)

    def test_prepare_request_body(self):
        body = {
            'fake': {
                'name': 'terminator',
                'model': 'T-800',
            }
        }
        params = [
            {'param-name': 'name',
             'required': True},
            {'param-name': 'model',
             'required': True},
            {'param-name': 'quote',
             'required': False,
             'default-value': "i'll be back"},
        ]
        expect = {
            'fake': {
                'name': 'terminator',
                'model': 'T-800',
                'quote': "i'll be back",
            }
        }
        actual = self.controller._prepare_request_body(body, params)
        self.assertThat(expect, matchers.Equals(actual))

    def test_prepare_request_body_none(self):
        body = None
        params = [
            {'param-name': 'quote',
             'required': False,
             'default-value': "I'll be back"},
        ]
        expect = {
            'fake': {
                'quote': "I'll be back",
            }
        }
        actual = self.controller._prepare_request_body(body, params)
        self.assertThat(expect, matchers.Equals(actual))

    def test_prepare_request_body_keyerror(self):
        body = {'t2': {}}
        params = []
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._prepare_request_body,
                          body,
                          params)

    def test_prepare_request_param_value_none(self):
        body = {
            'fake': {
                'name': None,
            }
        }
        params = [
            {'param-name': 'name',
             'required': True},
        ]
        self.assertRaises(exc.HTTPBadRequest,
                          self.controller._prepare_request_body,
                          body,
                          params)

    def test_convert_exception_to_http_exc_multiple_different_codes(self):
        e = n_exc.MultipleExceptions([exceptions.NetworkInUse(net_id='nid'),
                                      exceptions.PortNotFound(port_id='pid')])
        conv = common.convert_exception_to_http_exc(e, base_v2.FAULT_MAP, None)
        self.assertIsInstance(conv, exc.HTTPConflict)
        self.assertEqual(
            ("HTTP 409 NetworkInUse: Unable to complete operation on network "
             "nid. There are one or more ports still in use on the network.\n"
             "HTTP 404 PortNotFound: Port pid could not be found."),
            jsonutils.loads(conv.body)['NeutronError']['message'])

    def test_convert_exception_to_http_exc_multiple_same_codes(self):
        e = n_exc.MultipleExceptions([exceptions.NetworkNotFound(net_id='nid'),
                                      exceptions.PortNotFound(port_id='pid')])
        conv = common.convert_exception_to_http_exc(e, base_v2.FAULT_MAP, None)
        self.assertIsInstance(conv, exc.HTTPNotFound)
        self.assertEqual(
            "Network nid could not be found.\nPort pid could not be found.",
            jsonutils.loads(conv.body)['NeutronError']['message'])

    def test_convert_exception_to_http_exc_multiple_empty_inner(self):
        e = n_exc.MultipleExceptions([])
        conv = common.convert_exception_to_http_exc(e, base_v2.FAULT_MAP, None)
        self.assertIsInstance(conv, exc.HTTPInternalServerError)
