# Copyright (c) 2012 Intel Corporation.
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

from neutron_lib import context
from neutron_lib import exceptions as n_exc
import oslo_i18n
from webob import exc
import webtest

from neutron._i18n import _
from neutron.api.v2 import resource as wsgi_resource
from neutron.common import utils
from neutron.tests import base
from neutron import wsgi


class RequestTestCase(base.BaseTestCase):
    def setUp(self):
        super(RequestTestCase, self).setUp()
        self.req = wsgi_resource.Request({'foo': 'bar'})

    def test_content_type_missing(self):
        request = wsgi.Request.blank('/tests/123', method='POST')
        request.body = b"<body />"
        self.assertIsNone(request.get_content_type())

    def test_content_type_with_charset(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/json; charset=UTF-8"
        result = request.get_content_type()
        self.assertEqual("application/json", result)

    def test_content_type_with_partial_matched_string(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/j"
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

    def test_content_type_from_accept(self):
        content_type = 'application/json'
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = content_type
        result = request.best_match_content_type()
        self.assertEqual(content_type, result)

    def test_content_type_from_accept_best(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = ("application/json; q=0.3, "
                                     "application/xml; q=0.9")
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

    def test_content_type_from_query_extension(self):
        request = wsgi.Request.blank('/tests/123.json')
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

        request = wsgi.Request.blank('/tests/123.invalid')
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

    def test_content_type_accept_and_query_extension(self):
        request = wsgi.Request.blank('/tests/123.json')
        request.headers["Accept"] = "application/xml"
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

    def test_content_type_accept_default(self):
        request = wsgi.Request.blank('/tests/123.unsupported')
        request.headers["Accept"] = "application/unsupported1"
        result = request.best_match_content_type()
        self.assertEqual("application/json", result)

    def test_context_with_neutron_context(self):
        ctxt = context.Context('fake_user', 'fake_tenant')
        self.req.environ['neutron.context'] = ctxt
        self.assertEqual(self.req.context, ctxt)

    def test_context_without_neutron_context(self):
        self.assertTrue(self.req.context.is_admin)

    def test_request_context_elevated(self):
        user_context = context.Context(
            'fake_user', 'fake_project', is_admin=False)
        self.assertFalse(user_context.is_admin)
        admin_context = user_context.elevated()
        self.assertFalse(user_context.is_admin)
        self.assertTrue(admin_context.is_admin)
        self.assertNotIn('admin', user_context.roles)
        self.assertIn('admin', admin_context.roles)

    def test_best_match_language(self):
        # Test that we are actually invoking language negotiation by webop
        request = wsgi.Request.blank('/')
        oslo_i18n.get_available_languages = mock.MagicMock()
        oslo_i18n.get_available_languages.return_value = ['known-language',
                                                          'es', 'zh']
        request.headers['Accept-Language'] = 'known-language'
        language = request.best_match_language()
        self.assertEqual('known-language', language)

        # If the Accept-Leader is an unknown language, missing or empty,
        # the best match locale should be None
        request.headers['Accept-Language'] = 'unknown-language'
        language = request.best_match_language()
        self.assertIsNone(language)
        request.headers['Accept-Language'] = ''
        language = request.best_match_language()
        self.assertIsNone(language)
        request.headers.pop('Accept-Language')
        language = request.best_match_language()
        self.assertIsNone(language)


class ResourceTestCase(base.BaseTestCase):

    @staticmethod
    def _get_deserializer():
        return wsgi.JSONDeserializer()

    def test_unmapped_neutron_error_with_json(self):
        msg = '\u7f51\u7edc'

        class TestException(n_exc.NeutronException):
            message = msg
        expected_res = {'body': {
            'NeutronError': {
                'type': 'TestException',
                'message': msg,
                'detail': ''}}}
        controller = mock.MagicMock()
        controller.test.side_effect = TestException()

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test',
                                                   'format': 'json'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(exc.HTTPInternalServerError.code, res.status_int)
        self.assertEqual(expected_res,
                         wsgi.JSONDeserializer().deserialize(res.body))

    @mock.patch('oslo_i18n.translate')
    def test_unmapped_neutron_error_localized(self, mock_translation):
        msg_translation = 'Translated error'
        mock_translation.return_value = msg_translation
        msg = _('Unmapped error')

        class TestException(n_exc.NeutronException):
            message = msg

        controller = mock.MagicMock()
        controller.test.side_effect = TestException()
        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test',
                                                   'format': 'json'})}

        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(exc.HTTPInternalServerError.code, res.status_int)
        self.assertIn(msg_translation,
                      str(wsgi.JSONDeserializer().deserialize(res.body)))

    def test_mapped_neutron_error_with_json(self):
        msg = '\u7f51\u7edc'

        class TestException(n_exc.NeutronException):
            message = msg
        expected_res = {'body': {
            'NeutronError': {
                'type': 'TestException',
                'message': msg,
                'detail': ''}}}
        controller = mock.MagicMock()
        controller.test.side_effect = TestException()

        faults = {TestException: exc.HTTPGatewayTimeout}
        resource = webtest.TestApp(wsgi_resource.Resource(controller,
                                                          faults=faults))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test',
                                                   'format': 'json'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(exc.HTTPGatewayTimeout.code, res.status_int)
        self.assertEqual(expected_res,
                         wsgi.JSONDeserializer().deserialize(res.body))

    @mock.patch('oslo_i18n.translate')
    def test_mapped_neutron_error_localized(self, mock_translation):
        msg_translation = 'Translated error'
        mock_translation.return_value = msg_translation
        msg = _('Unmapped error')

        class TestException(n_exc.NeutronException):
            message = msg

        controller = mock.MagicMock()
        controller.test.side_effect = TestException()
        faults = {TestException: exc.HTTPGatewayTimeout}
        resource = webtest.TestApp(wsgi_resource.Resource(controller,
                                                          faults=faults))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test',
                                                   'format': 'json'})}

        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(exc.HTTPGatewayTimeout.code, res.status_int)
        self.assertIn(msg_translation,
                      str(wsgi.JSONDeserializer().deserialize(res.body)))

    @staticmethod
    def _make_request_with_side_effect(side_effect):
        controller = mock.MagicMock()
        controller.test.side_effect = side_effect

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        routing_args = {'action': 'test'}
        environ = {'wsgiorg.routing_args': (None, routing_args)}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        return res

    def test_http_error(self):
        res = self._make_request_with_side_effect(exc.HTTPGatewayTimeout())

        # verify that the exception structure is the one expected
        # by the python-neutronclient
        self.assertEqual(exc.HTTPGatewayTimeout().explanation,
                         res.json['NeutronError']['message'])
        self.assertEqual('HTTPGatewayTimeout',
                         res.json['NeutronError']['type'])
        self.assertEqual('', res.json['NeutronError']['detail'])
        self.assertEqual(exc.HTTPGatewayTimeout.code, res.status_int)

    def test_unhandled_error(self):
        expected_res = {'body': {'NeutronError':
                                {'detail': '',
                                 'message': _(
                                     'Request Failed: internal server '
                                     'error while processing your request.'),
                                 'type': 'HTTPInternalServerError'}}}
        res = self._make_request_with_side_effect(side_effect=Exception())
        self.assertEqual(exc.HTTPInternalServerError.code,
                         res.status_int)
        self.assertEqual(expected_res,
                         self._get_deserializer().deserialize(res.body))

    def test_not_implemented_error(self):
        expected_res = {'body': {'NeutronError':
                                {'detail': '',
                                 'message': _(
                                     'The server has either erred or is '
                                     'incapable of performing the requested '
                                     'operation.'),
                                 'type': 'HTTPNotImplemented'}}}

        res = self._make_request_with_side_effect(exc.HTTPNotImplemented())
        self.assertEqual(exc.HTTPNotImplemented.code, res.status_int)
        self.assertEqual(expected_res,
                         self._get_deserializer().deserialize(res.body))

    def test_status_200(self):
        controller = mock.MagicMock()
        controller.test = lambda request: {'foo': 'bar'}

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.get('', extra_environ=environ)
        self.assertEqual(200, res.status_int)

    def _test_unhandled_error_logs_details(self, e, expected_details):
        with mock.patch.object(wsgi_resource.LOG, 'exception') as log:
            self._make_request_with_side_effect(side_effect=e)
        log.assert_called_with(
            mock.ANY, {'action': mock.ANY, 'details': expected_details})

    def test_unhandled_error_logs_attached_details(self):
        e = Exception()
        utils.attach_exc_details(e, 'attached_details')
        self._test_unhandled_error_logs_details(e, 'attached_details')

    def test_unhandled_error_logs_no_attached_details(self):
        e = Exception()
        self._test_unhandled_error_logs_details(e, 'No details.')

    def test_status_204(self):
        controller = mock.MagicMock()
        controller.test = lambda request: {'foo': 'bar'}

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'delete'})}
        res = resource.delete('', extra_environ=environ)
        self.assertEqual(204, res.status_int)

    def test_action_status(self):
        controller = mock.MagicMock()
        controller.test = lambda request: {'foo': 'bar'}
        action_status = {'test_200': 200, 'test_201': 201, 'test_204': 204}
        resource = webtest.TestApp(
            wsgi_resource.Resource(controller,
                                   action_status=action_status))
        for action in action_status:
            environ = {'wsgiorg.routing_args': (None, {'action': action})}
            res = resource.get('', extra_environ=environ)
            self.assertEqual(action_status[action], res.status_int)

    def _test_error_log_level(self, expected_webob_exc, expect_log_info=False,
                              use_fault_map=True, exc_raised=None):
        if not exc_raised:
            class TestException(n_exc.NeutronException):
                message = 'Test Exception'
            exc_raised = TestException

        controller = mock.MagicMock()
        controller.test.side_effect = exc_raised()
        faults = {exc_raised: expected_webob_exc} if use_fault_map else {}
        resource = webtest.TestApp(wsgi_resource.Resource(controller, faults))
        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        with mock.patch.object(wsgi_resource, 'LOG') as log:
            res = resource.get('', extra_environ=environ, expect_errors=True)
            self.assertEqual(expected_webob_exc.code, res.status_int)
        self.assertEqual(expect_log_info, log.info.called)
        self.assertNotEqual(expect_log_info, log.exception.called)

    def test_4xx_error_logged_info_level(self):
        self._test_error_log_level(exc.HTTPNotFound, expect_log_info=True)

    def test_non_4xx_error_logged_exception_level(self):
        self._test_error_log_level(exc.HTTPServiceUnavailable,
                                   expect_log_info=False)

    def test_unmapped_error_logged_exception_level(self):
        self._test_error_log_level(exc.HTTPInternalServerError,
                                   expect_log_info=False, use_fault_map=False)

    def test_webob_4xx_logged_info_level(self):
        self._test_error_log_level(exc.HTTPNotFound,
                                   use_fault_map=False, expect_log_info=True,
                                   exc_raised=exc.HTTPNotFound)

    def test_webob_5xx_logged_info_level(self):
        self._test_error_log_level(exc.HTTPServiceUnavailable,
                                   use_fault_map=False, expect_log_info=False,
                                   exc_raised=exc.HTTPServiceUnavailable)

    def test_no_route_args(self):
        controller = mock.MagicMock()

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(exc.HTTPInternalServerError.code, res.status_int)

    def test_post_with_body(self):
        controller = mock.MagicMock()
        controller.test = lambda request, body: {'foo': 'bar'}

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.post('', params='{"key": "val"}',
                            extra_environ=environ)
        self.assertEqual(200, res.status_int)
