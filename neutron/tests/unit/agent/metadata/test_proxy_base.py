# Copyright 2024 Canonical Ltd.
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

import requests
import testtools
import webob

from oslo_config import cfg
from oslo_config import fixture as config_fixture

from neutron.agent.metadata import proxy_base
from neutron.common import utils
from neutron.conf.agent.metadata import config as meta_conf
from neutron.tests import base


class ConfFixture(config_fixture.Config):
    def setUp(self):
        super().setUp()
        meta_conf.register_meta_conf_opts(
            meta_conf.SHARED_OPTS, self.conf)
        meta_conf.register_meta_conf_opts(
            meta_conf.METADATA_PROXY_HANDLER_OPTS, self.conf)
        meta_conf.register_meta_conf_opts(
            meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS, self.conf)
        self.config(auth_ca_cert=None,
                    nova_metadata_host='9.9.9.9',
                    nova_metadata_port=8775,
                    metadata_proxy_shared_secret='secret',
                    nova_metadata_protocol='http',
                    nova_metadata_insecure=True,
                    nova_client_cert='nova_cert',
                    nova_client_priv_key='nova_priv_key')


class FakeMetadataProxyHandler(proxy_base.MetadataProxyHandlerBase):
    def __init__(self, conf):
        super().__init__(conf)

    def get_port(self, remote_address, network_id=None, remote_mac=None,
                 router_id=None, skip_cache=False):
        # This is an abstractmethod so must be defined
        return None, None


class TestMetadataProxyHandlerBase(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super().setUp()
        self.useFixture(self.fake_conf_fixture)
        self.handler = FakeMetadataProxyHandler(self.fake_conf)

    def _proxy_request_test_helper(self, response_code=200, method='GET'):
        hdrs = {'X-Forwarded-For': '8.8.8.8'}
        body = 'body'

        req = mock.Mock(path_info='/the_path', query_string='', headers=hdrs,
                        method=method, body=body)
        resp = mock.MagicMock(status_code=response_code)
        resp.status.__str__.side_effect = AttributeError
        resp.content = 'content'
        req.response = resp
        with mock.patch.object(utils, 'sign_instance_id') as sign:
            sign.return_value = 'signed'
            with mock.patch('requests.request') as mock_request:
                resp.headers = {'content-type': 'text/plain'}
                mock_request.return_value = resp
                retval = self.handler._proxy_request('the_id', 'tenant_id',
                                                     req)
                mock_request.assert_called_once_with(
                    method=method, url='http://9.9.9.9:8775/the_path',
                    headers={
                        'X-Forwarded-For': '8.8.8.8',
                        'X-Instance-ID-Signature': 'signed',
                        'X-Instance-ID': 'the_id',
                        'X-Tenant-ID': 'tenant_id'
                    },
                    data=body,
                    cert=(self.fake_conf.nova_client_cert,
                          self.fake_conf.nova_client_priv_key),
                    verify=False,
                    timeout=60)

                return retval

    def test_proxy_request_post(self):
        response = self._proxy_request_test_helper(method='POST')
        self.assertEqual('text/plain', response.content_type)
        self.assertEqual('content', response.body)

    def test_proxy_request_200(self):
        response = self._proxy_request_test_helper(200)
        self.assertEqual('text/plain', response.content_type)
        self.assertEqual('content', response.body)

    def test_proxy_request_400(self):
        self.assertIsInstance(self._proxy_request_test_helper(400),
                              webob.exc.HTTPBadRequest)

    def test_proxy_request_403(self):
        self.assertIsInstance(self._proxy_request_test_helper(403),
                              webob.exc.HTTPForbidden)

    def test_proxy_request_404(self):
        self.assertIsInstance(self._proxy_request_test_helper(404),
                              webob.exc.HTTPNotFound)

    def test_proxy_request_409(self):
        self.assertIsInstance(self._proxy_request_test_helper(409),
                              webob.exc.HTTPConflict)

    def test_proxy_request_500(self):
        self.assertIsInstance(self._proxy_request_test_helper(500),
                              webob.exc.HTTPInternalServerError)

    def test_proxy_request_502(self):
        self.assertIsInstance(self._proxy_request_test_helper(502),
                              webob.exc.HTTPBadGateway)

    def test_proxy_request_503(self):
        self.assertIsInstance(self._proxy_request_test_helper(503),
                              webob.exc.HTTPServiceUnavailable)

    def test_proxy_request_504(self):
        self.assertIsInstance(self._proxy_request_test_helper(504),
                              webob.exc.HTTPGatewayTimeout)

    def test_proxy_request_other_code(self):
        with testtools.ExpectedException(Exception):
            self._proxy_request_test_helper(302)

    def test_proxy_request_connection_error(self):
        req = mock.Mock(path_info='/the_path', query_string='', headers={},
                        method='GET', body='')
        with mock.patch('requests.request') as mock_request:
            mock_request.side_effect = requests.ConnectionError()
            retval = self.handler._proxy_request('the_id', 'tenant_id', req)
            self.assertIsInstance(retval, webob.exc.HTTPServiceUnavailable)


class FakeUnixDomainMetadataProxy(proxy_base.UnixDomainMetadataProxyBase):
    def run(self):
        # This is an abstractmethod so must be defined
        pass


class TestUnixDomainMetadataProxyBase(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super().setUp()
        self.useFixture(self.fake_conf_fixture)
        self.proxy = FakeUnixDomainMetadataProxy(self.fake_conf)

    def test__get_socket_mode_user(self):
        self.fake_conf_fixture.config(
            metadata_proxy_socket_mode=meta_conf.USER_MODE)
        mode = self.proxy._get_socket_mode()
        self.assertEqual(proxy_base.MODE_MAP[meta_conf.USER_MODE], mode)

    def test__get_socket_mode_deduce_user_root(self):
        self.fake_conf_fixture.config(
            metadata_proxy_socket_mode=meta_conf.DEDUCE_MODE,
            metadata_proxy_user='root')
        mode = self.proxy._get_socket_mode()
        self.assertEqual(proxy_base.MODE_MAP[meta_conf.USER_MODE], mode)

    @mock.patch.object(proxy_base.agent_utils, 'is_effective_group')
    @mock.patch.object(proxy_base.agent_utils, 'is_effective_user')
    def test__get_socket_mode_deduce_group(self, mock_ieu, mock_ieg):
        self.fake_conf_fixture.config(
            metadata_proxy_socket_mode=meta_conf.DEDUCE_MODE,
            metadata_proxy_user='fake',
            metadata_proxy_group='fake')
        # Always force non-effective user
        mock_ieu.return_value = False
        # group effective
        mock_ieg.return_value = True
        mode = self.proxy._get_socket_mode()
        self.assertEqual(proxy_base.MODE_MAP[meta_conf.GROUP_MODE], mode)
        # group non-effective
        mock_ieg.return_value = False
        mode = self.proxy._get_socket_mode()
        self.assertEqual(proxy_base.MODE_MAP[meta_conf.ALL_MODE], mode)
