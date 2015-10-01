# Copyright 2012 New Dream Network, LLC (DreamHost)
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
import testtools
import webob

from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import namespace_proxy as ns_proxy
from neutron.common import exceptions
from neutron.common import utils
from neutron.tests import base


class FakeConf(object):
    admin_user = 'neutron'
    admin_password = 'password'
    admin_tenant_name = 'tenant'
    auth_url = 'http://127.0.0.1'
    auth_strategy = 'keystone'
    auth_region = 'region'
    nova_metadata_ip = '9.9.9.9'
    nova_metadata_port = 8775
    metadata_proxy_shared_secret = 'secret'


class TestNetworkMetadataProxyHandler(base.BaseTestCase):
    def setUp(self):
        super(TestNetworkMetadataProxyHandler, self).setUp()
        self.handler = ns_proxy.NetworkMetadataProxyHandler('router_id')

    def test_call(self):
        req = mock.Mock(headers={})
        with mock.patch.object(self.handler, '_proxy_request') as proxy_req:
            proxy_req.return_value = 'value'

            retval = self.handler(req)
            self.assertEqual(retval, 'value')
            proxy_req.assert_called_once_with(req.remote_addr,
                                              req.method,
                                              req.path_info,
                                              req.query_string,
                                              req.body)

    def test_no_argument_passed_to_init(self):
        with testtools.ExpectedException(
                exceptions.NetworkIdOrRouterIdRequiredError):
            ns_proxy.NetworkMetadataProxyHandler()

    def test_call_internal_server_error(self):
        req = mock.Mock(headers={})
        with mock.patch.object(self.handler, '_proxy_request') as proxy_req:
            proxy_req.side_effect = Exception
            retval = self.handler(req)
            self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)
            self.assertTrue(proxy_req.called)

    def test_proxy_request_router_200(self):
        self.handler.router_id = 'router_id'

        resp = mock.MagicMock(status=200)
        with mock.patch('httplib2.Http') as mock_http:
            resp.__getitem__.return_value = "text/plain"
            mock_http.return_value.request.return_value = (resp, 'content')

            retval = self.handler._proxy_request('192.168.1.1',
                                                 'GET',
                                                 '/latest/meta-data',
                                                 '',
                                                 '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method='GET',
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Router-ID': 'router_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )

            self.assertEqual(retval.headers['Content-Type'], 'text/plain')
            self.assertEqual(retval.body, 'content')

    def _test_proxy_request_network_200(self, content):
        self.handler.network_id = 'network_id'

        resp = mock.MagicMock(status=200)
        with mock.patch('httplib2.Http') as mock_http:
            resp.__getitem__.return_value = "application/json"
            mock_http.return_value.request.return_value = (resp, content)

            retval = self.handler._proxy_request('192.168.1.1',
                                                 'GET',
                                                 '/latest/meta-data',
                                                 '',
                                                 '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method='GET',
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Network-ID': 'network_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )

            self.assertEqual(retval.headers['Content-Type'],
                             'application/json')
            self.assertEqual(content, retval.body)

    def test_proxy_request_network_200(self):
        self._test_proxy_request_network_200('{}')

    def test_proxy_request_network_200_unicode_in_content(self):
        self._test_proxy_request_network_200('Gl\xfcck')

    def _test_proxy_request_network_4xx(self, status, method, expected):
        self.handler.network_id = 'network_id'

        resp = mock.Mock(status=status)
        with mock.patch('httplib2.Http') as mock_http:
            mock_http.return_value.request.return_value = (resp, '')

            retval = self.handler._proxy_request('192.168.1.1',
                                                 method,
                                                 '/latest/meta-data',
                                                 '',
                                                 '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method=method,
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Network-ID': 'network_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )

            self.assertIsInstance(retval, expected)

    def test_proxy_request_network_400(self):
        self._test_proxy_request_network_4xx(
            400, 'GET', webob.exc.HTTPBadRequest)

    def test_proxy_request_network_404(self):
        self._test_proxy_request_network_4xx(
            404, 'GET', webob.exc.HTTPNotFound)

    def test_proxy_request_network_409(self):
        self._test_proxy_request_network_4xx(
            409, 'POST', webob.exc.HTTPConflict)

    def test_proxy_request_network_500(self):
        self.handler.network_id = 'network_id'

        resp = mock.Mock(status=500)
        with mock.patch('httplib2.Http') as mock_http:
            mock_http.return_value.request.return_value = (resp, '')

            retval = self.handler._proxy_request('192.168.1.1',
                                                 'GET',
                                                 '/latest/meta-data',
                                                 '',
                                                 '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method='GET',
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Network-ID': 'network_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )

            self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)

    def test_proxy_request_network_418(self):
        self.handler.network_id = 'network_id'

        resp = mock.Mock(status=418)
        with mock.patch('httplib2.Http') as mock_http:
            mock_http.return_value.request.return_value = (resp, '')

            with testtools.ExpectedException(Exception):
                self.handler._proxy_request('192.168.1.1',
                                            'GET',
                                            '/latest/meta-data',
                                            '',
                                            '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method='GET',
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Network-ID': 'network_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )

    def test_proxy_request_network_exception(self):
        self.handler.network_id = 'network_id'

        mock.Mock(status=500)
        with mock.patch('httplib2.Http') as mock_http:
            mock_http.return_value.request.side_effect = Exception

            with testtools.ExpectedException(Exception):
                self.handler._proxy_request('192.168.1.1',
                                            'GET',
                                            '/latest/meta-data',
                                            '',
                                            '')

            mock_http.assert_has_calls([
                mock.call().request(
                    'http://169.254.169.254/latest/meta-data',
                    method='GET',
                    headers={
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Neutron-Network-ID': 'network_id'
                    },
                    connection_type=agent_utils.UnixDomainHTTPConnection,
                    body=''
                )]
            )


class TestProxyDaemon(base.BaseTestCase):
    def test_init(self):
        with mock.patch('neutron.agent.linux.daemon.Pidfile'):
            pd = ns_proxy.ProxyDaemon('pidfile', 9697, 'net_id', 'router_id')
            self.assertEqual(pd.router_id, 'router_id')
            self.assertEqual(pd.network_id, 'net_id')

    def test_run(self):
        with mock.patch('neutron.agent.linux.daemon.Pidfile'):
            with mock.patch('neutron.wsgi.Server') as Server:
                pd = ns_proxy.ProxyDaemon('pidfile', 9697, 'net_id',
                                          'router_id')
                pd.run()
                Server.assert_has_calls([
                    mock.call('neutron-network-metadata-proxy'),
                    mock.call().start(mock.ANY, 9697),
                    mock.call().wait()]
                )

    def test_main(self):
        with mock.patch.object(ns_proxy, 'ProxyDaemon') as daemon:
            with mock.patch.object(ns_proxy, 'config') as config:
                with mock.patch.object(ns_proxy, 'cfg') as cfg:
                    with mock.patch.object(utils, 'cfg') as utils_cfg:
                        cfg.CONF.router_id = 'router_id'
                        cfg.CONF.network_id = None
                        cfg.CONF.metadata_port = 9697
                        cfg.CONF.pid_file = 'pidfile'
                        cfg.CONF.daemonize = True
                        utils_cfg.CONF.log_opt_values.return_value = None
                        ns_proxy.main()

                        self.assertTrue(config.setup_logging.called)
                        daemon.assert_has_calls([
                            mock.call('pidfile', 9697,
                                      router_id='router_id',
                                      network_id=None,
                                      user=mock.ANY,
                                      group=mock.ANY,
                                      watch_log=mock.ANY),
                            mock.call().start()]
                        )

    def test_main_dont_fork(self):
        with mock.patch.object(ns_proxy, 'ProxyDaemon') as daemon:
            with mock.patch.object(ns_proxy, 'config') as config:
                with mock.patch.object(ns_proxy, 'cfg') as cfg:
                    with mock.patch.object(utils, 'cfg') as utils_cfg:
                        cfg.CONF.router_id = 'router_id'
                        cfg.CONF.network_id = None
                        cfg.CONF.metadata_port = 9697
                        cfg.CONF.pid_file = 'pidfile'
                        cfg.CONF.daemonize = False
                        utils_cfg.CONF.log_opt_values.return_value = None
                        ns_proxy.main()

                        self.assertTrue(config.setup_logging.called)
                        daemon.assert_has_calls([
                            mock.call('pidfile', 9697,
                                      router_id='router_id',
                                      network_id=None,
                                      user=mock.ANY,
                                      group=mock.ANY,
                                      watch_log=mock.ANY),
                            mock.call().run()]
                        )
