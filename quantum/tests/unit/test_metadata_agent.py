# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
#
# @author: Mark McClain, DreamHost

import socket

import mock
import testtools
import webob

from quantum.agent.metadata import agent
from quantum.tests import base
from quantum.common import utils


class FakeConf(object):
    admin_user = 'quantum'
    admin_password = 'password'
    admin_tenant_name = 'tenant'
    auth_url = 'http://127.0.0.1'
    auth_strategy = 'keystone'
    auth_region = 'region'
    nova_metadata_ip = '9.9.9.9'
    nova_metadata_port = 8775
    metadata_proxy_shared_secret = 'secret'


class TestMetadataProxyHandler(base.BaseTestCase):
    def setUp(self):
        super(TestMetadataProxyHandler, self).setUp()
        self.qclient_p = mock.patch('quantumclient.v2_0.client.Client')
        self.qclient = self.qclient_p.start()
        self.addCleanup(self.qclient_p.stop)

        self.log_p = mock.patch.object(agent, 'LOG')
        self.log = self.log_p.start()
        self.addCleanup(self.log_p.stop)

        self.handler = agent.MetadataProxyHandler(FakeConf)

    def test_call(self):
        req = mock.Mock()
        with mock.patch.object(self.handler, '_get_instance_id') as get_id:
            get_id.return_value = 'id'
            with mock.patch.object(self.handler, '_proxy_request') as proxy:
                proxy.return_value = 'value'

                retval = self.handler(req)
                self.assertEqual(retval, 'value')

    def test_call_no_instance_match(self):
        req = mock.Mock()
        with mock.patch.object(self.handler, '_get_instance_id') as get_id:
            get_id.return_value = None
            retval = self.handler(req)
            self.assertIsInstance(retval, webob.exc.HTTPNotFound)

    def test_call_internal_server_error(self):
        req = mock.Mock()
        with mock.patch.object(self.handler, '_get_instance_id') as get_id:
            get_id.side_effect = Exception
            retval = self.handler(req)
            self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)
            self.assertEqual(len(self.log.mock_calls), 2)

    def _get_instance_id_helper(self, headers, list_ports_retval,
                                networks=None, router_id=None):
        headers['X-Forwarded-For'] = '192.168.1.1'
        req = mock.Mock(headers=headers)

        def mock_list_ports(*args, **kwargs):
            return {'ports': list_ports_retval.pop(0)}

        self.qclient.return_value.list_ports.side_effect = mock_list_ports
        retval = self.handler._get_instance_id(req)

        expected = [
            mock.call(
                username=FakeConf.admin_user,
                tenant_name=FakeConf.admin_tenant_name,
                region_name=FakeConf.auth_region,
                auth_url=FakeConf.auth_url,
                password=FakeConf.admin_password,
                auth_strategy=FakeConf.auth_strategy)
        ]

        if router_id:
            expected.append(
                mock.call().list_ports(
                    device_id=router_id,
                    device_owner='network:router_interface'
                )
            )

        expected.append(
            mock.call().list_ports(
                network_id=networks or [],
                fixed_ips=['ip_address=192.168.1.1'])
        )

        self.qclient.assert_has_calls(expected)

        return retval

    def test_get_instance_id_router_id(self):
        router_id = 'the_id'
        headers = {
            'X-Quantum-Router-ID': router_id
        }

        networks = ['net1', 'net2']
        ports = [
            [{'network_id': 'net1'}, {'network_id': 'net2'}],
            [{'device_id': 'device_id'}]
        ]

        self.assertEqual(
            self._get_instance_id_helper(headers, ports, networks=networks,
                                         router_id=router_id),
            'device_id'
        )

    def test_get_instance_id_router_id_no_match(self):
        router_id = 'the_id'
        headers = {
            'X-Quantum-Router-ID': router_id
        }

        networks = ['net1', 'net2']
        ports = [
            [{'network_id': 'net1'}, {'network_id': 'net2'}],
            []
        ]

        self.assertIsNone(
            self._get_instance_id_helper(headers, ports, networks=networks,
                                         router_id=router_id),
        )

    def test_get_instance_id_network_id(self):
        network_id = 'the_id'
        headers = {
            'X-Quantum-Network-ID': network_id
        }

        ports = [
            [{'device_id': 'device_id'}]
        ]

        self.assertEqual(
            self._get_instance_id_helper(headers, ports, networks=['the_id']),
            'device_id'
        )

    def test_get_instance_id_network_id_no_match(self):
        network_id = 'the_id'
        headers = {
            'X-Quantum-Network-ID': network_id
        }

        ports = [[]]

        self.assertIsNone(
            self._get_instance_id_helper(headers, ports, networks=['the_id'])
        )

    def _proxy_request_test_helper(self, response_code):
        hdrs = {'X-Forwarded-For': '8.8.8.8'}
        req = mock.Mock(path_info='/the_path', query_string='', headers=hdrs)
        resp = mock.Mock(status=response_code)
        with mock.patch.object(self.handler, '_sign_instance_id') as sign:
            sign.return_value = 'signed'
            with mock.patch('httplib2.Http') as mock_http:
                mock_http.return_value.request.return_value = (resp, 'content')

                retval = self.handler._proxy_request('the_id', req)
                mock_http.assert_has_calls([
                    mock.call().request(
                        'http://9.9.9.9:8775/the_path',
                        headers={
                            'X-Forwarded-For': '8.8.8.8',
                            'X-Instance-ID-Signature': 'signed',
                            'X-Instance-ID': 'the_id'
                        }
                    )]
                )

                return retval

    def test_proxy_request_200(self):
        self.assertEqual('content', self._proxy_request_test_helper(200))

    def test_proxy_request_403(self):
        self.assertIsInstance(self._proxy_request_test_helper(403),
                              webob.exc.HTTPForbidden)

    def test_proxy_request_404(self):
        self.assertIsInstance(self._proxy_request_test_helper(404),
                              webob.exc.HTTPNotFound)

    def test_proxy_request_500(self):
        self.assertIsInstance(self._proxy_request_test_helper(500),
                              webob.exc.HTTPInternalServerError)

    def test_proxy_request_other_code(self):
        with testtools.ExpectedException(Exception):
            self._proxy_request_test_helper(302)

    def test_sign_instance_id(self):
        self.assertEqual(
            self.handler._sign_instance_id('foo'),
            '773ba44693c7553d6ee20f61ea5d2757a9a4f4a44d2841ae4e95b52e4cd62db4'
        )


class TestUnixDomainHttpProtocol(base.BaseTestCase):
    def test_init_empty_client(self):
        u = agent.UnixDomainHttpProtocol(mock.Mock(), '', mock.Mock())
        self.assertEqual(u.client_address, ('<local>', 0))

    def test_init_with_client(self):
        u = agent.UnixDomainHttpProtocol(mock.Mock(), 'foo', mock.Mock())
        self.assertEqual(u.client_address, 'foo')


class TestUnixDomainWSGIServer(base.BaseTestCase):
    def setUp(self):
        super(TestUnixDomainWSGIServer, self).setUp()
        self.eventlet_p = mock.patch.object(agent, 'eventlet')
        self.eventlet = self.eventlet_p.start()
        self.addCleanup(self.eventlet_p.stop)
        self.server = agent.UnixDomainWSGIServer('test')

    def test_start(self):
        mock_app = mock.Mock()
        with mock.patch.object(self.server, 'pool') as pool:
            self.server.start(mock_app, '/the/path')
            self.eventlet.assert_has_calls([
                mock.call.listen(
                    '/the/path',
                    family=socket.AF_UNIX,
                    backlog=128
                )]
            )
            pool.spawn_n.assert_called_once_with(
                self.server._run,
                mock_app,
                self.eventlet.listen.return_value
            )

    def test_run(self):
        with mock.patch.object(agent, 'logging') as logging:
            self.server._run('app', 'sock')

            self.eventlet.wsgi.server.called_once_with(
                'sock',
                'app',
                self.server.pool,
                agent.UnixDomainHttpProtocol,
                mock.ANY
            )
            self.assertTrue(len(logging.mock_calls))


class TestUnixDomainMetadataProxy(base.BaseTestCase):
    def setUp(self):
        super(TestUnixDomainMetadataProxy, self).setUp()
        self.cfg_p = mock.patch.object(agent, 'cfg')
        self.cfg = self.cfg_p.start()
        self.addCleanup(self.cfg_p.stop)
        self.cfg.CONF.metadata_proxy_socket = '/the/path'

    def test_init_doesnot_exists(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.makedirs') as makedirs:
                isdir.return_value = False
                agent.UnixDomainMetadataProxy(mock.Mock())

                isdir.assert_called_once_with('/the')
                makedirs.assert_called_once_with('/the', 0755)

    def test_init_exists(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                isdir.return_value = True
                agent.UnixDomainMetadataProxy(mock.Mock())

                isdir.assert_called_once_with('/the')
                unlink.assert_called_once_with('/the/path')

    def test_init_exists_unlink_no_file(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                with mock.patch('os.path.exists') as exists:
                    isdir.return_value = True
                    exists.return_value = False
                    unlink.side_effect = OSError

                    agent.UnixDomainMetadataProxy(mock.Mock())

                    isdir.assert_called_once_with('/the')
                    unlink.assert_called_once_with('/the/path')
                    exists.assert_called_once_with('/the/path')

    def test_init_exists_unlink_fails_file_still_exists(self):
        with mock.patch('os.path.isdir') as isdir:
            with mock.patch('os.unlink') as unlink:
                with mock.patch('os.path.exists') as exists:
                    isdir.return_value = True
                    exists.return_value = True
                    unlink.side_effect = OSError

                    with testtools.ExpectedException(OSError):
                        agent.UnixDomainMetadataProxy(mock.Mock())

                    isdir.assert_called_once_with('/the')
                    unlink.assert_called_once_with('/the/path')
                    exists.assert_called_once_with('/the/path')

    def test_run(self):
        with mock.patch.object(agent, 'MetadataProxyHandler') as handler:
            with mock.patch.object(agent, 'UnixDomainWSGIServer') as server:
                with mock.patch('os.path.isdir') as isdir:
                    with mock.patch('os.makedirs') as makedirs:
                        isdir.return_value = False

                        p = agent.UnixDomainMetadataProxy(self.cfg.CONF)
                        p.run()

                        isdir.assert_called_once_with('/the')
                        makedirs.assert_called_once_with('/the', 0755)
                        server.assert_has_calls([
                            mock.call('quantum-metadata-agent'),
                            mock.call().start(handler.return_value,
                                              '/the/path'),
                            mock.call().wait()]
                        )

    def test_main(self):
        with mock.patch.object(agent, 'UnixDomainMetadataProxy') as proxy:
            with mock.patch('eventlet.monkey_patch') as eventlet:
                with mock.patch.object(agent, 'config') as config:
                    with mock.patch.object(agent, 'cfg') as cfg:
                        with mock.patch.object(utils, 'cfg'):
                            agent.main()

                            self.assertTrue(eventlet.called)
                            self.assertTrue(config.setup_logging.called)
                            proxy.assert_has_calls([
                                mock.call(cfg.CONF),
                                mock.call().run()]
                            )
