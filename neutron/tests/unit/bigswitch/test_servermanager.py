# Copyright 2014 Big Switch Networks, Inc.  All rights reserved.
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
# @author: Kevin Benton, kevin.benton@bigswitch.com
#
import httplib
import socket

from contextlib import nested
import mock
from oslo.config import cfg

from neutron.manager import NeutronManager
from neutron.openstack.common import importutils
from neutron.plugins.bigswitch import servermanager
from neutron.tests.unit.bigswitch import test_restproxy_plugin as test_rp

HTTPCON = 'httplib.HTTPConnection'
SERVERMANAGER = 'neutron.plugins.bigswitch.servermanager'


class ServerManagerTests(test_rp.BigSwitchProxyPluginV2TestCase):

    def test_no_servers(self):
        cfg.CONF.set_override('servers', [], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_malformed_servers(self):
        cfg.CONF.set_override('servers', ['a:b:c'], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_sticky_cert_fetch_fail(self):
        pl = NeutronManager.get_plugin()
        pl.servers.ssl = True
        with mock.patch(
            'ssl.get_server_certificate',
            side_effect=Exception('There is no more entropy in the universe')
        ) as sslgetmock:
            self.assertRaises(
                cfg.Error,
                pl.servers._get_combined_cert_for_server,
                *('example.org', 443)
            )
            sslgetmock.assert_has_calls([mock.call(('example.org', 443))])

    def test_consistency_watchdog(self):
        pl = NeutronManager.get_plugin()
        pl.servers.capabilities = []
        self.watch_p.stop()
        with nested(
            mock.patch('eventlet.sleep'),
            mock.patch(
                SERVERMANAGER + '.ServerPool.rest_call',
                side_effect=servermanager.RemoteRestError(
                    reason='Failure to break loop'
                )
            )
        ) as (smock, rmock):
            # should return immediately without consistency capability
            pl.servers._consistency_watchdog()
            self.assertFalse(smock.called)
            pl.servers.capabilities = ['consistency']
            self.assertRaises(servermanager.RemoteRestError,
                              pl.servers._consistency_watchdog)

    def test_file_put_contents(self):
        pl = NeutronManager.get_plugin()
        with mock.patch(SERVERMANAGER + '.open', create=True) as omock:
            pl.servers._file_put_contents('somepath', 'contents')
            omock.assert_has_calls([mock.call('somepath', 'w')])
            omock.return_value.__enter__.return_value.assert_has_calls([
                mock.call.write('contents')
            ])

    def test_combine_certs_to_file(self):
        pl = NeutronManager.get_plugin()
        with mock.patch(SERVERMANAGER + '.open', create=True) as omock:
            omock.return_value.__enter__().read.return_value = 'certdata'
            pl.servers._combine_certs_to_file(['cert1.pem', 'cert2.pem'],
                                              'combined.pem')
            # mock shared between read and write file handles so the calls
            # are mixed together
            omock.assert_has_calls([
                mock.call('combined.pem', 'w'),
                mock.call('cert1.pem', 'r'),
                mock.call('cert2.pem', 'r'),
            ], any_order=True)
            omock.return_value.__enter__.return_value.assert_has_calls([
                mock.call.read(),
                mock.call.write('certdata'),
                mock.call.read(),
                mock.call.write('certdata')
            ])

    def test_reconnect_cached_connection(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASH'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/first')
            # raise an error on re-use to verify reconnect
            # return okay the second time so the reconnect works
            rv.request.side_effect = [httplib.ImproperConnectionState(),
                                      mock.MagicMock()]
            sp.servers[0].rest_call('GET', '/second')
        uris = [c[1][1] for c in rv.request.mock_calls]
        expected = [
            sp.base_uri + '/first',
            sp.base_uri + '/second',
            sp.base_uri + '/second',
        ]
        self.assertEqual(uris, expected)

    def test_no_reconnect_recurse_to_infinity(self):
        # retry uses recursion when a reconnect is necessary
        # this test makes sure it stops after 1 recursive call
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            # hash header must be string instead of mock object
            rv.getresponse.return_value.getheader.return_value = 'HASH'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/first')
            # after retrying once, the rest call should raise the
            # exception up
            rv.request.side_effect = httplib.ImproperConnectionState()
            self.assertRaises(httplib.ImproperConnectionState,
                              sp.servers[0].rest_call,
                              *('GET', '/second'))
            # 1 for the first call, 2 for the second with retry
            self.assertEqual(rv.request.call_count, 3)

    def test_socket_error(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            conmock.return_value.request.side_effect = socket.timeout()
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))


class TestSockets(test_rp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        super(TestSockets, self).setUp()
        # http patch must not be running or it will mangle the servermanager
        # import where the https connection classes are defined
        self.httpPatch.stop()
        self.sm = importutils.import_module(SERVERMANAGER)

    def test_socket_create_attempt(self):
        # exercise the socket creation to make sure it works on both python
        # versions
        con = self.sm.HTTPSConnectionWithValidation('127.0.0.1', 0, timeout=1)
        # if httpcon was created, a connect attempt should raise a socket error
        self.assertRaises(socket.error, con.connect)
