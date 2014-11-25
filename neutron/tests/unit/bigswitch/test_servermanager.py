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
import contextlib
import httplib
import socket
import ssl

import mock
from oslo.config import cfg

from neutron import context
from neutron import manager
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils
from neutron.plugins.bigswitch.db import consistency_db as cdb
from neutron.plugins.bigswitch import servermanager
from neutron.tests.unit.bigswitch import test_restproxy_plugin as test_rp

SERVERMANAGER = 'neutron.plugins.bigswitch.servermanager'
HTTPCON = SERVERMANAGER + '.httplib.HTTPConnection'
HTTPSCON = SERVERMANAGER + '.HTTPSConnectionWithValidation'


class ServerManagerTests(test_rp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        self.socket_mock = mock.patch(
            SERVERMANAGER + '.socket.create_connection').start()
        self.wrap_mock = mock.patch(SERVERMANAGER + '.ssl.wrap_socket').start()
        super(ServerManagerTests, self).setUp()
        # http patch must not be running or it will mangle the servermanager
        # import where the https connection classes are defined
        self.httpPatch.stop()
        self.sm = importutils.import_module(SERVERMANAGER)

    def test_no_servers(self):
        cfg.CONF.set_override('servers', [], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_malformed_servers(self):
        cfg.CONF.set_override('servers', ['1.2.3.4', '1.1.1.1:a'], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_ipv6_server_address(self):
        cfg.CONF.set_override(
            'servers', ['[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]:80'],
            'RESTPROXY')
        s = servermanager.ServerPool()
        self.assertEqual(s.servers[0].server,
                         '[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]')

    def test_sticky_cert_fetch_fail(self):
        pl = manager.NeutronManager.get_plugin()
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
            sslgetmock.assert_has_calls([mock.call(
                  ('example.org', 443), ssl_version=ssl.PROTOCOL_TLSv1)])

    def test_consistency_watchdog_stops_with_0_polling_interval(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.capabilities = ['consistency']
        self.watch_p.stop()
        with mock.patch('eventlet.sleep') as smock:
            # should return immediately a polling interval of 0
            pl.servers._consistency_watchdog(0)
            self.assertFalse(smock.called)

    def test_consistency_watchdog(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.capabilities = []
        self.watch_p.stop()
        with contextlib.nested(
            mock.patch('eventlet.sleep'),
            mock.patch(
                SERVERMANAGER + '.ServerPool.rest_call',
                side_effect=servermanager.RemoteRestError(
                    reason='Failure to trigger except clause.'
                )
            ),
            mock.patch(
                SERVERMANAGER + '.LOG.exception',
                side_effect=KeyError('Failure to break loop')
            )
        ) as (smock, rmock, lmock):
            # should return immediately without consistency capability
            pl.servers._consistency_watchdog()
            self.assertFalse(smock.called)
            pl.servers.capabilities = ['consistency']
            self.assertRaises(KeyError,
                              pl.servers._consistency_watchdog)
            rmock.assert_called_with('GET', '/health', '', {}, [], False)
            self.assertEqual(1, len(lmock.mock_calls))

    def test_consistency_hash_header(self):
        # mock HTTP class instead of rest_call so we can see headers
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            rv.getresponse.return_value.status = 200
            rv.getresponse.return_value.read.return_value = ''
            with self.network() as network:
                callheaders = rv.request.mock_calls[0][1][3]
                self.assertIn('X-BSN-BVS-HASH-MATCH', callheaders)
                # first call will be empty to indicate no previous state hash
                self.assertEqual(callheaders['X-BSN-BVS-HASH-MATCH'], '')
                # change the header that will be received on delete call
                rv.getresponse.return_value.getheader.return_value = 'HASH2'
            self._delete('networks', network['network']['id'])
            # net delete should have used header received on create
            callheaders = rv.request.mock_calls[1][1][3]
            self.assertEqual(callheaders['X-BSN-BVS-HASH-MATCH'], 'HASHHEADER')

            # create again should now use header received from prev delete
            with self.network():
                callheaders = rv.request.mock_calls[2][1][3]
                self.assertIn('X-BSN-BVS-HASH-MATCH', callheaders)
                self.assertEqual(callheaders['X-BSN-BVS-HASH-MATCH'],
                                 'HASH2')

    def test_consistency_hash_header_no_update_on_bad_response(self):
        # mock HTTP class instead of rest_call so we can see headers
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            rv.getresponse.return_value.status = 200
            rv.getresponse.return_value.read.return_value = ''
            with self.network() as net:
                # change the header that will be received on delete call
                rv.getresponse.return_value.getheader.return_value = 'EVIL'
                rv.getresponse.return_value.status = 'GARBAGE'
                self._delete('networks', net['network']['id'])

            # create again should not use header from delete call
            with self.network():
                callheaders = rv.request.mock_calls[2][1][3]
                self.assertIn('X-BSN-BVS-HASH-MATCH', callheaders)
                self.assertEqual(callheaders['X-BSN-BVS-HASH-MATCH'],
                                 'HASHHEADER')

    def test_file_put_contents(self):
        pl = manager.NeutronManager.get_plugin()
        with mock.patch(SERVERMANAGER + '.open', create=True) as omock:
            pl.servers._file_put_contents('somepath', 'contents')
            omock.assert_has_calls([mock.call('somepath', 'w')])
            omock.return_value.__enter__.return_value.assert_has_calls([
                mock.call.write('contents')
            ])

    def test_combine_certs_to_file(self):
        pl = manager.NeutronManager.get_plugin()
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

    def test_auth_header(self):
        cfg.CONF.set_override('server_auth', 'username:pass', 'RESTPROXY')
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.rest_create_network('tenant', 'network')
        callheaders = rv.request.mock_calls[0][1][3]
        self.assertIn('Authorization', callheaders)
        self.assertEqual(callheaders['Authorization'],
                         'Basic dXNlcm5hbWU6cGFzcw==')

    def test_header_add(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.servers[0].rest_call('GET', '/', headers={'EXTRA-HEADER': 'HI'})
        callheaders = rv.request.mock_calls[0][1][3]
        # verify normal headers weren't mangled
        self.assertIn('Content-type', callheaders)
        self.assertEqual(callheaders['Content-type'],
                         'application/json')
        # verify new header made it in
        self.assertIn('EXTRA-HEADER', callheaders)
        self.assertEqual(callheaders['EXTRA-HEADER'], 'HI')

    def test_req_context_header(self):
        sp = manager.NeutronManager.get_plugin().servers
        ncontext = context.Context('uid', 'tid')
        sp.set_context(ncontext)
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.rest_action('GET', '/')
        callheaders = rv.request.mock_calls[0][1][3]
        self.assertIn(servermanager.REQ_CONTEXT_HEADER, callheaders)
        ctxdct = ncontext.to_dict()
        # auth token is not included
        ctxdct.pop('auth_token')
        self.assertEqual(
            ctxdct, jsonutils.loads(
                  callheaders[servermanager.REQ_CONTEXT_HEADER]))

    def test_capabilities_retrieval(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value.getresponse.return_value
            rv.getheader.return_value = 'HASHHEADER'

            # each server will get different capabilities
            rv.read.side_effect = ['["a","b","c"]', '["b","c","d"]']
            # pool capabilities is intersection between both
            self.assertEqual(set(['b', 'c']), sp.get_capabilities())
            self.assertEqual(2, rv.read.call_count)

            # the pool should cache after the first call so no more
            # HTTP calls should be made
            rv.read.side_effect = ['["w","x","y"]', '["x","y","z"]']
            self.assertEqual(set(['b', 'c']), sp.get_capabilities())
            self.assertEqual(2, rv.read.call_count)

    def test_capabilities_retrieval_failure(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value.getresponse.return_value
            rv.getheader.return_value = 'HASHHEADER'
            # a failure to parse should result in an empty capability set
            rv.read.return_value = 'XXXXX'
            self.assertEqual([], sp.servers[0].get_capabilities())

            # One broken server should affect all capabilities
            rv.read.side_effect = ['{"a": "b"}', '["b","c","d"]']
            self.assertEqual(set(), sp.get_capabilities())

    def test_reconnect_on_timeout_change(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/', timeout=10)
            # even with keep-alive enabled, a change in timeout will trigger
            # a reconnect
            sp.servers[0].rest_call('GET', '/', timeout=75)
        conmock.assert_has_calls([
            mock.call('localhost', 9000, timeout=10),
            mock.call('localhost', 9000, timeout=75),
        ], any_order=True)

    def test_connect_failures(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON, return_value=None):
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))
        # verify same behavior on ssl class
        sp.servers[0].currentcon = False
        sp.servers[0].ssl = True
        with mock.patch(HTTPSCON, return_value=None):
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))

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

    def test_cert_get_fail(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.ssl = True
        with mock.patch('os.path.exists', return_value=False):
            self.assertRaises(cfg.Error,
                              pl.servers._get_combined_cert_for_server,
                              *('example.org', 443))

    def test_cert_make_dirs(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.ssl = True
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        # pretend base dir exists, 3 children don't, and host cert does
        with contextlib.nested(
            mock.patch('os.path.exists', side_effect=[True, False, False,
                                                      False, True]),
            mock.patch('os.makedirs'),
            mock.patch(SERVERMANAGER + '.ServerPool._combine_certs_to_file')
        ) as (exmock, makemock, combmock):
            # will raise error because no certs found
            self.assertIn(
                'example.org',
                pl.servers._get_combined_cert_for_server('example.org', 443)
            )
            base = cfg.CONF.RESTPROXY.ssl_cert_directory
            hpath = base + '/host_certs/example.org.pem'
            combpath = base + '/combined/example.org.pem'
            combmock.assert_has_calls([mock.call([hpath], combpath)])
            self.assertEqual(exmock.call_count, 5)
            self.assertEqual(makemock.call_count, 3)

    def test_no_cert_error(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.ssl = True
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        # pretend base dir exists and 3 children do, but host cert doesn't
        with mock.patch(
            'os.path.exists',
            side_effect=[True, True, True, True, False]
        ) as exmock:
            # will raise error because no certs found
            self.assertRaises(
                cfg.Error,
                pl.servers._get_combined_cert_for_server,
                *('example.org', 443)
            )
            self.assertEqual(exmock.call_count, 5)

    def test_action_success(self):
        pl = manager.NeutronManager.get_plugin()
        self.assertTrue(pl.servers.action_success((200,)))

    def test_server_failure(self):
        pl = manager.NeutronManager.get_plugin()
        self.assertTrue(pl.servers.server_failure((404,)))
        # server failure has an ignore codes option
        self.assertFalse(pl.servers.server_failure((404,),
                                                   ignore_codes=[404]))

    def test_retry_on_unavailable(self):
        pl = manager.NeutronManager.get_plugin()
        with contextlib.nested(
            mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                       return_value=(httplib.SERVICE_UNAVAILABLE, 0, 0, 0)),
            mock.patch(SERVERMANAGER + '.time.sleep')
        ) as (srestmock, tmock):
            # making a call should trigger retries with sleeps in between
            pl.servers.rest_call('GET', '/', '', None, [])
            rest_call = [mock.call('GET', '/', '', None, False, reconnect=True,
                                   hash_handler=mock.ANY)]
            rest_call_count = (
                servermanager.HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT + 1)
            srestmock.assert_has_calls(rest_call * rest_call_count)
            sleep_call = [mock.call(
                servermanager.HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL)]
            # should sleep 1 less time than the number of calls
            sleep_call_count = rest_call_count - 1
            tmock.assert_has_calls(sleep_call * sleep_call_count)

    def test_delete_failure_sets_bad_hash(self):
        pl = manager.NeutronManager.get_plugin()
        hash_handler = cdb.HashHandler()
        with mock.patch(
            SERVERMANAGER + '.ServerProxy.rest_call',
            return_value=(httplib.INTERNAL_SERVER_ERROR, 0, 0, 0)
        ):
            # a failed delete call should put a bad hash in the DB
            pl.servers.rest_call('DELETE', '/', '', None, [])
            self.assertEqual('INCONSISTENT,INCONSISTENT',
                             hash_handler.read_for_update())

    def test_conflict_triggers_sync(self):
        pl = manager.NeutronManager.get_plugin()
        with mock.patch(
            SERVERMANAGER + '.ServerProxy.rest_call',
            return_value=(httplib.CONFLICT, 0, 0, 0)
        ) as srestmock:
            # making a call should trigger a conflict sync
            pl.servers.rest_call('GET', '/', '', None, [])
            srestmock.assert_has_calls([
                mock.call('GET', '/', '', None, False, reconnect=True,
                          hash_handler=mock.ANY),
                mock.call('PUT', '/topology',
                          {'routers': [], 'networks': []},
                          timeout=None)
            ])

    def test_conflict_sync_raises_error_without_topology(self):
        pl = manager.NeutronManager.get_plugin()
        pl.servers.get_topo_function = None
        with mock.patch(
            SERVERMANAGER + '.ServerProxy.rest_call',
            return_value=(httplib.CONFLICT, 0, 0, 0)
        ):
            # making a call should trigger a conflict sync that will
            # error without the topology function set
            self.assertRaises(
                cfg.Error,
                pl.servers.rest_call,
                *('GET', '/', '', None, [])
            )

    def test_floating_calls(self):
        pl = manager.NeutronManager.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerPool.rest_action') as ramock:
            body1 = {'id': 'somefloat'}
            body2 = {'name': 'myfl'}
            pl.servers.rest_create_floatingip('tenant', body1)
            pl.servers.rest_update_floatingip('tenant', body2, 'id')
            pl.servers.rest_delete_floatingip('tenant', 'oldid')
            ramock.assert_has_calls([
                mock.call('PUT', '/tenants/tenant/floatingips/somefloat',
                          body1,
                          errstr=u'Unable to create floating IP: %s'),
                mock.call('PUT', '/tenants/tenant/floatingips/id',
                          body2,
                          errstr=u'Unable to update floating IP: %s'),
                mock.call('DELETE', '/tenants/tenant/floatingips/oldid',
                          errstr=u'Unable to delete floating IP: %s')
            ])

    def test_HTTPSConnectionWithValidation_without_cert(self):
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.source_address = '127.0.0.1'
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_TLSv1
        )])
        self.assertEqual(con.sock, self.wrap_mock())

    def test_HTTPSConnectionWithValidation_with_cert(self):
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.combined_cert = 'SOMECERTS.pem'
        con.source_address = '127.0.0.1'
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, ca_certs='SOMECERTS.pem',
            cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1
        )])
        self.assertEqual(con.sock, self.wrap_mock())

    def test_HTTPSConnectionWithValidation_tunnel(self):
        tunnel_mock = mock.patch.object(
            self.sm.HTTPSConnectionWithValidation,
            '_tunnel').start()
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.source_address = '127.0.0.1'
        if not hasattr(con, 'set_tunnel'):
            # no tunnel support in py26
            return
        con.set_tunnel('myproxy.local', 3128)
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_TLSv1
        )])
        # _tunnel() doesn't take any args
        tunnel_mock.assert_has_calls([mock.call()])
        self.assertEqual(con._tunnel_host, 'myproxy.local')
        self.assertEqual(con._tunnel_port, 3128)
        self.assertEqual(con.sock, self.wrap_mock())


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
