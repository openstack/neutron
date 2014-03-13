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
from contextlib import nested
import mock
from oslo.config import cfg

from neutron.manager import NeutronManager
from neutron.plugins.bigswitch import servermanager
from neutron.tests.unit.bigswitch import test_restproxy_plugin as test_rp

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
