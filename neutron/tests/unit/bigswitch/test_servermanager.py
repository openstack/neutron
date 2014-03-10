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
            mock.patch('time.sleep'),
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
