# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import mock
from oslo.config import cfg

import neutron.common.test_lib as test_lib
from neutron.db import api as db
from neutron.plugins.bigswitch import config
from neutron.tests.unit.bigswitch import fake_server

RESTPROXY_PKG_PATH = 'neutron.plugins.bigswitch.plugin'
NOTIFIER = 'neutron.plugins.bigswitch.plugin.AgentNotifierApi'
CALLBACKS = 'neutron.plugins.bigswitch.plugin.RestProxyCallbacks'
CERTFETCH = 'neutron.plugins.bigswitch.servermanager.ServerPool._fetch_cert'
SERVER_MANAGER = 'neutron.plugins.bigswitch.servermanager'
HTTPCON = 'httplib.HTTPConnection'
SPAWN = 'eventlet.GreenPool.spawn_n'
CWATCH = SERVER_MANAGER + '.ServerPool._consistency_watchdog'


class BigSwitchTestBase(object):

    _plugin_name = ('%s.NeutronRestProxyV2' % RESTPROXY_PKG_PATH)

    def setup_config_files(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]
        self.addCleanup(cfg.CONF.reset)
        config.register_config()
        # Only try SSL on SSL tests
        cfg.CONF.set_override('server_ssl', False, 'RESTPROXY')
        cfg.CONF.set_override('ssl_cert_directory',
                              os.path.join(etc_path, 'ssl'), 'RESTPROXY')
        # The mock interferes with HTTP(S) connection caching
        cfg.CONF.set_override('cache_connections', False, 'RESTPROXY')

    def setup_patches(self):
        self.httpPatch = mock.patch(HTTPCON, create=True,
                                    new=fake_server.HTTPConnectionMock)
        self.plugin_notifier_p = mock.patch(NOTIFIER)
        self.callbacks_p = mock.patch(CALLBACKS)
        self.spawn_p = mock.patch(SPAWN)
        self.watch_p = mock.patch(CWATCH)
        self.addCleanup(db.clear_db)
        self.callbacks_p.start()
        self.plugin_notifier_p.start()
        self.httpPatch.start()
        self.spawn_p.start()
        self.watch_p.start()
