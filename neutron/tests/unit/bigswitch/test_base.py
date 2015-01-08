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
from oslo_config import cfg

import neutron.common.test_lib as test_lib
from neutron.plugins.bigswitch import config
from neutron.plugins.bigswitch.db import consistency_db
from neutron.tests.unit.bigswitch import fake_server


RESTPROXY_PKG_PATH = 'neutron.plugins.bigswitch.plugin'
L3_RESTPROXY_PKG_PATH = 'neutron.plugins.bigswitch.l3_router_plugin'
NOTIFIER = 'neutron.plugins.bigswitch.plugin.AgentNotifierApi'
CERTFETCH = 'neutron.plugins.bigswitch.servermanager.ServerPool._fetch_cert'
SERVER_MANAGER = 'neutron.plugins.bigswitch.servermanager'
HTTPCON = 'neutron.plugins.bigswitch.servermanager.httplib.HTTPConnection'
SPAWN = 'neutron.plugins.bigswitch.plugin.eventlet.GreenPool.spawn_n'
CWATCH = SERVER_MANAGER + '.ServerPool._consistency_watchdog'


class BigSwitchTestBase(object):

    _plugin_name = ('%s.NeutronRestProxyV2' % RESTPROXY_PKG_PATH)
    _l3_plugin_name = ('%s.L3RestProxy' % L3_RESTPROXY_PKG_PATH)

    def setup_config_files(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(consistency_db.clear_db)
        config.register_config()
        # Only try SSL on SSL tests
        cfg.CONF.set_override('server_ssl', False, 'RESTPROXY')
        cfg.CONF.set_override('ssl_cert_directory',
                              os.path.join(etc_path, 'ssl'), 'RESTPROXY')
        # The mock interferes with HTTP(S) connection caching
        cfg.CONF.set_override('cache_connections', False, 'RESTPROXY')
        cfg.CONF.set_override('service_plugins', ['bigswitch_l3'])
        cfg.CONF.set_override('add_meta_server_route', False, 'RESTPROXY')

    def setup_patches(self):
        self.dhcp_periodic_p = mock.patch(
            'neutron.db.agentschedulers_db.DhcpAgentSchedulerDbMixin.'
            'start_periodic_dhcp_agent_status_check')
        self.patched_dhcp_periodic = self.dhcp_periodic_p.start()
        self.plugin_notifier_p = mock.patch(NOTIFIER)
        # prevent any greenthreads from spawning
        self.spawn_p = mock.patch(SPAWN, new=lambda *args, **kwargs: None)
        # prevent the consistency watchdog from starting
        self.watch_p = mock.patch(CWATCH, new=lambda *args, **kwargs: None)
        # disable exception log to prevent json parse error from showing
        self.log_exc_p = mock.patch(SERVER_MANAGER + ".LOG.exception",
                                    new=lambda *args, **kwargs: None)
        self.log_exc_p.start()
        self.plugin_notifier_p.start()
        self.spawn_p.start()
        self.watch_p.start()

    def startHttpPatch(self):
        self.httpPatch = mock.patch(HTTPCON,
                                    new=fake_server.HTTPConnectionMock)
        self.httpPatch.start()

    def setup_db(self):
        # setup the db engine and models for the consistency db
        consistency_db.setup_db()
