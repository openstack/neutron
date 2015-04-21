# Copyright 2015 Red Hat, Inc.
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

from distutils import spawn
import functools

import fixtures
from neutronclient.common import exceptions as nc_exc
from neutronclient.v2_0 import client
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from neutron.agent.linux import async_process
from neutron.agent.linux import utils
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import config_fixtures

LOG = logging.getLogger(__name__)

# This should correspond the directory from which infra retrieves log files
DEFAULT_LOG_DIR = '/opt/stack/logs'


class ProcessFixture(fixtures.Fixture):
    def __init__(self, name, exec_name, config_filenames):
        self.name = name
        self.exec_name = exec_name
        self.config_filenames = config_filenames
        self.process = None

    def setUp(self):
        super(ProcessFixture, self).setUp()
        self.start()

    def start(self):
        fmt = self.name + "--%Y-%m-%d--%H%M%S.log"
        cmd = [spawn.find_executable(self.exec_name),
               '--log-dir', DEFAULT_LOG_DIR,
               '--log-file', timeutils.strtime(fmt=fmt)]
        for filename in self.config_filenames:
            cmd += ['--config-file', filename]
        self.process = async_process.AsyncProcess(cmd)
        self.process.start(block=True)

    def stop(self):
        self.process.stop(block=True)

    def cleanUp(self, *args, **kwargs):
        self.stop()
        super(ProcessFixture, self).cleanUp(*args, **kwargs)


class EnvironmentFixture(fixtures.Fixture):

    def setUp(self):
        super(EnvironmentFixture, self).setUp()

        self.temp_dir = self.useFixture(fixtures.TempDir()).path

        self.neutron_server = self.useFixture(
            NeutronServerFixture(self.temp_dir))

    def wait_until_env_is_up(self, agents_count=0):
        utils.wait_until_true(
            functools.partial(self._processes_are_ready, agents_count))

    def _processes_are_ready(self, agents_count):
        try:
            running_agents = self.neutron_server.client.list_agents()['agents']
            LOG.warn("There are %d agents running!", len(running_agents))
            return len(running_agents) == agents_count
        except nc_exc.NeutronClientException:
            LOG.warn("neutron-server isn't up yet (cannot contact REST API).")
            return False


class NeutronServerFixture(fixtures.Fixture):

    NEUTRON_SERVER = "neutron-server"

    def __init__(self, temp_dir):
        self.temp_dir = temp_dir

    def setUp(self):
        super(NeutronServerFixture, self).setUp()

        self.neutron_cfg_fixture = config_fixtures.NeutronConfigFixture(
            self.temp_dir, cfg.CONF.database.connection)
        self.plugin_cfg_fixture = config_fixtures.ML2ConfigFixture(
            self.temp_dir)

        self.useFixture(self.neutron_cfg_fixture)
        self.useFixture(self.plugin_cfg_fixture)

        self.neutron_config = self.neutron_cfg_fixture.config
        self.plugin_config = self.plugin_cfg_fixture.config

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            name=self.NEUTRON_SERVER,
            exec_name=self.NEUTRON_SERVER,
            config_filenames=config_filenames))

        utils.wait_until_true(self.server_is_live)

    def server_is_live(self):
        try:
            self.client.list_networks()
            return True
        except nc_exc.NeutronClientException:
            LOG.warn("neutron-server isn't up yet (cannot contact REST API).")
            return False

    @property
    def client(self):
        url = "http://127.0.0.1:%s" % self.neutron_config.DEFAULT.bind_port
        return client.Client(auth_strategy="noauth", endpoint_url=url)


class OVSAgentFixture(fixtures.Fixture):

    NEUTRON_OVS_AGENT = "neutron-openvswitch-agent"

    def __init__(self, neutron_cfg_fixture, ml2_cfg_fixture):
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.plugin_cfg_fixture = ml2_cfg_fixture

        self.neutron_config = self.neutron_cfg_fixture.config
        self.plugin_config = self.plugin_cfg_fixture.config

    def setUp(self):
        super(OVSAgentFixture, self).setUp()

        self.useFixture(net_helpers.OVSBridgeFixture(self._get_br_int_name()))
        self.useFixture(net_helpers.OVSBridgeFixture(self._get_br_phys_name()))

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            name=self.NEUTRON_OVS_AGENT,
            exec_name=self.NEUTRON_OVS_AGENT,
            config_filenames=config_filenames))

    def _get_br_int_name(self):
        return self.plugin_config.ovs.integration_bridge

    def _get_br_phys_name(self):
        return self.plugin_config.ovs.bridge_mappings.split(':')[1]


class L3AgentFixture(fixtures.Fixture):

    NEUTRON_L3_AGENT = "neutron-l3-agent"

    def __init__(self, temp_dir, neutron_cfg_fixture, integration_bridge_name):
        self.temp_dir = temp_dir
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.neutron_config = self.neutron_cfg_fixture.config
        self.integration_bridge_name = integration_bridge_name

    def setUp(self):
        super(L3AgentFixture, self).setUp()

        self.plugin_cfg_fixture = config_fixtures.L3ConfigFixture(
            self.temp_dir, self.integration_bridge_name)
        self.useFixture(self.plugin_cfg_fixture)
        self.plugin_config = self.plugin_cfg_fixture.config

        self.useFixture(net_helpers.OVSBridgeFixture(self._get_br_ex_name()))

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            name=self.NEUTRON_L3_AGENT,
            exec_name=self.NEUTRON_L3_AGENT,
            config_filenames=config_filenames))

    def _get_br_ex_name(self):
        return self.plugin_config.DEFAULT.external_network_bridge
