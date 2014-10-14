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

import fixtures
from neutronclient.common import exceptions as nc_exc
from neutronclient.v2_0 import client
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from neutron.agent.linux import async_process
from neutron.agent.linux import utils
from neutron.tests.fullstack import config_fixtures

LOG = logging.getLogger(__name__)

# This should correspond the directory from which infra retrieves log files
DEFAULT_LOG_DIR = '/opt/stack/logs'


class ProcessFixture(fixtures.Fixture):
    def __init__(self, name, exec_name, config_filenames):
        super(ProcessFixture, self).__init__()
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
        super(ProcessFixture, self, *args, **kwargs)


class NeutronServerFixture(fixtures.Fixture):

    def setUp(self):
        super(NeutronServerFixture, self).setUp()
        self.temp_dir = self.useFixture(fixtures.TempDir()).path

        self.neutron_cfg_fixture = config_fixtures.NeutronConfigFixture(
            self.temp_dir, cfg.CONF.database.connection)
        self.plugin_cfg_fixture = config_fixtures.ML2ConfigFixture(
            self.temp_dir)

        self.useFixture(self.neutron_cfg_fixture)
        self.useFixture(self.plugin_cfg_fixture)

        self.neutron_config = self.neutron_cfg_fixture.config

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            name='neutron_server',
            exec_name='neutron-server',
            config_filenames=config_filenames,
        ))

        utils.wait_until_true(self.processes_are_ready)

    @property
    def client(self):
        url = "http://127.0.0.1:%s" % self.neutron_config.DEFAULT.bind_port
        return client.Client(auth_strategy="noauth", endpoint_url=url)

    def processes_are_ready(self):
        # ProcessFixture will ensure that the server has started, but
        # that doesn't mean that the server will be serving commands yet, nor
        # that all processes are up.
        try:
            return len(self.client.list_agents()['agents']) == 0
        except nc_exc.NeutronClientException:
            LOG.debug("Processes aren't up yet.")
            return False
