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

import datetime
from distutils import spawn
import os
import signal

import fixtures
from neutronclient.common import exceptions as nc_exc
from neutronclient.v2_0 import client

from neutron.agent.linux import async_process
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests import base
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base as fullstack_base


class ProcessFixture(fixtures.Fixture):
    def __init__(self, test_name, process_name, exec_name, config_filenames,
                 namespace=None, kill_signal=signal.SIGKILL):
        super(ProcessFixture, self).__init__()
        self.test_name = test_name
        self.process_name = process_name
        self.exec_name = exec_name
        self.config_filenames = config_filenames
        self.process = None
        self.kill_signal = kill_signal
        self.namespace = namespace

    def _setUp(self):
        self.start()
        self.addCleanup(self.stop)

    def start(self):
        test_name = base.sanitize_log_path(self.test_name)

        log_dir = os.path.join(fullstack_base.DEFAULT_LOG_DIR, test_name)
        common_utils.ensure_dir(log_dir)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S-%f")
        log_file = "%s--%s.log" % (self.process_name, timestamp)
        cmd = [spawn.find_executable(self.exec_name),
               '--log-dir', log_dir,
               '--log-file', log_file]
        for filename in self.config_filenames:
            cmd += ['--config-file', filename]
        run_as_root = bool(self.namespace)
        self.process = async_process.AsyncProcess(
            cmd, run_as_root=run_as_root, namespace=self.namespace
        )
        self.process.start(block=True)

    def stop(self):
        self.process.stop(block=True, kill_signal=self.kill_signal)


class RabbitmqEnvironmentFixture(fixtures.Fixture):

    def __init__(self, host="127.0.0.1"):
        super(RabbitmqEnvironmentFixture, self).__init__()
        self.host = host

    def _setUp(self):
        self.user = common_utils.get_rand_name(prefix='user')
        self.password = common_utils.get_rand_name(prefix='pass')
        self.vhost = common_utils.get_rand_name(prefix='vhost')

        self._execute('add_user', self.user, self.password)
        self.addCleanup(self._execute, 'delete_user', self.user)

        self._execute('add_vhost', self.vhost)
        self.addCleanup(self._execute, 'delete_vhost', self.vhost)

        self._execute('set_permissions', '-p', self.vhost, self.user,
                      '.*', '.*', '.*')

    def _execute(self, *args):
        cmd = ['rabbitmqctl']
        cmd.extend(args)
        utils.execute(cmd, run_as_root=True)


class NeutronServerFixture(fixtures.Fixture):

    NEUTRON_SERVER = "neutron-server"

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_cfg_fixture, plugin_cfg_fixture):
        super(NeutronServerFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.plugin_cfg_fixture = plugin_cfg_fixture

    def _setUp(self):
        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name=self.NEUTRON_SERVER,
            exec_name=self.NEUTRON_SERVER,
            config_filenames=config_filenames,
            kill_signal=signal.SIGTERM))

        common_utils.wait_until_true(self.server_is_live)

    def server_is_live(self):
        try:
            self.client.list_networks()
            return True
        except nc_exc.NeutronClientException:
            return False

    @property
    def client(self):
        url = ("http://127.0.0.1:%s" %
               self.neutron_cfg_fixture.config.DEFAULT.bind_port)
        return client.Client(auth_strategy="noauth", endpoint_url=url)


class OVSAgentFixture(fixtures.Fixture):

    NEUTRON_OVS_AGENT = "neutron-openvswitch-agent"

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_cfg_fixture, agent_cfg_fixture):
        super(OVSAgentFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.neutron_config = self.neutron_cfg_fixture.config
        self.agent_cfg_fixture = agent_cfg_fixture
        self.agent_config = agent_cfg_fixture.config

    def _setUp(self):
        self.br_int = self.useFixture(
            net_helpers.OVSBridgeFixture(
                self.agent_cfg_fixture.get_br_int_name())).bridge

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.agent_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name=self.NEUTRON_OVS_AGENT,
            exec_name=spawn.find_executable(
                'ovs_agent.py',
                path=os.path.join(base.ROOTDIR, 'common', 'agents')),
            config_filenames=config_filenames,
            kill_signal=signal.SIGTERM))


class LinuxBridgeAgentFixture(fixtures.Fixture):

    NEUTRON_LINUXBRIDGE_AGENT = "neutron-linuxbridge-agent"

    def __init__(self, env_desc, host_desc, test_name,
                 neutron_cfg_fixture, agent_cfg_fixture,
                 namespace=None):
        super(LinuxBridgeAgentFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.neutron_config = self.neutron_cfg_fixture.config
        self.agent_cfg_fixture = agent_cfg_fixture
        self.agent_config = agent_cfg_fixture.config
        self.namespace = namespace

    def _setUp(self):
        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.agent_cfg_fixture.filename]

        self.process_fixture = self.useFixture(
            ProcessFixture(
                test_name=self.test_name,
                process_name=self.NEUTRON_LINUXBRIDGE_AGENT,
                exec_name=self.NEUTRON_LINUXBRIDGE_AGENT,
                config_filenames=config_filenames,
                namespace=self.namespace
            )
        )


class L3AgentFixture(fixtures.Fixture):

    NEUTRON_L3_AGENT = "neutron-l3-agent"

    def __init__(self, env_desc, host_desc, test_name,
                 neutron_cfg_fixture, l3_agent_cfg_fixture,
                 namespace=None):
        super(L3AgentFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.l3_agent_cfg_fixture = l3_agent_cfg_fixture
        self.namespace = namespace

    def _setUp(self):
        self.plugin_config = self.l3_agent_cfg_fixture.config

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.l3_agent_cfg_fixture.filename]
        self.process_fixture = self.useFixture(
            ProcessFixture(
                test_name=self.test_name,
                process_name=self.NEUTRON_L3_AGENT,
                exec_name=spawn.find_executable(
                    'l3_agent.py',
                    path=os.path.join(base.ROOTDIR, 'common', 'agents')),
                config_filenames=config_filenames,
                namespace=self.namespace
            )
        )

    def get_namespace_suffix(self):
        return self.plugin_config.DEFAULT.test_namespace_suffix
