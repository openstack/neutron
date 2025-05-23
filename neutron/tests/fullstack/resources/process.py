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
import os
import re
import shutil

import fixtures
from neutron_lib import constants
from neutronclient.common import exceptions as nc_exc
from neutronclient.v2_0 import client
from oslo_log import log as logging
from oslo_utils import fileutils

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests import base
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base as fullstack_base

LOG = logging.getLogger(__name__)
CMD_FOLDER = 'agents'


class ProcessFixture(fixtures.Fixture):
    def __init__(self, test_name, process_name, exec_name, config_filenames,
                 namespace=None, slice_name=None):
        super().__init__()
        self.test_name = test_name
        self.process_name = process_name
        self.exec_name = exec_name
        self.config_filenames = config_filenames
        self.process = None
        self.namespace = namespace

        self.slice_name = slice_name
        self.unit_name = f'{self.test_name}-{self.process_name}'
        if self.namespace:
            self.unit_name += f'-{self.namespace}'

        # Escape special characters in unit names, see man systemd.unit
        self.unit_name = utils.execute(
            ['systemd-escape', self.unit_name],
        ).strip()

    def _setUp(self):
        self.start()
        self.addCleanup(self.stop)

    def start(self):
        test_name = base.sanitize_log_path(self.test_name)

        log_dir = os.path.join(fullstack_base.DEFAULT_LOG_DIR, test_name)
        fileutils.ensure_tree(log_dir, mode=0o755)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S-%f")
        log_file = f"{self.process_name}--{timestamp}.log"
        run_as_root = bool(self.namespace)
        exec_name = (self.exec_name
                     if run_as_root
                     else shutil.which(self.exec_name))
        cmd = [exec_name, '--log-dir', log_dir, '--log-file', log_file]
        if self.namespace:
            cmd = ip_lib.add_namespace_to_cmd(cmd, self.namespace)
        for filename in self.config_filenames:
            cmd += ['--config-file', filename]

        systemd_run = [
            'systemd-run',
            '--service-type', 'exec',
            # Timeout and KILL processes 5s before the timeout the restart
            # tests use.
            '--property', 'TimeoutStopSec=25s',
            '--property', 'KillMode=mixed',
            '--unit', self.unit_name,
            '--setenv', f'PATH={os.environ["PATH"]}',
            '--same-dir',
            '--collect',
        ]

        if not run_as_root:
            systemd_run += [
                '--uid', os.getuid(),
                '--gid', os.getgid(),
            ]

        if self.slice_name:
            systemd_run += ['--slice', self.slice_name]

        utils.execute(
            systemd_run + cmd,
            # Always create the systemd unit as root, the process itself will
            # run unprivileged if run_as_root is False.
            run_as_root=True,
        )
        fullstack_base.wait_until_true(self.service_is_active)
        LOG.debug("Process started: %s", self.process_name)

    def stop(self, kill_signal=None):
        if self.process_is_not_running():
            return

        if kill_signal:
            # systemd in ubuntu noble returns invalid-argument for some child
            # processes
            check_exit_code = False
            stop_cmd = [
                'systemctl',
                'kill',
                '--signal', kill_signal.value,
                '--kill-who', 'all',
                self.unit_name,
            ]
            msg = (f'Process killed with signal {kill_signal}: '
                   f'{self.process_name}')
        else:
            check_exit_code = True
            stop_cmd = ['systemctl', 'stop', '--no-block', self.unit_name]
            msg = f'Process stopped: {self.process_name}'

        utils.execute(stop_cmd, run_as_root=True,
                      check_exit_code=check_exit_code)
        fullstack_base.wait_until_true(self.process_is_not_running)
        LOG.debug(msg)

    def restart(self, executor=None):
        def _restart():
            if self.process_is_running():
                restart_cmd = [
                    'systemctl',
                    'restart',
                    '--no-block',
                    self.unit_name,
                ]
                utils.execute(restart_cmd, run_as_root=True)
                fullstack_base.wait_until_true(self.service_is_active)
            else:
                self.start()

        LOG.debug("Restarting process: %s", self.process_name)

        if executor is not None:
            return executor.submit(_restart)

        _restart()

    @property
    def service_state(self):
        cmd = ['systemctl', 'is-active', self.unit_name]
        return utils.execute(
            cmd,
            run_as_root=True,
            log_fail_as_error=False,
            check_exit_code=False,
        ).strip()

    def service_is_active(self):
        return self.service_state == 'active'

    def process_is_running(self):
        return self.service_state in ('active', 'activating', 'deactivating')

    def process_is_not_running(self):
        return not self.process_is_running()


class RabbitmqEnvironmentFixture(fixtures.Fixture):

    def __init__(self, host="127.0.0.1"):
        super().__init__()
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


class ServiceFixture(fixtures.Fixture):
    def restart(self, executor=None):
        return self.process_fixture.restart(executor=executor)

    def start(self):
        return self.process_fixture.start()

    def stop(self, kill_signal=None):
        return self.process_fixture.stop(kill_signal=kill_signal)


class NeutronServerFixture(ServiceFixture):

    NEUTRON_SERVER = "neutron-server"

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_cfg_fixture, plugin_cfg_fixture,
                 service_cfg_fixtures=None):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.plugin_cfg_fixture = plugin_cfg_fixture
        self.service_cfg_fixtures = service_cfg_fixtures
        self.hostname = self.neutron_cfg_fixture.config['DEFAULT']['host']

    def _setUp(self):
        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.plugin_cfg_fixture.filename]

        if self.service_cfg_fixtures:
            config_filenames.extend(
                [scf.filename for scf in self.service_cfg_fixtures])

        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name=f'{self.NEUTRON_SERVER}-{self.hostname}',
            exec_name=self.NEUTRON_SERVER,
            config_filenames=config_filenames))

        fullstack_base.wait_until_true(self.server_is_live)

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


class OVSAgentFixture(ServiceFixture):

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_cfg_fixture, agent_cfg_fixture):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.neutron_config = self.neutron_cfg_fixture.config
        self.agent_cfg_fixture = agent_cfg_fixture
        self.agent_config = agent_cfg_fixture.config
        self.hostname = self.neutron_config['DEFAULT']['host']

    def _setUp(self):
        self.br_int = self.useFixture(
            net_helpers.OVSBridgeFixture(
                self.agent_cfg_fixture.get_br_int_name())).bridge

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.agent_cfg_fixture.filename]

        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name=f'{constants.AGENT_PROCESS_OVS}-{self.hostname}',
            slice_name=self.hostname,
            exec_name=shutil.which(
                'ovs_agent.py',
                path=os.path.join(fullstack_base.ROOTDIR, CMD_FOLDER)),
            config_filenames=config_filenames,
        ))


class PlacementFixture(ServiceFixture):

    def __init__(self, env_desc, host_desc, test_name, placement_cfg_fixture):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.placement_cfg_fixture = placement_cfg_fixture
        self.placement_config = self.placement_cfg_fixture.config

    def _setUp(self):
        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name='placement',
            exec_name=shutil.which(
                'placement.py', path=os.path.join(fullstack_base.ROOTDIR,
                                                  'servers')
            ),
            config_filenames=[self.placement_cfg_fixture.filename]))


class MetadataFixture(ServiceFixture):

    def __init__(self, env_desc, host_desc, test_name, metadata_cfg_fixture):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.metadata_cfg_fixture = metadata_cfg_fixture
        self.metadata_config = self.metadata_cfg_fixture.config

    def _setUp(self):
        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name='metadata',
            exec_name=shutil.which(
                'metadata.py', path=os.path.join(fullstack_base.ROOTDIR,
                                                 'servers')
            ),
            config_filenames=[self.metadata_cfg_fixture.filename]))


class SRIOVAgentFixture(ServiceFixture):

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_cfg_fixture, agent_cfg_fixture):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.neutron_config = self.neutron_cfg_fixture.config
        self.agent_cfg_fixture = agent_cfg_fixture
        self.agent_config = agent_cfg_fixture.config
        self.hostname = self.neutron_config['DEFAULT']['host']

    def _setUp(self):
        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.agent_cfg_fixture.filename]
        process_name = f'{constants.AGENT_PROCESS_NIC_SWITCH}-{self.hostname}'
        self.process_fixture = self.useFixture(ProcessFixture(
            test_name=self.test_name,
            process_name=process_name,
            slice_name=self.hostname,
            exec_name=constants.AGENT_PROCESS_NIC_SWITCH,
            config_filenames=config_filenames))


class NamespaceCleanupFixture(ServiceFixture):

    namespace_pattern = None

    def _setUp(self):
        super()._setUp()
        self.addCleanup(self.clean_namespaces)

    def clean_namespaces(self):
        """Delete all DHCP namespaces created by DHCP agent.

        In some tests for DHCP agent HA agents are killed when handling DHCP
        service for network(s). In such case DHCP namespace is not deleted by
        DHCP agent and such namespaces are found and deleted using agent's
        namespace suffix.
        """

        for namespace in ip_lib.list_network_namespaces():
            if (self.namespace_pattern and
                    self.namespace_pattern.match(namespace)):
                try:
                    ip_lib.delete_network_namespace(namespace)
                except RuntimeError:
                    # Continue cleaning even if namespace deletions fails
                    pass


class L3AgentFixture(NamespaceCleanupFixture):

    def __init__(self, env_desc, host_desc, test_name,
                 neutron_cfg_fixture, l3_agent_cfg_fixture,
                 namespace=None):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.l3_agent_cfg_fixture = l3_agent_cfg_fixture
        self.namespace = namespace
        self.hostname = self.neutron_cfg_fixture.config['DEFAULT']['host']

    def _setUp(self):
        super()._setUp()

        self.plugin_config = self.l3_agent_cfg_fixture.config

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.l3_agent_cfg_fixture.filename]

        # if we execute in namespace as root, then allow rootwrap to find the
        # executable, otherwise construct full path ourselves
        if self.namespace:
            exec_name = 'l3_agent.py'
        else:
            exec_name = shutil.which(
                'l3_agent.py',
                path=os.path.join(fullstack_base.ROOTDIR, CMD_FOLDER))

        self.process_fixture = self.useFixture(
            ProcessFixture(
                test_name=self.test_name,
                process_name=f'{constants.AGENT_PROCESS_L3}-{self.hostname}',
                slice_name=self.hostname,
                exec_name=exec_name,
                config_filenames=config_filenames,
                namespace=self.namespace
            )
        )
        self.namespace_pattern = re.compile(
            r"qrouter-[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}@%s" %
            self.get_namespace_suffix())

    def get_namespace_suffix(self):
        return self.plugin_config.DEFAULT.test_namespace_suffix


class DhcpAgentFixture(NamespaceCleanupFixture):

    def __init__(self, env_desc, host_desc, test_name,
                 neutron_cfg_fixture, agent_cfg_fixture, namespace=None):
        super().__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_cfg_fixture = neutron_cfg_fixture
        self.agent_cfg_fixture = agent_cfg_fixture
        self.namespace = namespace

    def _setUp(self):
        super()._setUp()

        self.plugin_config = self.agent_cfg_fixture.config

        config_filenames = [self.neutron_cfg_fixture.filename,
                            self.agent_cfg_fixture.filename]

        # if we execute in namespace as root, then allow rootwrap to find the
        # executable, otherwise construct full path ourselves
        if self.namespace:
            exec_name = 'dhcp_agent.py'
        else:
            exec_name = shutil.which(
                'dhcp_agent.py',
                path=os.path.join(fullstack_base.ROOTDIR, CMD_FOLDER))
        hostname = self.get_agent_hostname()

        self.process_fixture = self.useFixture(
            ProcessFixture(
                test_name=self.test_name,
                process_name=f'{constants.AGENT_PROCESS_DHCP}-{hostname}',
                slice_name=hostname,
                exec_name=exec_name,
                config_filenames=config_filenames,
                namespace=self.namespace
            )
        )
        self.namespace_pattern = re.compile(
            r"qdhcp-[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}%s" %
            self.get_namespace_suffix())

    def get_agent_hostname(self):
        return self.neutron_cfg_fixture.config['DEFAULT']['host']

    def get_namespace_suffix(self):
        return self.plugin_config.DEFAULT.test_namespace_suffix

    def kill(self):
        self.process_fixture.stop()
        self.clean_namespaces()
