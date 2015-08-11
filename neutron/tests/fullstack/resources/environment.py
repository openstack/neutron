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

import fixtures
from neutronclient.common import exceptions as nc_exc
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import utils
from neutron.tests.common import net_helpers
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import process

LOG = logging.getLogger(__name__)


class HostDescription(object):
    """A set of characteristics of an environment Host.

    What agents should the host spawn? What mode should each agent operate
    under?
    """
    def __init__(self, l3_agent=True):
        self.l3_agent = l3_agent


class Host(fixtures.Fixture):
    """The Host class models a physical host running agents, all reporting with
    the same hostname.

    OpenStack installers or administrators connect compute nodes to the
    physical tenant network by connecting the provider bridges to their
    respective physical NICs. Or, if using tunneling, by configuring an
    IP address on the appropriate physical NIC. The Host class does the same
    with the connect_* methods.

    TODO(amuller): Add start/stop/restart methods that will start/stop/restart
    all of the agents on this host. Add a kill method that stops all agents
    and disconnects the host from other hosts.
    """

    def __init__(self, test_name, neutron_config, host_description,
                 central_data_bridge, central_external_bridge):
        self.test_name = test_name
        self.neutron_config = neutron_config
        self.host_description = host_description
        self.central_data_bridge = central_data_bridge
        self.central_external_bridge = central_external_bridge
        self.agents = {}

    def _setUp(self):
        agent_cfg_fixture = config.OVSConfigFixture(
            self.neutron_config.temp_dir)
        self.useFixture(agent_cfg_fixture)

        br_phys = self.useFixture(
            net_helpers.OVSBridgeFixture(
                agent_cfg_fixture.get_br_phys_name())).bridge
        self.connect_to_internal_network_via_vlans(br_phys)

        self.ovs_agent = self.useFixture(
            process.OVSAgentFixture(
                self.test_name, self.neutron_config, agent_cfg_fixture))

        if self.host_description.l3_agent:
            l3_agent_cfg_fixture = self.useFixture(
                config.L3ConfigFixture(
                    self.neutron_config.temp_dir,
                    self.ovs_agent.agent_cfg_fixture.get_br_int_name()))
            br_ex = self.useFixture(
                net_helpers.OVSBridgeFixture(
                    l3_agent_cfg_fixture.get_external_bridge())).bridge
            self.connect_to_external_network(br_ex)
            self.l3_agent = self.useFixture(
                process.L3AgentFixture(
                    self.test_name,
                    self.neutron_config,
                    l3_agent_cfg_fixture))

    def connect_to_internal_network_via_vlans(self, host_data_bridge):
        # If using VLANs as a segmentation device, it's needed to connect
        # a provider bridge to a centralized, shared bridge.
        net_helpers.create_patch_ports(
            self.central_data_bridge, host_data_bridge)

    def connect_to_external_network(self, host_external_bridge):
        net_helpers.create_patch_ports(
            self.central_external_bridge, host_external_bridge)

    @property
    def l3_agent(self):
        return self.agents['l3']

    @l3_agent.setter
    def l3_agent(self, agent):
        self.agents['l3'] = agent

    @property
    def ovs_agent(self):
        return self.agents['ovs']

    @ovs_agent.setter
    def ovs_agent(self, agent):
        self.agents['ovs'] = agent


class Environment(fixtures.Fixture):
    """Represents a deployment topology.

    Environment is a collection of hosts. It starts a Neutron server
    and a parametrized number of Hosts, each a collection of agents.
    The Environment accepts a collection of HostDescription, each describing
    the type of Host to create.
    """

    def __init__(self, hosts_descriptions):
        """
        :param hosts_descriptions: A list of HostDescription instances.
        """

        super(Environment, self).__init__()
        self.hosts_descriptions = hosts_descriptions
        self.hosts = []

    def wait_until_env_is_up(self):
        utils.wait_until_true(self._processes_are_ready)

    def _processes_are_ready(self):
        try:
            running_agents = self.neutron_server.client.list_agents()['agents']
            agents_count = sum(len(host.agents) for host in self.hosts)
            return len(running_agents) == agents_count
        except nc_exc.NeutronClientException:
            return False

    def _create_host(self, description):
        temp_dir = self.useFixture(fixtures.TempDir()).path
        neutron_config = config.NeutronConfigFixture(
            temp_dir, cfg.CONF.database.connection,
            self.rabbitmq_environment)
        self.useFixture(neutron_config)

        return self.useFixture(
            Host(self.test_name,
                 neutron_config,
                 description,
                 self.central_data_bridge,
                 self.central_external_bridge))

    def _setUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        self.rabbitmq_environment = self.useFixture(
            process.RabbitmqEnvironmentFixture())
        plugin_cfg_fixture = self.useFixture(
            config.ML2ConfigFixture(self.temp_dir, 'vlan'))
        neutron_cfg_fixture = self.useFixture(
            config.NeutronConfigFixture(
                self.temp_dir,
                cfg.CONF.database.connection,
                self.rabbitmq_environment))
        self.neutron_server = self.useFixture(
            process.NeutronServerFixture(
                self.test_name, neutron_cfg_fixture, plugin_cfg_fixture))

        self.central_data_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-data')).bridge
        self.central_external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-ex')).bridge

        self.hosts = [self._create_host(description) for description in
                      self.hosts_descriptions]

        self.wait_until_env_is_up()
