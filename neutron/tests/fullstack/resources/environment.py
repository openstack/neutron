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

import random

import fixtures
import netaddr
from neutronclient.common import exceptions as nc_exc
from oslo_config import cfg

from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests.common import net_helpers
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import process


class EnvironmentDescription(object):
    """A set of characteristics of an environment setup.

    Does the setup, as a whole, support tunneling? How about l2pop?
    """
    def __init__(self, network_type='vxlan', l2_pop=True, qos=False):
        self.network_type = network_type
        self.l2_pop = l2_pop
        self.qos = qos

    @property
    def tunneling_enabled(self):
        return self.network_type in ('vxlan', 'gre')


class HostDescription(object):
    """A set of characteristics of an environment Host.

    What agents should the host spawn? What mode should each agent operate
    under?
    """
    def __init__(self, l3_agent=False, of_interface='ovs-ofctl'):
        self.l3_agent = l3_agent
        self.of_interface = of_interface


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

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_config,
                 central_data_bridge, central_external_bridge):
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_config = neutron_config
        # Use reserved class E addresses
        self.local_ip = self.get_random_ip('240.0.0.1', '255.255.255.254')
        self.central_data_bridge = central_data_bridge
        self.central_external_bridge = central_external_bridge
        self.agents = {}

    def _setUp(self):
        agent_cfg_fixture = config.OVSConfigFixture(
            self.env_desc, self.host_desc, self.neutron_config.temp_dir,
            self.local_ip)
        self.useFixture(agent_cfg_fixture)

        if self.env_desc.tunneling_enabled:
            self.useFixture(
                net_helpers.OVSBridgeFixture(
                    agent_cfg_fixture.get_br_tun_name())).bridge
            self.connect_to_internal_network_via_tunneling()
        else:
            br_phys = self.useFixture(
                net_helpers.OVSBridgeFixture(
                    agent_cfg_fixture.get_br_phys_name())).bridge
            self.connect_to_internal_network_via_vlans(br_phys)

        self.ovs_agent = self.useFixture(
            process.OVSAgentFixture(
                self.env_desc, self.host_desc,
                self.test_name, self.neutron_config, agent_cfg_fixture))

        if self.host_desc.l3_agent:
            l3_agent_cfg_fixture = self.useFixture(
                config.L3ConfigFixture(
                    self.env_desc, self.host_desc,
                    self.neutron_config.temp_dir,
                    self.ovs_agent.agent_cfg_fixture.get_br_int_name()))
            br_ex = self.useFixture(
                net_helpers.OVSBridgeFixture(
                    l3_agent_cfg_fixture.get_external_bridge())).bridge
            self.connect_to_external_network(br_ex)
            self.l3_agent = self.useFixture(
                process.L3AgentFixture(
                    self.env_desc, self.host_desc,
                    self.test_name,
                    self.neutron_config,
                    l3_agent_cfg_fixture))

    def connect_to_internal_network_via_tunneling(self):
        veth_1, veth_2 = self.useFixture(
            net_helpers.VethFixture()).ports

        # NOTE: This sets an IP address on the host's root namespace
        # which is cleaned up when the device is deleted.
        veth_1.addr.add(common_utils.ip_to_cidr(self.local_ip, 32))

        veth_1.link.set_up()
        veth_2.link.set_up()

    def connect_to_internal_network_via_vlans(self, host_data_bridge):
        # If using VLANs as a segmentation device, it's needed to connect
        # a provider bridge to a centralized, shared bridge.
        net_helpers.create_patch_ports(
            self.central_data_bridge, host_data_bridge)

    def connect_to_external_network(self, host_external_bridge):
        net_helpers.create_patch_ports(
            self.central_external_bridge, host_external_bridge)

    @staticmethod
    def get_random_ip(low, high):
        parent_range = netaddr.IPRange(low, high)
        return str(random.choice(parent_range))

    @property
    def hostname(self):
        return self.neutron_config.config.DEFAULT.host

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

    def __init__(self, env_desc, hosts_desc):
        """
        :param env_desc: An EnvironmentDescription instance.
        :param hosts_desc: A list of HostDescription instances.
        """

        super(Environment, self).__init__()
        self.env_desc = env_desc
        self.hosts_desc = hosts_desc
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

    def _create_host(self, host_desc):
        temp_dir = self.useFixture(fixtures.TempDir()).path
        neutron_config = config.NeutronConfigFixture(
            self.env_desc, host_desc, temp_dir,
            cfg.CONF.database.connection, self.rabbitmq_environment)
        self.useFixture(neutron_config)

        return self.useFixture(
            Host(self.env_desc,
                 host_desc,
                 self.test_name,
                 neutron_config,
                 self.central_data_bridge,
                 self.central_external_bridge))

    def _setUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path

        self.rabbitmq_environment = self.useFixture(
            process.RabbitmqEnvironmentFixture())

        plugin_cfg_fixture = self.useFixture(
            config.ML2ConfigFixture(
                self.env_desc, None, self.temp_dir,
                self.env_desc.network_type))
        neutron_cfg_fixture = self.useFixture(
            config.NeutronConfigFixture(
                self.env_desc, None, self.temp_dir,
                cfg.CONF.database.connection, self.rabbitmq_environment))
        self.neutron_server = self.useFixture(
            process.NeutronServerFixture(
                self.env_desc, None,
                self.test_name, neutron_cfg_fixture, plugin_cfg_fixture))

        self.central_data_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-data')).bridge
        self.central_external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-ex')).bridge

        self.hosts = [self._create_host(desc) for desc in self.hosts_desc]

        self.wait_until_env_is_up()
