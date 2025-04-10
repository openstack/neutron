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

import signal

import fixtures
from neutron_lib import constants
from neutronclient.common import exceptions as nc_exc
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import utils as common_utils
from neutron.conf import quota as quota_conf
from neutron.tests.common.exclusive_resources import ip_address
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import process

LOG = logging.getLogger(__name__)


class EnvironmentDescription:
    """A set of characteristics of an environment setup.

    Does the setup, as a whole, support tunneling? How about l2pop?
    """
    def __init__(self, network_type='vxlan', l2_pop=True, qos=False,
                 mech_drivers='openvswitch',
                 service_plugins='router', arp_responder=False,
                 agent_down_time=75, router_scheduler=None,
                 global_mtu=constants.DEFAULT_NETWORK_MTU,
                 debug_iptables=False, log=False, report_bandwidths=False,
                 has_placement=False, placement_port=None,
                 dhcp_scheduler_class=None, ml2_extension_drivers=None,
                 api_workers=1,
                 enable_traditional_dhcp=True, local_ip_ext=False,
                 quota_driver=quota_conf.QUOTA_DB_DRIVER,
                 use_meter_bandwidth_limit=False,
                 has_metadata=False, metadata_host=None, metadata_port=None,
                 host_proxy_listen_port=None):
        self.network_type = network_type
        self.l2_pop = l2_pop
        self.qos = qos
        self.log = log
        self.network_range = None
        self.mech_drivers = mech_drivers
        self.arp_responder = arp_responder
        self.agent_down_time = agent_down_time
        self.router_scheduler = router_scheduler
        self.global_mtu = global_mtu
        self.service_plugins = service_plugins
        self.debug_iptables = debug_iptables
        self.report_bandwidths = report_bandwidths
        self.has_placement = has_placement
        self.placement_port = placement_port
        self.dhcp_scheduler_class = dhcp_scheduler_class
        if self.qos:
            self.service_plugins += ',qos'
        if self.log:
            self.service_plugins += ',log'
        self.ml2_extension_drivers = ml2_extension_drivers
        self.api_workers = api_workers
        self.enable_traditional_dhcp = enable_traditional_dhcp
        self.local_ip_ext = local_ip_ext
        if self.local_ip_ext:
            self.service_plugins += ',local_ip'
        self.quota_driver = quota_driver
        self.use_meter_bandwidth_limit = use_meter_bandwidth_limit
        self.has_metadata = has_metadata
        self.metadata_host = metadata_host
        self.metadata_port = metadata_port
        self.hp_listen_port = host_proxy_listen_port

    @property
    def tunneling_enabled(self):
        return self.network_type in ('vxlan', 'gre')

    def __str__(self):
        return f'{vars(self)}'


class HostDescription:
    """A set of characteristics of an environment Host.

    What agents should the host spawn? What mode should each agent operate
    under?
    """
    def __init__(self, l3_agent=False, dhcp_agent=False,
                 l2_agent_type=constants.AGENT_TYPE_OVS,
                 firewall_driver='noop', availability_zone=None,
                 l3_agent_mode=None,
                 l3_agent_extensions=None,
                 segmented_physnet=False):
        self.l2_agent_type = l2_agent_type
        self.l3_agent = l3_agent
        self.dhcp_agent = dhcp_agent
        self.firewall_driver = firewall_driver
        self.availability_zone = availability_zone
        self.l3_agent_mode = l3_agent_mode
        self.l3_agent_extensions = l3_agent_extensions
        self.segmented_physnet = segmented_physnet

    def __str__(self):
        return f'{vars(self)}'


class Host(fixtures.Fixture):
    """The Host class models a physical host running agents, all reporting with
    the same hostname.

    OpenStack installers or administrators connect compute nodes to the
    physical tenant network by connecting the provider bridges to their
    respective physical NICs. Or, if using tunneling, by configuring an
    IP address on the appropriate physical NIC. The Host class does the same
    with the connect_* methods.

    TODO(amuller): Add restart method that will restart all of the agents on
    this host.
    """

    def __init__(self, env_desc, host_desc, test_name,
                 neutron_config, central_bridge):
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.neutron_config = neutron_config
        self.central_bridge = central_bridge
        self.host_namespace = None
        self.agents = {}

    def _setUp(self):
        self.local_ip = self.allocate_local_ip()

        if self.host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            self.setup_host_with_ovs_agent()
        elif self.host_desc.l2_agent_type == constants.AGENT_TYPE_NIC_SWITCH:
            self.setup_host_with_sriov_agent()
        if self.host_desc.l3_agent:
            self.l3_agent = self.useFixture(
                process.L3AgentFixture(
                    self.env_desc, self.host_desc,
                    self.test_name,
                    self.neutron_config,
                    self.l3_agent_cfg_fixture))

        if self.host_desc.dhcp_agent:
            self.dhcp_agent = self.useFixture(
                process.DhcpAgentFixture(
                    self.env_desc, self.host_desc,
                    self.test_name,
                    self.neutron_config,
                    self.dhcp_agent_cfg_fixture,
                    namespace=self.host_namespace))

    def __repr__(self) -> str:
        return 'Host description {}, environment description: {}'.format(
            self.host_desc, self.env_desc)

    def setup_host_with_ovs_agent(self):
        agent_cfg_fixture = config.OVSConfigFixture(
            self.env_desc, self.host_desc, self.neutron_config.temp_dir,
            self.local_ip, test_name=self.test_name)
        self.useFixture(agent_cfg_fixture)

        self.br_phys = self.useFixture(
            net_helpers.OVSBridgeFixture(
                agent_cfg_fixture.get_br_phys_name())).bridge
        if self.env_desc.tunneling_enabled:
            self.useFixture(
                net_helpers.OVSBridgeFixture(
                    agent_cfg_fixture.get_br_tun_name()))
            self.connect_to_central_network_via_tunneling()
        else:
            self.connect_to_central_network_via_vlans(self.br_phys)

        self.ovs_agent = self.useFixture(
            process.OVSAgentFixture(
                self.env_desc, self.host_desc,
                self.test_name, self.neutron_config, agent_cfg_fixture))

        if self.env_desc.has_metadata:
            self.br_meta = self.useFixture(
                net_helpers.OVSMetaBridgeFixture(
                    self.ovs_agent.agent_cfg_fixture.get_br_meta_name())
            ).bridge

        if self.host_desc.l3_agent:
            self.l3_agent_cfg_fixture = self.useFixture(
                config.L3ConfigFixture(
                    self.env_desc, self.host_desc,
                    self.neutron_config.temp_dir,
                    self.ovs_agent.agent_cfg_fixture.get_br_int_name()))

        if self.host_desc.dhcp_agent:
            self.dhcp_agent_cfg_fixture = self.useFixture(
                config.DhcpConfigFixture(
                    self.env_desc, self.host_desc,
                    self.neutron_config.temp_dir,
                    self.ovs_agent.agent_cfg_fixture.get_br_int_name()))

    def setup_host_with_sriov_agent(self):
        agent_cfg_fixture = config.SRIOVConfigFixture(
            self.env_desc, self.host_desc, self.neutron_config.temp_dir,
            self.local_ip)
        self.useFixture(agent_cfg_fixture)
        self.sriov_agent = self.useFixture(
            process.SRIOVAgentFixture(
                self.env_desc, self.host_desc,
                self.test_name, self.neutron_config, agent_cfg_fixture))

    def _connect_ovs_port(self, cidr_address):
        ovs_device = self.useFixture(
            net_helpers.OVSPortFixture(
                bridge=self.central_bridge,
                namespace=self.host_namespace)).port
        # NOTE: This sets an IP address on the host's root namespace
        # which is cleaned up when the device is deleted.
        ovs_device.addr.add(cidr_address)
        return ovs_device

    def connect_namespace_to_control_network(self):
        self.host_port = self._connect_ovs_port(
            common_utils.ip_to_cidr(self.local_ip, 24)
        )
        self.host_port.link.set_up()

    def connect_to_central_network_via_tunneling(self):
        veth_1, veth_2 = self.useFixture(
            net_helpers.VethFixture()).ports

        # NOTE: This sets an IP address on the host's root namespace
        # which is cleaned up when the device is deleted.
        veth_1.addr.add(common_utils.ip_to_cidr(self.local_ip, 32))

        veth_1.link.set_up()
        veth_2.link.set_up()
        self.tunnel_device = veth_1

    def connect_to_central_network_via_vlans(self, host_data_bridge):
        # If using VLANs as a segmentation device, it's needed to connect
        # a provider bridge to a centralized, shared bridge.
        source, destination = net_helpers.create_patch_ports(
            self.central_bridge, host_data_bridge)
        self.internal_port = destination

    def allocate_local_ip(self):
        if not self.env_desc.network_range:
            return str(self.useFixture(
                ip_address.ExclusiveIPAddress(
                    '240.0.0.1', '240.255.255.254')).address)
        return str(self.useFixture(
            ip_address.ExclusiveIPAddress(
                str(self.env_desc.network_range[2]),
                str(self.env_desc.network_range[-2]))).address)

    def get_bridge(self):
        if "ovs" in self.agents.keys():
            return self.ovs_agent.br_int

    def disconnect(self):
        if self.env_desc.tunneling_enabled:
            self.tunnel_device.addr.flush(4)
        else:
            self.br_phys.delete_port(self.internal_port)
        LOG.info(f'Host {self.hostname} disconnected.')

    def kill(self, parent=None):
        # First kill all the agent to prevent a graceful shutdown
        for agent_name, agent in self.agents.items():
            agent.stop(kill_signal=signal.SIGKILL)
        LOG.info(f'Agents on host {self.hostname} killed.')

        self.shutdown(parent)

    def shutdown(self, parent=None):
        self.cleanUp()

        # Remove cleanup function from parent because it can't be called twice
        if parent:
            parent._cleanups._cleanups.remove(
                (self.cleanUp, (), {})
            )

        LOG.info(f'Host {self.hostname} shut down.')

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
    def dhcp_agent(self):
        return self.agents['dhcp']

    @dhcp_agent.setter
    def dhcp_agent(self, agent):
        self.agents['dhcp'] = agent

    @property
    def ovs_agent(self):
        return self.agents['ovs']

    @ovs_agent.setter
    def ovs_agent(self, agent):
        self.agents['ovs'] = agent

    @property
    def sriov_agent(self):
        return self.agents['sriov']

    @sriov_agent.setter
    def sriov_agent(self, agent):
        self.agents['sriov'] = agent

    @property
    def l2_agent(self):
        if self.host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            return self.ovs_agent
        if self.host_desc.l2_agent_type == constants.AGENT_TYPE_NIC_SWITCH:
            return self.sriov_agent


class Environment(fixtures.Fixture):
    """Represents a deployment topology.

    Environment is a collection of hosts. It starts a Neutron server
    and a parametrized number of Hosts, each a collection of agents.
    The Environment accepts a collection of HostDescription, each describing
    the type of Host to create.
    """

    def __init__(self, env_desc, hosts_desc):
        """Initialize Environment

        :param env_desc: An EnvironmentDescription instance.
        :param hosts_desc: A list of HostDescription instances.
        """

        super().__init__()
        self.env_desc = env_desc
        self.hosts_desc = hosts_desc
        self.hosts = []

    def wait_until_env_is_up(self):
        base.wait_until_true(
            self._processes_are_ready,
            timeout=180,
            sleep=10)

    def _processes_are_ready(self):
        try:
            running_agents = self.neutron_server.client.list_agents()['agents']
            agents_count = sum(len(host.agents) for host in self.hosts)
            return len(running_agents) == agents_count
        except nc_exc.NeutronClientException:
            return False

    def get_host_by_name(self, hostname):
        return next(host for host in self.hosts if host.hostname == hostname)

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
                 self.central_bridge))

    def _setUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path

        # we need this bridge before rabbit and neutron service will start
        self.central_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-data')).bridge

        # Get rabbitmq address (and cnt-data network)
        rabbitmq_ip_address = "127.0.0.1"
        self.rabbitmq_environment = self.useFixture(
            process.RabbitmqEnvironmentFixture(host=rabbitmq_ip_address)
        )

        plugin_cfg_fixture = self.useFixture(
            config.ML2ConfigFixture(
                self.env_desc, self.hosts_desc, self.temp_dir,
                self.env_desc.network_type))
        neutron_cfg_fixture = self.useFixture(
            config.NeutronConfigFixture(
                self.env_desc, None, self.temp_dir,
                cfg.CONF.database.connection, self.rabbitmq_environment))
        self.neutron_server = self.useFixture(
            process.NeutronServerFixture(
                self.env_desc, None,
                self.test_name, neutron_cfg_fixture, plugin_cfg_fixture))

        if self.env_desc.has_placement:
            placement_cfg_fixture = self.useFixture(
                config.PlacementConfigFixture(self.env_desc, self.hosts_desc,
                                              self.temp_dir)
            )
            self.placement = self.useFixture(
                process.PlacementFixture(
                    self.env_desc, self.hosts_desc, self.test_name,
                    placement_cfg_fixture)
            )

        if self.env_desc.has_metadata:
            metadata_cfg_fixture = self.useFixture(
                config.MetadataConfigFixture(self.env_desc, self.hosts_desc,
                                             self.temp_dir)
            )
            self.metadata = self.useFixture(
                process.MetadataFixture(
                    self.env_desc, self.hosts_desc, self.test_name,
                    metadata_cfg_fixture)
            )

        self.hosts = [self._create_host(desc) for desc in self.hosts_desc]

        self.wait_until_env_is_up()
