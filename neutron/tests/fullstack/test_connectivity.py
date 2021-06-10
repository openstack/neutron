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

from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import uuidutils
import testscenarios

from neutron.common import utils as common_utils
from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests

SEGMENTATION_ID = 1234

LOG = logging.getLogger(__name__)


class BaseConnectivitySameNetworkTest(base.BaseFullStackTestCase):

    arp_responder = False
    use_dhcp = True

    num_hosts = 3

    def setUp(self):
        host_descriptions = [
            # There's value in enabling L3 agents registration when l2pop
            # is enabled, because l2pop code makes assumptions about the
            # agent types present on machines.
            environment.HostDescription(
                l3_agent=self.l2_pop,
                l2_agent_type=self.l2_agent_type,
                dhcp_agent=self.use_dhcp,
            )
            for _ in range(self.num_hosts)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type,
                l2_pop=self.l2_pop,
                arp_responder=self.arp_responder),
            host_descriptions)
        super(BaseConnectivitySameNetworkTest, self).setUp(env)

    def _prepare_network(self, tenant_uuid):
        net_args = {'network_type': self.network_type}
        if self.network_type in ['flat', 'vlan']:
            net_args['physical_network'] = config.PHYSICAL_NETWORK_NAME
        if self.network_type in ['vlan', 'gre', 'vxlan']:
            net_args['segmentation_id'] = SEGMENTATION_ID

        network = self.safe_client.create_network(tenant_uuid, **net_args)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], '20.0.0.0/24',
            enable_dhcp=self.use_dhcp)

        return network

    def _prepare_vms_in_single_network(self):
        tenant_uuid = uuidutils.generate_uuid()
        network = self._prepare_network(tenant_uuid)
        return self._prepare_vms_in_net(tenant_uuid, network, self.use_dhcp)

    def _test_connectivity(self):
        vms = self._prepare_vms_in_single_network()
        vms.ping_all()


class TestOvsConnectivitySameNetwork(BaseConnectivitySameNetworkTest):

    l2_agent_type = constants.AGENT_TYPE_OVS
    scenarios = [
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
        ('GRE-l2pop-arp_responder', {'network_type': 'gre',
                                     'l2_pop': True,
                                     'arp_responder': True}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False})]

    def test_connectivity(self):
        self._test_connectivity()


class TestOvsConnectivitySameNetworkOnOvsBridgeControllerStop(
        BaseConnectivitySameNetworkTest):

    num_hosts = 2

    l2_agent_type = constants.AGENT_TYPE_OVS
    scenarios = [
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
        ('GRE and l2pop', {'network_type': 'gre',
                           'l2_pop': True}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False})]

    def _test_controller_timeout_does_not_break_connectivity(self,
                                                             kill_signal=None):
        # Environment preparation is effectively the same as connectivity test
        vms = self._prepare_vms_in_single_network()
        vms.ping_all()

        ns0 = vms[0].namespace
        ip1 = vms[1].ip

        LOG.debug("Stopping agents (hence also OVS bridge controllers)")
        for host in self.environment.hosts:
            if kill_signal is not None:
                host.l2_agent.stop(kill_signal=kill_signal)
            else:
                host.l2_agent.stop()

        # Ping to make sure that 3 x 5 seconds is overcame even under a high
        # load. The time was chosen to match three times inactivity_probe time,
        # which is the time after which the OVS vswitchd
        # treats the controller as dead and starts managing the bridge
        # by itself when the fail type settings is not set to secure (see
        # ovs-vsctl man page for further details)
        with net_helpers.async_ping(ns0, [ip1], timeout=2, count=25) as done:
            common_utils.wait_until_true(
                done,
                exception=RuntimeError("Networking interrupted after "
                                       "controllers have vanished"))

    def test_controller_timeout_does_not_break_connectivity_sigterm(self):
        self._test_controller_timeout_does_not_break_connectivity()

    def test_controller_timeout_does_not_break_connectivity_sigkill(self):
        self._test_controller_timeout_does_not_break_connectivity(
            signal.SIGKILL)


class TestLinuxBridgeConnectivitySameNetwork(BaseConnectivitySameNetworkTest):

    l2_agent_type = constants.AGENT_TYPE_LINUXBRIDGE
    scenarios = [
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False}),
        ('VXLAN and l2pop', {'network_type': 'vxlan',
                             'l2_pop': True})
    ]

    def test_connectivity(self):
        self._test_connectivity()


class TestConnectivitySameNetworkNoDhcp(BaseConnectivitySameNetworkTest):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        (constants.AGENT_TYPE_LINUXBRIDGE,
         {'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})
    ]

    use_dhcp = False
    network_type = 'vxlan'
    l2_pop = False

    def test_connectivity(self):
        self._test_connectivity()


class _TestUninterruptedConnectivityOnL2AgentRestart(
        BaseConnectivitySameNetworkTest):

    num_hosts = 2

    network_scenarios = [
        ('Flat network', {'network_type': 'flat',
                          'l2_pop': False}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False}),
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
    ]

    def _test_l2_agent_restart(self, agent_restart_timeout=20):
        # Environment preparation is effectively the same as connectivity test
        vms = self._prepare_vms_in_single_network()
        vms.ping_all()

        ns0 = vms[0].namespace
        ip1 = vms[1].ip
        agents = [host.l2_agent for host in self.environment.hosts]

        # Restart agents on all nodes simultaneously while pinging across
        # the hosts. The ping has to cross int and phys bridges and travels
        # via central bridge as the vms are on separate hosts.
        self._assert_ping_during_agents_restart(
            agents, ns0, [ip1], restart_timeout=agent_restart_timeout,
            ping_timeout=2, count=agent_restart_timeout)


class TestUninterruptedConnectivityOnL2AgentRestartOvs(
        _TestUninterruptedConnectivityOnL2AgentRestart):

    scenario = [('OVS',
                 {'l2_agent_type': constants.AGENT_TYPE_OVS})]

    scenarios = (
        testscenarios.multiply_scenarios(
            scenario,
            _TestUninterruptedConnectivityOnL2AgentRestart.network_scenarios))

    def test_l2_agent_restart(self, agent_restart_timeout=20):
        self._test_l2_agent_restart(agent_restart_timeout)


class TestUninterruptedConnectivityOnL2AgentRestartLB(
        _TestUninterruptedConnectivityOnL2AgentRestart):

    scenario = [('LB',
                 {'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})]

    scenarios = (
        testscenarios.multiply_scenarios(
            scenario,
            _TestUninterruptedConnectivityOnL2AgentRestart.network_scenarios)
    )

    @tests_base.unstable_test("bug 1928764")
    def test_l2_agent_restart(self, agent_restart_timeout=20):
        self._test_l2_agent_restart(agent_restart_timeout)
