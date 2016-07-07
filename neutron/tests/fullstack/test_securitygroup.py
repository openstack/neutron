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

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.cmd.sanity import checks
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class OVSVersionChecker(object):
    conntrack_supported = None

    @classmethod
    def supports_ovsfirewall(cls):
        if cls.conntrack_supported is None:
            cls.conntrack_supported = checks.ovs_conntrack_supported()

        return cls.conntrack_supported


class BaseSecurityGroupsSameNetworkTest(base.BaseFullStackTestCase):

    of_interface = None
    ovsdb_interface = None

    def setUp(self):
        if (self.firewall_driver == 'openvswitch' and
            not OVSVersionChecker.supports_ovsfirewall()):
            self.skipTest("Open vSwitch firewall_driver doesn't work "
                          "with this version of ovs.")
        host_descriptions = [
            environment.HostDescription(
                of_interface=self.of_interface,
                ovsdb_interface=self.ovsdb_interface,
                l2_agent_type=self.l2_agent_type,
                firewall_driver=self.firewall_driver) for _ in range(2)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type),
            host_descriptions)
        super(BaseSecurityGroupsSameNetworkTest, self).setUp(env)

    def assert_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)
        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())
        netcat.stop_processes()

    def assert_no_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)
        self.addCleanup(netcat.stop_processes)
        self.assertRaises(RuntimeError, netcat.test_connectivity)
        netcat.stop_processes()


class TestSecurityGroupsSameNetwork(BaseSecurityGroupsSameNetworkTest):

    l2_agent_type = constants.AGENT_TYPE_OVS
    network_type = 'vxlan'
    scenarios = [
        ('hybrid', {'firewall_driver': 'iptables_hybrid',
                    'of_interface': 'native',
                    'ovsdb_interface': 'native'}),
        ('openflow-cli_ovsdb-cli', {'firewall_driver': 'openvswitch',
                                    'of_interface': 'ovs-ofctl',
                                    'ovsdb_interface': 'vsctl'}),
        ('openflow-native_ovsdb-native', {'firewall_driver': 'openvswitch',
                                          'of_interface': 'native',
                                          'ovsdb_interface': 'native'})]

    def test_tcp_securitygroup(self):
        """Tests if a TCP security group rule is working, by confirming
        that 1. connection from allowed security group is allowed,
             2. connection from elsewhere is blocked,
             3. traffic not explicitly allowed (eg. ICMP) is blocked, and
             4. a security group update takes effect.
        """
        index_to_sg = [0, 0, 1]
        if self.firewall_driver == 'iptables_hybrid':
            # The iptables_hybrid driver lacks isolation between agents
            index_to_host = [0] * 3
        else:
            index_to_host = [0, 1, 1]

        tenant_uuid = uuidutils.generate_uuid()

        network = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], '20.0.0.0/24')

        sgs = [self.safe_client.create_security_group(tenant_uuid)
               for i in range(2)]
        ports = [
            self.safe_client.create_port(tenant_uuid, network['id'],
                                         self.environment.hosts[host].hostname,
                                         security_groups=[sgs[sg]['id']])
            for host, sg in zip(index_to_host, index_to_sg)]

        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=3333, port_range_max=3333)

        vms = [
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[host],
                    network['id'],
                    tenant_uuid,
                    self.safe_client,
                    neutron_port=ports[port]))
            for port, host in enumerate(index_to_host)]

        for vm in vms:
            vm.block_until_boot()

        # 1. check if connection from allowed security group is allowed
        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)

        # 2. check if connection from elsewhere is blocked
        self.assert_no_connection(
            vms[2].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)

        # 3. check if traffic not explicitly allowed (eg. ICMP) is blocked
        net_helpers.assert_no_ping(vms[0].namespace, vms[1].ip)
        net_helpers.assert_no_ping(vms[0].namespace, vms[2].ip)
        net_helpers.assert_no_ping(vms[1].namespace, vms[2].ip)

        # 4. check if a security group update takes effect
        self.assert_no_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3344,
            net_helpers.NetcatTester.TCP)

        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=3344, port_range_max=3344)

        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3344,
            net_helpers.NetcatTester.TCP)
