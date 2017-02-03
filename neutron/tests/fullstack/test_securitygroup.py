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
from neutron.common import utils as common_utils
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
        try:
            self.assertTrue(netcat.test_connectivity())
        finally:
            netcat.stop_processes()

    def assert_no_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)
        try:
            self.assertRaises(RuntimeError, netcat.test_connectivity)
        finally:
            netcat.stop_processes()


class TestSecurityGroupsSameNetwork(BaseSecurityGroupsSameNetworkTest):

    network_type = 'vxlan'
    scenarios = [
        ('ovs-hybrid', {
            'firewall_driver': 'iptables_hybrid',
            'of_interface': 'native',
            'ovsdb_interface': 'native',
            'l2_agent_type': constants.AGENT_TYPE_OVS}),
        ('ovs-openflow-cli_ovsdb-cli', {
            'firewall_driver': 'openvswitch',
            'of_interface': 'ovs-ofctl',
            'ovsdb_interface': 'vsctl',
            'l2_agent_type': constants.AGENT_TYPE_OVS}),
        ('ovs-openflow-native_ovsdb-native', {
            'firewall_driver': 'openvswitch',
            'of_interface': 'native',
            'ovsdb_interface': 'native',
            'l2_agent_type': constants.AGENT_TYPE_OVS}),
        ('linuxbridge-iptables', {
            'firewall_driver': 'iptables',
            'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})]

    # NOTE(toshii): As a firewall_driver can interfere with others,
    # the recommended way to add test is to expand this method, not
    # adding another.
    def test_securitygroup(self):
        """Tests if a security group rules are working, by confirming
        that 0. traffic is allowed when port security is disabled,
             1. connection from allowed security group is allowed,
             2. connection from elsewhere is blocked,
             3. traffic not explicitly allowed (eg. ICMP) is blocked,
             4. a security group update takes effect,
             5. a remote security group member addition works, and
             6. an established connection stops by deleting a SG rule.
             7. test other protocol functionality by using SCTP protocol
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
                                         security_groups=[],
                                         port_security_enabled=False)
            for host in index_to_host]

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

        # 0. check that traffic is allowed when port security is disabled
        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)
        self.assert_connection(
            vms[2].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)
        net_helpers.assert_ping(vms[0].namespace, vms[1].ip)
        net_helpers.assert_ping(vms[0].namespace, vms[2].ip)
        net_helpers.assert_ping(vms[1].namespace, vms[2].ip)

        # Apply security groups to the ports
        for port, sg in zip(ports, index_to_sg):
            self.safe_client.client.update_port(
                port['id'],
                body={'port': {'port_security_enabled': True,
                               'security_groups': [sgs[sg]['id']]}})

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

        # 5. check if a remote security group member addition works
        rule2 = self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[1]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=3355, port_range_max=3355)

        self.assert_connection(
            vms[2].namespace, vms[0].namespace, vms[0].ip, 3355,
            net_helpers.NetcatTester.TCP)

        # 6. check if an established connection stops by deleting
        #    the supporting SG rule.
        index_to_host.append(index_to_host[2])
        index_to_sg.append(1)
        ports.append(
            self.safe_client.create_port(tenant_uuid, network['id'],
                                         self.environment.hosts[
                                             index_to_host[3]].hostname,
                                         security_groups=[sgs[1]['id']]))

        vms.append(
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[index_to_host[3]],
                    network['id'],
                    tenant_uuid,
                    self.safe_client,
                    neutron_port=ports[3])))

        vms[3].block_until_boot()

        netcat = net_helpers.NetcatTester(vms[3].namespace,
            vms[0].namespace, vms[0].ip, 3355,
            net_helpers.NetcatTester.TCP)

        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())

        self.client.delete_security_group_rule(rule2['id'])
        common_utils.wait_until_true(lambda: netcat.test_no_connectivity(),
                                     sleep=8)
        netcat.stop_processes()

        # 7. check SCTP is supported by security group
        self.assert_no_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3366,
            net_helpers.NetcatTester.SCTP)

        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NUM_SCTP,
            port_range_min=3366, port_range_max=3366)

        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3366,
            net_helpers.NetcatTester.SCTP)
