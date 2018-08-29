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
from neutron.tests import base as tests_base
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

    def setUp(self):
        debug_iptables = self.firewall_driver.startswith("iptables")
        host_descriptions = [
            environment.HostDescription(
                of_interface=self.of_interface,
                l2_agent_type=self.l2_agent_type,
                firewall_driver=self.firewall_driver,
                dhcp_agent=True) for _ in range(self.num_hosts)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type,
                debug_iptables=debug_iptables),
            host_descriptions)
        super(BaseSecurityGroupsSameNetworkTest, self).setUp(env)

        if (self.firewall_driver == 'openvswitch' and
                not OVSVersionChecker.supports_ovsfirewall()):
            self.skipTest("Open vSwitch firewall_driver doesn't work "
                          "with this version of ovs.")

    def assert_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)

        def test_connectivity():
            try:
                return netcat.test_connectivity()
            except RuntimeError:
                return False

        try:
            common_utils.wait_until_true(test_connectivity)
        finally:
            netcat.stop_processes()

    def assert_no_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)
        try:
            common_utils.wait_until_true(netcat.test_no_connectivity)
        finally:
            netcat.stop_processes()


class TestSecurityGroupsSameNetwork(BaseSecurityGroupsSameNetworkTest):

    network_type = 'vxlan'
    scenarios = [
        # The iptables_hybrid driver lacks isolation between agents and
        # because of that using only one host is enough
        ('ovs-hybrid', {
            'firewall_driver': 'iptables_hybrid',
            'of_interface': 'native',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'num_hosts': 1}),
        ('ovs-openflow-cli', {
            'firewall_driver': 'openvswitch',
            'of_interface': 'ovs-ofctl',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'num_hosts': 2}),
        ('ovs-openflow-native', {
            'firewall_driver': 'openvswitch',
            'of_interface': 'native',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'num_hosts': 2}),
        ('linuxbridge-iptables', {
            'firewall_driver': 'iptables',
            'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE,
            'num_hosts': 2})]

    index_to_sg = [0, 0, 1, 2]

    # NOTE(toshii): As a firewall_driver can interfere with others,
    # the recommended way to add test is to expand this method, not
    # adding another.
    @tests_base.unstable_test("bug 1779328")
    def test_securitygroup(self):
        """Tests if a security group rules are working, by confirming
        that 0. traffic is allowed when port security is disabled,
             1. connection from outside of allowed security group is blocked
             2. connection from allowed security group is permitted
             3. traffic not explicitly allowed (eg. ICMP) is blocked,
             4. a security group update takes effect,
             5. a remote security group member addition works, and
             6. an established connection stops by deleting a SG rule.
             7. multiple overlapping remote rules work,
             8. test other protocol functionality by using SCTP protocol
             9. test two vms with same mac on the same host in different
                networks
             10. test using multiple security groups
        """

        tenant_uuid = uuidutils.generate_uuid()
        subnet_cidr = '20.0.0.0/24'
        vms, ports, sgs, network, index_to_host = self._create_resources(
            tenant_uuid, subnet_cidr)

        # 0. check that traffic is allowed when port security is disabled
        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)
        self.assert_connection(
            vms[2].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)
        vms[0].block_until_ping(vms[1].ip)
        vms[0].block_until_ping(vms[2].ip)
        vms[1].block_until_ping(vms[2].ip)

        # Apply security groups to the ports
        for port, sg in zip(ports, self.index_to_sg):
            self.safe_client.client.update_port(
                port['id'],
                body={'port': {'port_security_enabled': True,
                               'security_groups': [sgs[sg]['id']]}})

        # 1. connection from outside of allowed security group is blocked
        netcat = net_helpers.NetcatTester(
            vms[2].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)
        # Wait until port update takes effect on the ports
        common_utils.wait_until_true(
            netcat.test_no_connectivity,
            exception=AssertionError(
                "Still can connect to the VM from different host.")
        )
        netcat.stop_processes()

        # 2. check if connection from allowed security group is permitted
        self.assert_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 3333,
            net_helpers.NetcatTester.TCP)

        # 3. check if traffic not explicitly allowed (eg. ICMP) is blocked
        vms[0].block_until_no_ping(vms[1].ip)
        vms[0].block_until_no_ping(vms[2].ip)
        vms[1].block_until_no_ping(vms[2].ip)

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
        self.index_to_sg.append(1)
        ports.append(
            self.safe_client.create_port(tenant_uuid, network['id'],
                                         self.environment.hosts[
                                             index_to_host[-1]].hostname,
                                         security_groups=[sgs[1]['id']]))

        vms.append(
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[index_to_host[-1]],
                    network['id'],
                    tenant_uuid,
                    self.safe_client,
                    neutron_port=ports[-1],
                    use_dhcp=True)))
        self.assertEqual(5, len(vms))

        vms[4].block_until_boot()

        netcat = net_helpers.NetcatTester(vms[4].namespace,
            vms[0].namespace, vms[0].ip, 3355,
            net_helpers.NetcatTester.TCP)

        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())

        self.client.delete_security_group_rule(rule2['id'])
        common_utils.wait_until_true(lambda: netcat.test_no_connectivity(),
                                     sleep=8)
        netcat.stop_processes()

        # 7. check if multiple overlapping remote rules work
        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[1]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=3333, port_range_max=3333)
        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[2]['id'], direction='ingress',
            ethertype=constants.IPv4)

        for i in range(2):
            self.assert_connection(
                vms[0].namespace, vms[1].namespace, vms[1].ip, 3333,
                net_helpers.NetcatTester.TCP)
            self.assert_connection(
                vms[2].namespace, vms[1].namespace, vms[1].ip, 3333,
                net_helpers.NetcatTester.TCP)
            self.assert_connection(
                vms[3].namespace, vms[0].namespace, vms[0].ip, 8080,
                net_helpers.NetcatTester.TCP)

        # 8. check SCTP is supported by security group
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

        # 9. test two vms with same mac on the same host in different networks
        self._test_overlapping_mac_addresses()

        # 10. Check using multiple security groups
        self._test_using_multiple_security_groups()

    def _test_using_multiple_security_groups(self):
        """Test using multiple security groups.

        This test will do following things:
        1. Create three vms with two security groups. vm0, vm1 in sg0;
           vm2 in sg1.
        2. Add SSH and ICMP rules in sg0. vm0 and vm1 can ping and ssh
           for each other, but can not access between vm0 and vm2.
        3. Using multiple security groups(sg0, sg1) for vm0, and sg1
           have rules allowed sg0 access(ICMP), so vm0 and vm1 can
           ping vm2.
        4. Then remove sg0 from vm0, we removed ICMP and SSH rules.
           vm0 and vm1 can not ping and ssh for each other.
        """

        tenant_uuid = uuidutils.generate_uuid()
        subnet_cidr = '30.0.0.0/24'
        vms, ports, sgs, _, _ = self._create_resources(tenant_uuid,
                                                       subnet_cidr)

        # Apply security groups to the ports
        for port, sg in zip(ports, self.index_to_sg):
            self.safe_client.client.update_port(
                port['id'],
                body={'port': {'port_security_enabled': True,
                               'security_groups': [sgs[sg]['id']]}})

        # Traffic not explicitly allowed (eg. SSH, ICMP) is blocked
        self.verify_no_connectivity_between_vms(
            vms[1], vms[0], net_helpers.NetcatTester.TCP, 22)

        vms[0].block_until_no_ping(vms[1].ip)
        vms[0].block_until_no_ping(vms[2].ip)
        vms[1].block_until_no_ping(vms[2].ip)

        # Add SSH and ICMP allowed in the same security group
        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=22, port_range_max=22)

        self.verify_connectivity_between_vms(
            vms[1], vms[0], net_helpers.NetcatTester.TCP, 22)

        self.verify_no_connectivity_between_vms(
            vms[2], vms[0], net_helpers.NetcatTester.TCP, 22)

        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[0]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)

        vms[1].block_until_ping(vms[0].ip)
        vms[2].block_until_no_ping(vms[0].ip)

        # Update vm0 to use two security groups
        # Add security group rules(ICMP) in another security group
        self.safe_client.client.update_port(
                ports[0]['id'],
                body={'port': {'security_groups': [sgs[0]['id'],
                                                   sgs[1]['id']]}})

        self.safe_client.create_security_group_rule(
            tenant_uuid, sgs[1]['id'],
            remote_group_id=sgs[0]['id'], direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)

        vms[0].block_until_ping(vms[2].ip)
        vms[1].block_until_ping(vms[2].ip)
        vms[2].block_until_no_ping(vms[0].ip)
        vms[2].block_until_no_ping(vms[1].ip)

        self.verify_connectivity_between_vms(
            vms[1], vms[0], net_helpers.NetcatTester.TCP, 22)

        self.verify_no_connectivity_between_vms(
            vms[2], vms[0], net_helpers.NetcatTester.TCP, 22)

        # Remove first security group from port
        self.safe_client.client.update_port(
                ports[0]['id'],
                body={'port': {'security_groups': [sgs[1]['id']]}})

        vms[0].block_until_ping(vms[2].ip)
        vms[1].block_until_ping(vms[2].ip)
        vms[2].block_until_no_ping(vms[0].ip)
        vms[2].block_until_no_ping(vms[1].ip)

        self.verify_no_connectivity_between_vms(
            vms[1], vms[0], net_helpers.NetcatTester.TCP, 22)

    # NOTE: This can be used after refactor other tests to
    # one scenario one test.
    def _create_resources(self, tenant_uuid, subnet_cidr):
        if self.firewall_driver == 'iptables_hybrid':
            # The iptables_hybrid driver lacks isolation between agents
            index_to_host = [0] * 4
        else:
            index_to_host = [0, 1, 1, 0]

        network = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], subnet_cidr)

        sgs = [self.safe_client.create_security_group(tenant_uuid)
               for i in range(3)]
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
                    neutron_port=ports[port],
                    use_dhcp=True))
            for port, host in enumerate(index_to_host)]
        map(lambda vm: vm.block_until_boot(), vms)
        map(lambda vm: vm.block_until_dhcp_config_done(), vms)

        return vms, ports, sgs, network, index_to_host

    def _create_vm_on_host(
            self, project_id, network_id, sg_id, host, mac_address=None):
        if mac_address:
            port = self.safe_client.create_port(
                project_id, network_id, host.hostname,
                security_groups=[sg_id], mac_address=mac_address)
        else:
            port = self.safe_client.create_port(
                project_id, network_id, host.hostname,
                security_groups=[sg_id])

        return self.useFixture(
            machine.FakeFullstackMachine(
                host, network_id, project_id, self.safe_client,
                neutron_port=port))

    def _create_three_vms_first_has_static_mac(
            self, project_id, allowed_port, subnet_cidr):
        """Create three vms.

        First VM has a static mac and is placed on first host. Second VM is
        placed on the first host and third VM is placed on second host.
        """
        network = self.safe_client.create_network(project_id)
        self.safe_client.create_subnet(
            project_id, network['id'], subnet_cidr)
        sg = self.safe_client.create_security_group(project_id)

        self.safe_client.create_security_group_rule(
            project_id, sg['id'],
            direction='ingress',
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_TCP,
            port_range_min=allowed_port, port_range_max=allowed_port)

        vms = [self._create_vm_on_host(
            project_id, network['id'], sg['id'], self.environment.hosts[0],
            mac_address="fa:16:3e:de:ad:fe")]

        if self.firewall_driver == 'iptables_hybrid':
            # iptables lack isolation between agents, use only a single host
            vms.extend([
                self._create_vm_on_host(
                    project_id, network['id'], sg['id'],
                    self.environment.hosts[0])
                for _ in range(2)])
        else:
            vms.extend([
                self._create_vm_on_host(
                    project_id, network['id'], sg['id'], host)
                for host in self.environment.hosts[:2]])

        map(lambda vm: vm.block_until_boot(), vms)
        return vms

    def verify_connectivity_between_vms(self, src_vm, dst_vm, protocol, port):
        self.assert_connection(
            src_vm.namespace, dst_vm.namespace, dst_vm.ip, port,
            protocol)

    def verify_no_connectivity_between_vms(
            self, src_vm, dst_vm, protocol, port):
        self.assert_no_connection(
            src_vm.namespace, dst_vm.namespace, dst_vm.ip, port, protocol)

    def _test_overlapping_mac_addresses(self):
        project1 = uuidutils.generate_uuid()
        p1_allowed = 4444

        project2 = uuidutils.generate_uuid()
        p2_allowed = 4445

        p1_vms = self._create_three_vms_first_has_static_mac(
            project1, p1_allowed, '20.0.2.0/24')
        p2_vms = self._create_three_vms_first_has_static_mac(
            project2, p2_allowed, '20.0.3.0/24')

        have_connectivity = [
            (p1_vms[0], p1_vms[1], p1_allowed),
            (p1_vms[1], p1_vms[2], p1_allowed),
            (p2_vms[0], p2_vms[1], p2_allowed),
            (p2_vms[1], p2_vms[2], p2_allowed),
        ]

        for vm1, vm2, port in have_connectivity:
            self.verify_connectivity_between_vms(
                vm1, vm2, net_helpers.NetcatTester.TCP, port)
            self.verify_connectivity_between_vms(
                vm2, vm1, net_helpers.NetcatTester.TCP, port)
            self.verify_no_connectivity_between_vms(
                vm1, vm2, net_helpers.NetcatTester.TCP, port + 1)
            self.verify_no_connectivity_between_vms(
                vm2, vm1, net_helpers.NetcatTester.TCP, port + 1)
