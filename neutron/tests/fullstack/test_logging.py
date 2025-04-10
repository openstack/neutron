# Copyright 2018 Fujitsu Limited
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

import re

from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as ovs_const
from oslo_utils import uuidutils

from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


class BaseLoggingTestCase(base.BaseFullStackTestCase):
    number_of_hosts = 1

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l2_agent_type=constants.AGENT_TYPE_OVS,
                firewall_driver='openvswitch',
                dhcp_agent=True) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription(
            mech_drivers='openvswitch', log=True)
        env = environment.Environment(env_desc, host_desc)
        super().setUp(env)

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(
            self.tenant_id, 'network-test')
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test')

    def assert_no_connection(self, *args, **kwargs):
        netcat = net_helpers.NetcatTester(*args, **kwargs)
        try:
            base.wait_until_true(netcat.test_no_connectivity)
        finally:
            netcat.stop_processes()

    def _wait_for_log_rules_applied(self, vm, table, actions):

        def _is_log_flow_set(table, actions):
            flows = vm.bridge.dump_flows_for_table(table)
            flows_list = flows.splitlines()
            pattern = re.compile(
                fr"^.* table={table}.* actions={actions}")
            for flow in flows_list:
                if pattern.match(flow.strip()):
                    return True
            return False
        base.wait_until_true(lambda: _is_log_flow_set(table, actions))

    def _check_log(self, log_id, action, regex_str=None):

        config = self.environment.hosts[0].ovs_agent.agent_config

        def _is_log_event(log_id, action, regex_str):
            regex_p = re.compile(
                r"^.*action={}.* log_resource_ids=\[[^\]]*{}".format(
                    action, log_id) + ".*" + regex_str if regex_str else "")

            with open(config.network_log.local_output_log_base) as f:
                for line in f.readlines():
                    if regex_p.match(line):
                        return True
            return False

        base.wait_until_true(lambda: _is_log_event(log_id, action, regex_str))


class TestLogging(BaseLoggingTestCase):
    def _create_network_log(self, resource_type,
                            resource_id=None, target_id=None):
        return self.safe_client.create_network_log(
            tenant_id=self.tenant_id,
            name='test-log',
            resource_type=resource_type,
            resource_id=resource_id,
            target_id=target_id)

    def _prepare_vms(self):

        sgs = [self.safe_client.create_security_group(self.tenant_id)
               for i in range(2)]

        port1 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            security_groups=[sgs[0]['id']])

        port2 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            security_groups=[sgs[1]['id']])

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[0]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[1]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)

        vm1 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port1))

        vm2 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port2))
        return machine.FakeFullstackMachinesList([vm1, vm2])

    def test_logging(self):
        vms = self._prepare_vms()

        vms.block_until_all_boot()

        sg_log = self._create_network_log(resource_type='security_group')
        log_id = sg_log['log']['id']
        for vm in vms:
            self._wait_for_log_rules_applied(
                vm, ovs_const.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                actions=r"resubmit\(,%d\),CONTROLLER:65535" % (
                    ovs_const.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE))
            self._wait_for_log_rules_applied(
                vm, ovs_const.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                actions="CONTROLLER:65535")
            self._wait_for_log_rules_applied(
                vm, ovs_const.DROPPED_TRAFFIC_TABLE,
                actions="CONTROLLER:65535")

        # ping all vm
        vms.ping_all()

        # check log accept packets for icmp
        self._check_log(log_id=log_id, action='ACCEPT')

        # Try to connect from VM1 to VM2 via ssh
        self.assert_no_connection(
            vms[0].namespace, vms[1].namespace, vms[1].ip, 22,
            net_helpers.NetcatTester.TCP)

        # Try to ssh from VM2 to VM1 via ssh
        self.assert_no_connection(
            vms[1].namespace, vms[0].namespace, vms[0].ip, 22,
            net_helpers.NetcatTester.TCP)

        # check log drop packets for ssh
        self._check_log(log_id=log_id, action='DROP', regex_str="dst_port=22")
