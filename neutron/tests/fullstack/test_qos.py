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

import functools

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.linux import tc_lib
from neutron.common import utils
from neutron.services.qos import qos_consts
from neutron.tests.common.agents import l2_extensions
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.fullstack import utils as fullstack_utils
from neutron.tests.unit import testlib_api

from neutron.conf.plugins.ml2.drivers import linuxbridge as \
    linuxbridge_agent_config
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent as linuxbridge_agent
from neutron.services.qos.drivers.openvswitch import driver as ovs_drv


load_tests = testlib_api.module_load_tests

BANDWIDTH_BURST = 100
BANDWIDTH_LIMIT = 500
DSCP_MARK = 16


class BaseQoSRuleTestCase(object):
    of_interface = None
    ovsdb_interface = None
    number_of_hosts = 1

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l3_agent=False,
                of_interface=self.of_interface,
                ovsdb_interface=self.ovsdb_interface,
                l2_agent_type=self.l2_agent_type
            ) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription(
            qos=True)
        env = environment.Environment(env_desc, host_desc)
        super(BaseQoSRuleTestCase, self).setUp(env)

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(self.tenant_id,
                                                       'network-test')
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=False)

    def _create_qos_policy(self):
        return self.safe_client.create_qos_policy(
            self.tenant_id, 'fs_policy', 'Fullstack testing policy',
            shared='False')

    def _prepare_vm_with_qos_policy(self, rule_add_functions):
        qos_policy = self._create_qos_policy()
        qos_policy_id = qos_policy['id']

        port = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            qos_policy_id)

        for rule_add in rule_add_functions:
            rule_add(qos_policy)

        vm = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port))

        return vm, qos_policy


class _TestBwLimitQoS(BaseQoSRuleTestCase):

    number_of_hosts = 1

    def _wait_for_bw_rule_removed(self, vm):
        # No values are provided when port doesn't have qos policy
        self._wait_for_bw_rule_applied(vm, None, None)

    def _add_bw_limit_rule(self, limit, burst, qos_policy):
        qos_policy_id = qos_policy['id']
        rule = self.safe_client.create_bandwidth_limit_rule(
            self.tenant_id, qos_policy_id, limit, burst)
        # Make it consistent with GET reply
        rule['type'] = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT
        rule['qos_policy_id'] = qos_policy_id
        qos_policy['rules'].append(rule)

    def test_bw_limit_qos_policy_rule_lifecycle(self):
        new_limit = BANDWIDTH_LIMIT + 100

        # Create port with qos policy attached
        vm, qos_policy = self._prepare_vm_with_qos_policy(
            [functools.partial(self._add_bw_limit_rule,
                               BANDWIDTH_LIMIT, BANDWIDTH_BURST)])
        bw_rule = qos_policy['rules'][0]

        self._wait_for_bw_rule_applied(vm, BANDWIDTH_LIMIT, BANDWIDTH_BURST)
        qos_policy_id = qos_policy['id']

        self.client.delete_bandwidth_limit_rule(bw_rule['id'], qos_policy_id)
        self._wait_for_bw_rule_removed(vm)

        # Create new rule with no given burst value, in such case ovs and lb
        # agent should apply burst value as
        # bandwidth_limit * qos_consts.DEFAULT_BURST_RATE
        new_expected_burst = int(
            new_limit * qos_consts.DEFAULT_BURST_RATE
        )
        new_rule = self.safe_client.create_bandwidth_limit_rule(
            self.tenant_id, qos_policy_id, new_limit)
        self._wait_for_bw_rule_applied(vm, new_limit, new_expected_burst)

        # Update qos policy rule id
        self.client.update_bandwidth_limit_rule(
            new_rule['id'], qos_policy_id,
            body={'bandwidth_limit_rule': {'max_kbps': BANDWIDTH_LIMIT,
                                           'max_burst_kbps': BANDWIDTH_BURST}})
        self._wait_for_bw_rule_applied(vm, BANDWIDTH_LIMIT, BANDWIDTH_BURST)

        # Remove qos policy from port
        self.client.update_port(
            vm.neutron_port['id'],
            body={'port': {'qos_policy_id': None}})
        self._wait_for_bw_rule_removed(vm)


class TestBwLimitQoSOvs(_TestBwLimitQoS, base.BaseFullStackTestCase):
    l2_agent_type = constants.AGENT_TYPE_OVS
    scenarios = fullstack_utils.get_ovs_interface_scenarios()

    def _wait_for_bw_rule_applied(self, vm, limit, burst):
        utils.wait_until_true(
            lambda: vm.bridge.get_egress_bw_limit_for_port(
                vm.port.name) == (limit, burst))


class TestBwLimitQoSLinuxbridge(_TestBwLimitQoS, base.BaseFullStackTestCase):
    l2_agent_type = constants.AGENT_TYPE_LINUXBRIDGE

    def _wait_for_bw_rule_applied(self, vm, limit, burst):
        port_name = linuxbridge_agent.LinuxBridgeManager.get_tap_device_name(
            vm.neutron_port['id'])
        tc = tc_lib.TcCommand(
            port_name,
            linuxbridge_agent_config.DEFAULT_KERNEL_HZ_VALUE,
            namespace=vm.host.host_namespace
        )
        utils.wait_until_true(
            lambda: tc.get_filters_bw_limits() == (limit, burst))


class _TestDscpMarkingQoS(BaseQoSRuleTestCase):

    number_of_hosts = 2

    def _wait_for_dscp_marking_rule_removed(self, vm):
        self._wait_for_dscp_marking_rule_applied(vm, None)

    def _add_dscp_rule(self, dscp_mark, qos_policy):
        qos_policy_id = qos_policy['id']
        rule = self.safe_client.create_dscp_marking_rule(
            self.tenant_id, qos_policy_id, dscp_mark)
        # Make it consistent with GET reply
        rule['type'] = qos_consts.RULE_TYPE_DSCP_MARKING
        rule['qos_policy_id'] = qos_policy_id
        qos_policy['rules'].append(rule)

    def test_dscp_qos_policy_rule_lifecycle(self):
        new_dscp_mark = DSCP_MARK + 8

        # Create port with qos policy attached
        vm, qos_policy = self._prepare_vm_with_qos_policy(
            [functools.partial(self._add_dscp_rule, DSCP_MARK)])
        dscp_rule = qos_policy['rules'][0]

        self._wait_for_dscp_marking_rule_applied(vm, DSCP_MARK)
        qos_policy_id = qos_policy['id']

        self.client.delete_dscp_marking_rule(dscp_rule['id'], qos_policy_id)
        self._wait_for_dscp_marking_rule_removed(vm)

        # Create new rule
        new_rule = self.safe_client.create_dscp_marking_rule(
            self.tenant_id, qos_policy_id, new_dscp_mark)
        self._wait_for_dscp_marking_rule_applied(vm, new_dscp_mark)

        # Update qos policy rule id
        self.client.update_dscp_marking_rule(
            new_rule['id'], qos_policy_id,
            body={'dscp_marking_rule': {'dscp_mark': DSCP_MARK}})
        self._wait_for_dscp_marking_rule_applied(vm, DSCP_MARK)

        # Remove qos policy from port
        self.client.update_port(
            vm.neutron_port['id'],
            body={'port': {'qos_policy_id': None}})
        self._wait_for_dscp_marking_rule_removed(vm)

    def test_dscp_marking_packets(self):
        # Create port (vm) which will be used to received and test packets
        receiver_port = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[1].hostname)

        receiver = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[1],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=receiver_port))

        # Create port with qos policy attached
        sender, qos_policy = self._prepare_vm_with_qos_policy(
            [functools.partial(self._add_dscp_rule, DSCP_MARK)])

        sender.block_until_boot()
        receiver.block_until_boot()

        self._wait_for_dscp_marking_rule_applied(sender, DSCP_MARK)
        l2_extensions.wait_for_dscp_marked_packet(
            sender, receiver, DSCP_MARK)


class TestDscpMarkingQoSOvs(_TestDscpMarkingQoS, base.BaseFullStackTestCase):
    scenarios = fullstack_utils.get_ovs_interface_scenarios()
    l2_agent_type = constants.AGENT_TYPE_OVS

    def _wait_for_dscp_marking_rule_applied(self, vm, dscp_mark):
        l2_extensions.wait_until_dscp_marking_rule_applied_ovs(
            vm.bridge, vm.port.name, dscp_mark)


class TestDscpMarkingQoSLinuxbridge(_TestDscpMarkingQoS,
                                    base.BaseFullStackTestCase):
    l2_agent_type = constants.AGENT_TYPE_LINUXBRIDGE

    def _wait_for_dscp_marking_rule_applied(self, vm, dscp_mark):
        l2_extensions.wait_until_dscp_marking_rule_applied_linuxbridge(
            vm.host.host_namespace, vm.port.name, dscp_mark)


class TestQoSWithL2Population(base.BaseFullStackTestCase):

    def setUp(self):
        host_desc = []  # No need to register agents for this test case
        env_desc = environment.EnvironmentDescription(qos=True, l2_pop=True)
        env = environment.Environment(env_desc, host_desc)
        super(TestQoSWithL2Population, self).setUp(env)

    def test_supported_qos_rule_types(self):
        res = self.client.list_qos_rule_types()
        rule_types = {t['type'] for t in res['rule_types']}
        expected_rules = set(ovs_drv.SUPPORTED_RULES)
        self.assertEqual(expected_rules, rule_types)
