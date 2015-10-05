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

from oslo_utils import uuidutils

from neutron.agent.linux import utils
from neutron.services.qos import qos_consts
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine

from neutron.plugins.ml2.drivers.openvswitch.mech_driver import \
    mech_openvswitch as mech_ovs


BANDWIDTH_LIMIT = 500
BANDWIDTH_BURST = 100


def _wait_for_rule_applied(vm, limit, burst):
    utils.wait_until_true(
        lambda: vm.bridge.get_egress_bw_limit_for_port(
            vm.port.name) == (limit, burst))


def _wait_for_rule_removed(vm):
    # No values are provided when port doesn't have qos policy
    _wait_for_rule_applied(vm, None, None)


class TestQoSWithOvsAgent(base.BaseFullStackTestCase):

    def setUp(self):
        host_desc = [environment.HostDescription(l3_agent=False)]
        env_desc = environment.EnvironmentDescription(qos=True)
        env = environment.Environment(env_desc, host_desc)
        super(TestQoSWithOvsAgent, self).setUp(env)

    def _create_qos_policy(self):
        return self.safe_client.create_qos_policy(
            self.tenant_id, 'fs_policy', 'Fullstack testing policy',
            shared='False')

    def _prepare_vm_with_qos_policy(self, limit, burst):
        qos_policy = self._create_qos_policy()
        qos_policy_id = qos_policy['id']

        rule = self.safe_client.create_bandwidth_limit_rule(
            self.tenant_id, qos_policy_id, limit, burst)
        # Make it consistent with GET reply
        qos_policy['rules'].append(rule)
        rule['type'] = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT
        rule['qos_policy_id'] = qos_policy_id

        port = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            qos_policy_id)

        vm = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port))

        return vm, qos_policy

    def test_qos_policy_rule_lifecycle(self):
        new_limit = BANDWIDTH_LIMIT + 100
        new_burst = BANDWIDTH_BURST + 50

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(self.tenant_id,
                                                       'network-test')
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=False)

        # Create port with qos policy attached
        vm, qos_policy = self._prepare_vm_with_qos_policy(BANDWIDTH_LIMIT,
                                                          BANDWIDTH_BURST)
        _wait_for_rule_applied(vm, BANDWIDTH_LIMIT, BANDWIDTH_BURST)
        qos_policy_id = qos_policy['id']
        rule = qos_policy['rules'][0]

        # Remove rule from qos policy
        self.client.delete_bandwidth_limit_rule(rule['id'], qos_policy_id)
        _wait_for_rule_removed(vm)

        # Create new rule
        new_rule = self.safe_client.create_bandwidth_limit_rule(
            self.tenant_id, qos_policy_id, new_limit, new_burst)
        _wait_for_rule_applied(vm, new_limit, new_burst)

        # Update qos policy rule id
        self.client.update_bandwidth_limit_rule(
            new_rule['id'], qos_policy_id,
            body={'bandwidth_limit_rule': {'max_kbps': BANDWIDTH_LIMIT,
                                           'max_burst_kbps': BANDWIDTH_BURST}})
        _wait_for_rule_applied(vm, BANDWIDTH_LIMIT, BANDWIDTH_BURST)

        # Remove qos policy from port
        self.client.update_port(
            vm.neutron_port['id'],
            body={'port': {'qos_policy_id': None}})
        _wait_for_rule_removed(vm)


class TestQoSWithL2Population(base.BaseFullStackTestCase):

    def setUp(self):
        host_desc = []  # No need to register agents for this test case
        env_desc = environment.EnvironmentDescription(qos=True, l2_pop=True)
        env = environment.Environment(env_desc, host_desc)
        super(TestQoSWithL2Population, self).setUp(env)

    def test_supported_qos_rule_types(self):
        res = self.client.list_qos_rule_types()
        rule_types = {t['type'] for t in res['rule_types']}
        expected_rules = (
            set(mech_ovs.OpenvswitchMechanismDriver.supported_qos_rule_types))
        self.assertEqual(expected_rules, rule_types)
