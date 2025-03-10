# Copyright 2018 Red Hat, Inc.
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
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.agent.linux import iptables_firewall
from neutron.agent.linux import iptables_manager
from neutron.agent.linux.openvswitch_firewall import iptables as ovs_iptables
from neutron.tests.common import machine_fixtures
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine

LOG = logging.getLogger(__name__)


class IptablesNotConfiguredException(Exception):
    pass


class VmsUnreachableException(Exception):
    pass


class FirewallMigrationTestCase(base.BaseFullStackTestCase):
    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l3_agent=False,
                l2_agent_type=constants.AGENT_TYPE_OVS,
                firewall_driver='iptables_hybrid',
                dhcp_agent=False,
            )]
        env = environment.Environment(
            environment.EnvironmentDescription(),
            host_descriptions)
        super().setUp(env)
        # fullstack doesn't separate nodes running ovs agent so iptables rules
        # are implemented in root namespace
        self.iptables_manager = iptables_manager.IptablesManager()

    def _prepare_resources(self):
        self.tenant_uuid = uuidutils.generate_uuid()
        network = self.safe_client.create_network(self.tenant_uuid)
        self.safe_client.create_subnet(
            self.tenant_uuid, network['id'], '20.0.0.0/24', enable_dhcp=False)
        vms = machine.FakeFullstackMachinesList(
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[0],
                    network['id'],
                    self.tenant_uuid,
                    self.safe_client,
                    use_dhcp=False))
            for i in range(2))
        vms.block_until_all_boot()

        for vm in vms:
            self._add_icmp_security_group_rule(vm)

        return vms

    def _add_icmp_security_group_rule(self, vm):
        sg_id = self.safe_client.create_security_group(self.tenant_uuid)['id']
        self.safe_client.create_security_group_rule(
            self.tenant_uuid, sg_id,
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)
        self.safe_client.client.update_port(
            vm.neutron_port['id'],
            body={'port': {'security_groups': [sg_id]}})
        self.addCleanup(
            self.safe_client.client.update_port,
            vm.neutron_port['id'],
            body={'port': {'security_groups': []}})

    def _validate_iptables_rules(self, vms):
        """Check if rules from iptables firewall are configured.

        Raises IptablesNotConfiguredException exception if no rules are found.
        """
        for vm in vms:
            vm_tap_device = iptables_firewall.get_hybrid_port_name(
                vm.neutron_port['id'])
            filter_rules = self.iptables_manager.get_rules_for_table('filter')
            if not any(vm_tap_device in line for line in filter_rules):
                raise IptablesNotConfiguredException(
                    "There are no iptables rules configured for interface %s" %
                    vm_tap_device)

    def _switch_firewall(self, firewall_driver):
        """Switch firewall_driver to given driver and restart the agent."""
        l2_agent = self.environment.hosts[0].l2_agent
        l2_agent_config = l2_agent.agent_cfg_fixture.config
        l2_agent_config['securitygroup']['firewall_driver'] = firewall_driver
        l2_agent.agent_cfg_fixture.write_config_to_configfile()
        l2_agent.restart()

        int_bridge = ovs_lib.OVSBridge(
            l2_agent_config['ovs']['integration_bridge'])
        predicate = functools.partial(
            ovs_iptables.is_bridge_cleaned, int_bridge)
        base.wait_until_true(
            predicate,
            exception=RuntimeError(
                "Bridge %s hasn't been marked as clean." % int_bridge.br_name))

    def test_migration(self):
        vms = self._prepare_resources()
        # Make sure ICMP packets can get through with iptables firewall
        vms.ping_all()
        self._validate_iptables_rules(vms)
        self._switch_firewall('openvswitch')
        # Make sure security groups still work after migration
        vms.ping_all()

        self.assertRaises(
            IptablesNotConfiguredException, self._validate_iptables_rules, vms)

        # Remove security groups so traffic cannot get through
        for vm in vms:
            self.safe_client.client.update_port(
                vm.neutron_port['id'],
                body={'port': {'security_groups': []}})

        # TODO(jlibosva): Test all permutations and don't fail on the first one
        self.assertRaises(machine_fixtures.FakeMachineException, vms.ping_all)

        # Add back some security groups allowing ICMP and test traffic can now
        # get through
        for vm in vms:
            self._add_icmp_security_group_rule(vm)
        vms.ping_all()
