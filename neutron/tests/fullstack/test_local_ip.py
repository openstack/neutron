# Copyright 2021 Huawei, Inc.
# All Rights Reserved.
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

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class LocalIPTestCase(base.BaseFullStackTestCase):
    number_of_hosts = 2

    scenarios = [
        ('with_conntrack_rules', {'firewall_driver': 'noop'}),
        # with ovs firewall driver - test config will set static_nat=True
        ('static_nat', {'firewall_driver': 'openvswitch'}),
    ]

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l2_agent_type=constants.AGENT_TYPE_OVS,
                firewall_driver=self.firewall_driver,
                l3_agent=False,
                dhcp_agent=False) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription(
            mech_drivers='openvswitch',
            local_ip_ext=True)
        env = environment.Environment(env_desc, host_desc)
        super(LocalIPTestCase, self).setUp(env)
        self.project_id = uuidutils.generate_uuid()

        self.network = self.safe_client.create_network(
            self.project_id, 'network-local-ip-test')
        self.subnet_v4 = self.safe_client.create_subnet(
            self.project_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-v4-test')

    def _prepare_vms(self):
        port1 = self.safe_client.create_port(
            self.project_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_local_ip")

        port2 = self.safe_client.create_port(
            self.project_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_local_ip")

        port3 = self.safe_client.create_port(
            self.project_id, self.network['id'],
            self.environment.hosts[1].hostname,
            device_owner="compute:test_local_ip")

        vm1 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.project_id,
                self.safe_client,
                neutron_port=port1))

        vm2 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.project_id,
                self.safe_client,
                neutron_port=port2))

        vm_diff_host = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[1],
                self.network['id'],
                self.project_id,
                self.safe_client,
                neutron_port=port3))
        return machine.FakeFullstackMachinesList([vm1, vm2, vm_diff_host])

    def _create_local_ip(self):
        return self.safe_client.create_local_ip(
            self.project_id, network_id=self.network['id'])

    def _associate_local_ip(self, local_ip_id, port_id):
        return self.safe_client.create_local_ip_association(
            local_ip_id, port_id)

    def test_vm_is_accessible_by_local_ip(self):
        vms = self._prepare_vms()
        vms.block_until_all_boot()
        # first check basic connectivity between VMs
        vms.ping_all()

        local_ip = self._create_local_ip()
        self._associate_local_ip(
            local_ip['id'], vms[0].neutron_port['id'])
        # VM on same host should have access to this Local IP
        vms[1].block_until_ping(local_ip['local_ip_address'])

        # VM on different host shouldn't have access to this Local IP
        vms[2].assert_no_ping(local_ip['local_ip_address'])

        # check that VMs can still access each other with fixed IPs
        vms.ping_all()
