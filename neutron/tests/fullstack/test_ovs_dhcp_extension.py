# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
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

from neutron.common import utils as common_utils
from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


class OvsDHCPExtensionTestCase(base.BaseFullStackTestCase):
    number_of_hosts = 1

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l2_agent_type=constants.AGENT_TYPE_OVS,
                firewall_driver='openvswitch',
                # VM needs to receive the RA notification
                # from radvd which is handled by router and L3 agent.
                l3_agent=True,
                dhcp_agent=False) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription(
            mech_drivers='openvswitch',
            enable_traditional_dhcp=False)
        env = environment.Environment(env_desc, host_desc)
        super(OvsDHCPExtensionTestCase, self).setUp(env)
        self.tenant_id = uuidutils.generate_uuid()

        network = self.safe_client.create_network(
            self.tenant_id, name='public', external=True)
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "240.0.0.0", "240.255.255.255", "24")).network
        self.safe_client.create_subnet(
            self.tenant_id, network['id'], cidr)

        router = self.safe_client.create_router(
            self.tenant_id, external_network=network['id'])

        self.network = self.safe_client.create_network(
            self.tenant_id, 'network-test')
        subnet_routes_v4 = [
            {"destination": "1.1.1.0/24", "nexthop": "10.0.0.100"},
            {"destination": "2.2.2.2/32", "nexthop": "10.0.0.101"}]
        self.subnet_v4 = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-v4-test',
            host_routes=subnet_routes_v4)

        router_interface_info = self.safe_client.add_router_interface(
            router['id'], self.subnet_v4['id'])
        self.block_until_port_status_active(
            router_interface_info['port_id'])

        subnet_routes_v6 = [
            {"destination": "2001:4860:4860::8888/128",
             "nexthop": "fda7:a5cc:3460:1::1"},
            {"destination": "1234:5678:abcd::/64",
             "nexthop": "fda7:a5cc:3460:1::fff"}]
        self.subnet_v6 = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='fda7:a5cc:3460:1::/64',
            gateway_ip='fda7:a5cc:3460:1::1',
            enable_dhcp=True,
            ipv6_address_mode="dhcpv6-stateful",
            ipv6_ra_mode="dhcpv6-stateful",
            ip_version=6,
            name='subnet-v6-test',
            host_routes=subnet_routes_v6)

        # Need router radvd to send IPv6 address prefix to make the default
        # route work.
        router_interface_info = self.safe_client.add_router_interface(
            router['id'], self.subnet_v6['id'])
        self.block_until_port_status_active(
            router_interface_info['port_id'])

    def block_until_port_status_active(self, port_id):
        def is_port_status_active():
            port = self.client.show_port(port_id)
            return port['port']['status'] == 'ACTIVE'
        common_utils.wait_until_true(lambda: is_port_status_active(), sleep=1)

    def _prepare_vms(self):
        sgs = [self.safe_client.create_security_group(self.tenant_id)
               for _ in range(2)]

        port1 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_ovs_dhcp",
            security_groups=[sgs[0]['id']])

        port2 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_ovs_dhcp",
            security_groups=[sgs[1]['id']])

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[0]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[0]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv6,
            protocol=constants.PROTO_NAME_ICMP)

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[1]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[1]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv6,
            protocol=constants.PROTO_NAME_ICMP)

        vm1 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port1,
                use_dhcp=True,
                use_dhcp6=True))

        vm2 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port2,
                use_dhcp=True,
                use_dhcp6=True))
        return machine.FakeFullstackMachinesList([vm1, vm2])

    def test_ovs_dhcp_agent_extension_ping_vms(self):
        vms = self._prepare_vms()
        vms.block_until_all_boot()
        vms.block_until_all_dhcp_config_done()
        # ping -4 from vm_1 to vm_2
        vms.ping_all()
        # ping -6 from vm_1 to vm_2
        vms.ping6_all()
