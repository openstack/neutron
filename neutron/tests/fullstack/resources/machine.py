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

import netaddr

from neutron.agent.linux import utils
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers


class FakeFullstackMachine(machine_fixtures.FakeMachineBase):
    def __init__(self, host, network_id, tenant_id, safe_client):
        super(FakeFullstackMachine, self).__init__()
        self.bridge = host.ovs_agent.br_int
        self.host_binding = host.hostname
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.safe_client = safe_client

    def _setUp(self):
        super(FakeFullstackMachine, self)._setUp()

        self.neutron_port = self.safe_client.create_port(
            network_id=self.network_id,
            tenant_id=self.tenant_id,
            hostname=self.host_binding)
        self.neutron_port_id = self.neutron_port['id']
        mac_address = self.neutron_port['mac_address']

        self.port = self.useFixture(
            net_helpers.PortFixture.get(
                self.bridge, self.namespace, mac_address,
                self.neutron_port_id)).port

        self._ip = self.neutron_port['fixed_ips'][0]['ip_address']
        subnet_id = self.neutron_port['fixed_ips'][0]['subnet_id']
        subnet = self.safe_client.client.show_subnet(subnet_id)
        prefixlen = netaddr.IPNetwork(subnet['subnet']['cidr']).prefixlen
        self._ip_cidr = '%s/%s' % (self._ip, prefixlen)

        # TODO(amuller): Support DHCP
        self.port.addr.add(self.ip_cidr)

        self.gateway_ip = subnet['subnet']['gateway_ip']
        if self.gateway_ip:
            net_helpers.set_namespace_gateway(self.port, self.gateway_ip)

    @property
    def ip(self):
        return self._ip

    @property
    def ip_cidr(self):
        return self._ip_cidr

    def block_until_boot(self):
        utils.wait_until_true(
            lambda: (self.safe_client.client.show_port(self.neutron_port_id)
                     ['port']['status'] == 'ACTIVE'),
            sleep=3)
