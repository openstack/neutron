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

from neutron_lib import constants

from neutron.common import utils
from neutron.extensions import portbindings as pbs
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers


class FakeFullstackMachine(machine_fixtures.FakeMachineBase):

    def __init__(self, host, network_id, tenant_id, safe_client,
                 neutron_port=None):
        super(FakeFullstackMachine, self).__init__()
        self.host = host
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.safe_client = safe_client
        self.neutron_port = neutron_port

    def _setUp(self):
        super(FakeFullstackMachine, self)._setUp()

        self.bridge = self.host.get_bridge(self.network_id)

        if not self.neutron_port:
            self.neutron_port = self.safe_client.create_port(
                network_id=self.network_id,
                tenant_id=self.tenant_id,
                hostname=self.host.hostname)
        mac_address = self.neutron_port['mac_address']
        hybrid_plug = self.neutron_port[pbs.VIF_DETAILS].get(
            pbs.OVS_HYBRID_PLUG, False)

        self.port = self.useFixture(
            net_helpers.PortFixture.get(
                self.bridge, self.namespace, mac_address,
                self.neutron_port['id'], hybrid_plug)).port

        for fixed_ip in self.neutron_port['fixed_ips']:
            self._configure_ipaddress(fixed_ip)

    def _configure_ipaddress(self, fixed_ip):
        if (netaddr.IPAddress(fixed_ip['ip_address']).version ==
            constants.IP_VERSION_6):
            # v6Address/default_route is auto-configured.
            self._ipv6 = fixed_ip['ip_address']
        else:
            self._ip = fixed_ip['ip_address']
            subnet_id = fixed_ip['subnet_id']
            subnet = self.safe_client.client.show_subnet(subnet_id)
            prefixlen = netaddr.IPNetwork(subnet['subnet']['cidr']).prefixlen
            self._ip_cidr = '%s/%s' % (self._ip, prefixlen)

            # TODO(amuller): Support DHCP
            self.port.addr.add(self.ip_cidr)

            self.gateway_ip = subnet['subnet']['gateway_ip']
            if self.gateway_ip:
                net_helpers.set_namespace_gateway(self.port, self.gateway_ip)

    @property
    def ipv6(self):
        return self._ipv6

    @property
    def ip(self):
        return self._ip

    @property
    def ip_cidr(self):
        return self._ip_cidr

    def block_until_boot(self):
        utils.wait_until_true(
            lambda: (self.safe_client.client.show_port(self.neutron_port['id'])
                     ['port']['status'] == 'ACTIVE'),
            sleep=3)
