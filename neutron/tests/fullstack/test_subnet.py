# Copyright 2019 Red Hat, Inc.
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
from neutronclient.common import exceptions as nclient_exceptions
from oslo_utils import uuidutils

from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


class TestSubnet(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True, dhcp_agent=True),
            environment.HostDescription()]
        env = environment.Environment(
            environment.EnvironmentDescription(network_type='vlan',
                                               l2_pop=False),
            host_descriptions)
        super().setUp(env)
        self._project_id = uuidutils.generate_uuid()
        self._network = self._create_network(self._project_id)

    def _create_network(self, project_id, name='test_network'):
        return self.safe_client.create_network(project_id, name=name)

    def _create_subnetpool(self, project_id, min_prefixlen, max_prefixlen,
                           default_prefixlen, prefixes):
        return self.safe_client.create_subnetpool(
            project_id=project_id, min_prefixlen=min_prefixlen,
            max_prefixlen=max_prefixlen,
            default_prefixlen=default_prefixlen, prefixes=prefixes)

    def _create_subnet(self, project_id, network_id, cidr=None,
                       ipv6_address_mode=None, ipv6_ra_mode=None,
                       subnetpool_id=None, ip_version=None, gateway_ip=None):
        if ipv6_address_mode or ipv6_ra_mode:
            ip_version = constants.IP_VERSION_6
        return self.safe_client.create_subnet(
            project_id, network_id, cidr=cidr, enable_dhcp=True,
            ipv6_address_mode=ipv6_address_mode, ipv6_ra_mode=ipv6_ra_mode,
            subnetpool_id=subnetpool_id, ip_version=ip_version,
            gateway_ip=gateway_ip)

    def _show_subnet(self, subnet_id):
        return self.client.show_subnet(subnet_id)

    def test_create_subnet_ipv6_prefix_delegation(self):
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     None, ipv6_address_mode='slaac',
                                     ipv6_ra_mode='slaac',
                                     subnetpool_id='prefix_delegation')
        subnet = self._show_subnet(subnet['id'])
        cidr = subnet['subnet']['cidr']
        self.assertEqual(subnet['subnet']['gateway_ip'],
                         str(netaddr.IPNetwork(cidr).network))
        router = self.safe_client.create_router(self._project_id)
        self.safe_client.add_router_interface(
            router['id'], subnet['subnet']['id'])

    def test_create_subnet_ipv4_with_subnetpool(self):
        subnetpool_cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                '240.0.0.0', '240.255.255.255', '16')).network
        subnetpool = self._create_subnetpool(self._project_id, 8, 24, 24,
                                             [subnetpool_cidr])
        subnets = list(subnetpool_cidr.subnet(24))

        # Request from subnetpool.
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     subnetpool_id=subnetpool['id'],
                                     ip_version=4)
        subnet = self._show_subnet(subnet['id'])
        self.assertEqual(subnet['subnet']['cidr'], str(subnets[0].cidr))
        self.assertEqual(subnet['subnet']['gateway_ip'],
                         str(subnets[0].network + 1))

        # Request from subnetpool with gateway_ip.
        gateway_ip = subnets[1].ip + 10
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     subnetpool_id=subnetpool['id'],
                                     ip_version=4, gateway_ip=gateway_ip)
        subnet = self._show_subnet(subnet['id'])
        self.assertEqual(subnet['subnet']['cidr'], str(subnets[1].cidr))
        self.assertEqual(subnet['subnet']['gateway_ip'], str(gateway_ip))

        # Request from subnetpool with incorrect gateway_ip (cannot be the
        # network broadcast IP).
        gateway_ip = subnets[2].ip
        self.assertRaises(nclient_exceptions.Conflict,
                          self._create_subnet, self._project_id,
                          self._network['id'], subnetpool_id=subnetpool['id'],
                          ip_version=4, gateway_ip=gateway_ip)

        # Request from subnetpool using a correct gateway_ip from the same
        # CIDR; that means this subnet has not been allocated yet.
        gateway_ip += 1
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     subnetpool_id=subnetpool['id'],
                                     ip_version=4, gateway_ip=gateway_ip)
        subnet = self._show_subnet(subnet['id'])
        self.assertEqual(subnet['subnet']['cidr'], str(subnets[2].cidr))
        self.assertEqual(subnet['subnet']['gateway_ip'], str(gateway_ip))

    def test_subnet_with_prefixlen_31_connectivity(self):
        network = self._create_network(self._project_id)
        self.safe_client.create_subnet(
            self._project_id, network['id'],
            cidr='10.14.0.20/31',
            gateway_ip='10.14.0.19',
            name='subnet-test',
            enable_dhcp=False)

        vms = self._prepare_vms_in_net(self._project_id, network, False)
        vms.ping_all()

    def test_subnet_with_prefixlen_32_vm_spawn(self):
        network = self._create_network(self._project_id)
        self.safe_client.create_subnet(
            self._project_id, network['id'],
            cidr='10.14.0.20/32',
            gateway_ip='10.14.0.19',
            name='subnet-test',
            enable_dhcp=False)

        vm = self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[0],
                    network['id'],
                    self._project_id,
                    self.safe_client))
        vm.block_until_boot()
