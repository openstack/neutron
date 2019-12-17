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
from oslo_utils import uuidutils

from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment


class TestSubnet(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True, dhcp_agent=True),
            environment.HostDescription()]
        env = environment.Environment(
            environment.EnvironmentDescription(network_type='vlan',
                                               l2_pop=False),
            host_descriptions)
        super(TestSubnet, self).setUp(env)
        self._project_id = uuidutils.generate_uuid()
        self._network = self._create_network(self._project_id)

    def _create_network(self, project_id, name='test_network'):
        return self.safe_client.create_network(project_id, name=name)

    def _create_subnet(self, project_id, network_id, cidr,
                       ipv6_address_mode=None, ipv6_ra_mode=None,
                       subnetpool_id=None):
        ip_version = None
        if ipv6_address_mode or ipv6_ra_mode:
            ip_version = constants.IP_VERSION_6
        return self.safe_client.create_subnet(
            project_id, network_id, cidr, enable_dhcp=True,
            ipv6_address_mode=ipv6_address_mode, ipv6_ra_mode=ipv6_ra_mode,
            subnetpool_id=subnetpool_id, ip_version=ip_version)

    def _show_subnet(self, subnet_id):
        return self.client.show_subnet(subnet_id)

    def test_create_subnet_ipv4(self):
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                '240.0.0.0', '240.255.255.255', '24')).network
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     cidr)
        subnet = self._show_subnet(subnet['id'])
        self.assertEqual(subnet['subnet']['gateway_ip'],
                         str(netaddr.IPNetwork(cidr).network + 1))

    def test_create_subnet_ipv6_slaac(self):
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                '2001:db8::', '2001:db8::ffff', '64')).network
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     cidr, ipv6_address_mode='slaac',
                                     ipv6_ra_mode='slaac')
        subnet = self._show_subnet(subnet['id'])
        self.assertEqual(subnet['subnet']['gateway_ip'],
                         str(netaddr.IPNetwork(cidr).network))

    def test_create_subnet_ipv6_prefix_delegation(self):
        subnet = self._create_subnet(self._project_id, self._network['id'],
                                     None, ipv6_address_mode='slaac',
                                     ipv6_ra_mode='slaac',
                                     subnetpool_id='prefix_delegation')
        subnet = self._show_subnet(subnet['id'])
        self.assertIsNone(subnet['subnet']['gateway_ip'])
