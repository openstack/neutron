# Copyright 2016 OpenStack Foundation
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

import netaddr

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config

from neutron_lib import constants as lib_constants

# 3 IP addresses are taken from every total for IPv4 these are reserved
DEFAULT_IP4_RESERVED = 3
# 2 IP addresses are taken from every total for IPv6 these are reserved
# I assume the reason for having one less than IPv4 is it does not have
# broadcast address
DEFAULT_IP6_RESERVED = 2

DELETE_TIMEOUT = 10
DELETE_SLEEP = 2


class NetworksIpAvailabilityTest(base.BaseAdminNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        test total and used ips for net create
        test total and ips for net after subnet create
        test total and used ips for net after subnet and port create

    """

    @classmethod
    @utils.requires_ext(extension="network-ip-availability", service="network")
    def skip_checks(cls):
        super(NetworksIpAvailabilityTest, cls).skip_checks()

    def _get_used_ips(self, network, net_availability):
        if network:
            for availability in net_availability['network_ip_availabilities']:
                if availability['network_id'] == network['id']:
                    return availability['used_ips']

    def _cleanUp_port(self, port_id):
        # delete port, any way to avoid race
        try:
            self.client.delete_port(port_id)
        # if port is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _assert_total_and_used_ips(self, expected_used, expected_total,
                                   network, net_availability):
        if network:
            for availability in net_availability['network_ip_availabilities']:
                if availability['network_id'] == network['id']:
                    self.assertEqual(expected_total, availability['total_ips'])
                    self.assertEqual(expected_used, availability['used_ips'])

    def _create_subnet(self, network, ip_version):
        if ip_version == lib_constants.IP_VERSION_4:
            cidr = netaddr.IPNetwork('20.0.0.0/24')
            mask_bits = config.safe_get_config_value(
                'network', 'project_network_mask_bits')
        elif ip_version == lib_constants.IP_VERSION_6:
            cidr = netaddr.IPNetwork('20:db8::/64')
            mask_bits = config.safe_get_config_value(
                'network', 'project_network_v6_mask_bits')

        subnet_cidr = next(cidr.subnet(mask_bits))
        prefix_len = subnet_cidr.prefixlen
        subnet = self.create_subnet(network,
                                    cidr=subnet_cidr,
                                    enable_dhcp=False,
                                    mask_bits=mask_bits,
                                    ip_version=ip_version)
        return subnet, prefix_len


def calc_total_ips(prefix, ip_version):
    # will calculate total ips after removing reserved.
    if ip_version == lib_constants.IP_VERSION_4:
        total_ips = 2 ** (lib_constants.IPv4_BITS
                          - prefix) - DEFAULT_IP4_RESERVED
    elif ip_version == lib_constants.IP_VERSION_6:
        total_ips = 2 ** (lib_constants.IPv6_BITS
                          - prefix) - DEFAULT_IP6_RESERVED
    return total_ips


class NetworksIpAvailabilityIPv4Test(NetworksIpAvailabilityTest):

    @decorators.idempotent_id('0f33cc8c-1bf6-47d1-9ce1-010618240599')
    def test_admin_network_availability_before_subnet(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.addCleanup(self.client.delete_network, network['id'])
        net_availability = self.admin_client.list_network_ip_availabilities()
        self._assert_total_and_used_ips(0, 0, network, net_availability)

    @decorators.idempotent_id('3aecd3b2-16ed-4b87-a54a-91d7b3c2986b')
    def test_net_ip_availability_after_subnet_and_ports(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.addCleanup(self.client.delete_network, network['id'])
        subnet, prefix = self._create_subnet(network, self._ip_version)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        body = self.admin_client.list_network_ip_availabilities()
        used_ip = self._get_used_ips(network, body)
        port1 = self.client.create_port(network_id=network['id'])
        self.addCleanup(self.client.delete_port, port1['port']['id'])
        port2 = self.client.create_port(network_id=network['id'])
        self.addCleanup(self.client.delete_port, port2['port']['id'])
        net_availability = self.admin_client.list_network_ip_availabilities()
        self._assert_total_and_used_ips(
            used_ip + 2,
            calc_total_ips(prefix, self._ip_version),
            network, net_availability)

    @decorators.idempotent_id('9f11254d-757b-492e-b14b-f52144e4ee7b')
    def test_net_ip_availability_after_port_delete(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.addCleanup(self.client.delete_network, network['id'])
        subnet, prefix = self._create_subnet(network, self._ip_version)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        port = self.client.create_port(network_id=network['id'])
        self.addCleanup(self._cleanUp_port, port['port']['id'])
        net_availability = self.admin_client.list_network_ip_availabilities()
        used_ip = self._get_used_ips(network, net_availability)
        self.client.delete_port(port['port']['id'])

        def get_net_availability():
            availabilities = self.admin_client.list_network_ip_availabilities()
            used_ip_after_port_delete = self._get_used_ips(network,
                                                           availabilities)
            return used_ip - 1 == used_ip_after_port_delete

        self.assertTrue(
            test_utils.call_until_true(
                get_net_availability, DELETE_TIMEOUT, DELETE_SLEEP),
            msg="IP address did not become available after port delete")


class NetworksIpAvailabilityIPv6Test(NetworksIpAvailabilityIPv4Test):

    _ip_version = lib_constants.IP_VERSION_6
