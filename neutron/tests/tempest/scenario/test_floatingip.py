# Copyright (c) 2017 Midokura SARL
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
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
import testscenarios
from testscenarios.scenarios import multiply_scenarios

from neutron.tests.tempest.common import ssh
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants


CONF = config.CONF


load_tests = testscenarios.load_tests_apply_scenarios


class FloatingIpTestCasesMixin(object):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(FloatingIpTestCasesMixin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router_by_client()
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.keypair = cls.create_keypair()

        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup-'))['security_group']
        cls.security_groups.append(cls.secgroup)
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])

        if cls.same_network:
            cls._dest_network = cls.network
        else:
            cls._dest_network = cls._create_dest_network()

    @classmethod
    def _create_dest_network(cls):
        network = cls.create_network()
        subnet = cls.create_subnet(network,
            cidr=netaddr.IPNetwork('10.10.0.0/24'))
        cls.create_router_interface(cls.router['id'], subnet['id'])
        return network

    def _create_server(self, create_floating_ip=True, network=None):
        if network is None:
            network = self.network
        port = self.create_port(network, security_groups=[self.secgroup['id']])
        if create_floating_ip:
            fip = self.create_and_associate_floatingip(port['id'])
        else:
            fip = None
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        return {'port': port, 'fip': fip, 'server': server}

    def _test_east_west(self):
        # The proxy VM is used to control the source VM when it doesn't
        # have a floating-ip.
        if self.src_has_fip:
            proxy = None
            proxy_client = None
        else:
            proxy = self._create_server()
            proxy_client = ssh.Client(proxy['fip']['floating_ip_address'],
                                      CONF.validation.image_ssh_user,
                                      pkey=self.keypair['private_key'])

        # Source VM
        if self.src_has_fip:
            src_server = self._create_server()
            src_server_ip = src_server['fip']['floating_ip_address']
        else:
            src_server = self._create_server(create_floating_ip=False)
            src_server_ip = src_server['port']['fixed_ips'][0]['ip_address']
        ssh_client = ssh.Client(src_server_ip,
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'],
                                proxy_client=proxy_client)

        # Destination VM
        if self.dest_has_fip:
            dest_server = self._create_server(network=self._dest_network)
        else:
            dest_server = self._create_server(create_floating_ip=False,
                                              network=self._dest_network)

        # Check connectivity
        self.check_remote_connectivity(ssh_client,
            dest_server['port']['fixed_ips'][0]['ip_address'])
        if self.dest_has_fip:
            self.check_remote_connectivity(ssh_client,
                dest_server['fip']['floating_ip_address'])


class FloatingIpSameNetwork(FloatingIpTestCasesMixin,
                            base.BaseTempestTestCase):
    scenarios = multiply_scenarios([
        ('SRC with FIP', dict(src_has_fip=True)),
        ('SRC without FIP', dict(src_has_fip=False)),
    ], [
        ('DEST with FIP', dict(dest_has_fip=True)),
        ('DEST without FIP', dict(dest_has_fip=False)),
    ])

    same_network = True

    @decorators.idempotent_id('05c4e3b3-7319-4052-90ad-e8916436c23b')
    def test_east_west(self):
        self._test_east_west()


class FloatingIpSeparateNetwork(FloatingIpTestCasesMixin,
                                base.BaseTempestTestCase):
    scenarios = multiply_scenarios([
        ('SRC with FIP', dict(src_has_fip=True)),
        ('SRC without FIP', dict(src_has_fip=False)),
    ], [
        ('DEST with FIP', dict(dest_has_fip=True)),
        ('DEST without FIP', dict(dest_has_fip=False)),
    ])

    same_network = False

    @decorators.idempotent_id('f18f0090-3289-4783-b956-a0f8ac511e8b')
    def test_east_west(self):
        self._test_east_west()
