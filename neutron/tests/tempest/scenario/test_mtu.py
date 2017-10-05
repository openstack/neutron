# Copyright 2016 Red Hat, Inc.
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
from tempest.lib import decorators

from neutron.tests.tempest.common import ssh
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants
from neutron_lib.api.definitions import provider_net

CONF = config.CONF


class NetworkMtuBaseTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    servers = []
    networks = []

    @classmethod
    def skip_checks(cls):
        super(NetworkMtuBaseTest, cls).skip_checks()
        if ("vxlan" not in
                config.CONF.neutron_plugin_options.available_type_drivers
            or "gre" not in
                config.CONF.neutron_plugin_options.available_type_drivers):
            raise cls.skipException("GRE or VXLAN type_driver is not enabled")

    @classmethod
    @utils.requires_ext(extension=provider_net.ALIAS, service="network")
    def resource_setup(cls):
        super(NetworkMtuBaseTest, cls).resource_setup()
        # setup basic topology for servers we can log into it
        cls.router = cls.create_router_by_client()
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name='secgroup_mtu')
        cls.security_groups.append(cls.secgroup['security_group'])
        cls.create_loginable_secgroup_rule(
            secgroup_id=cls.secgroup['security_group']['id'])
        cls.create_pingable_secgroup_rule(
            secgroup_id=cls.secgroup['security_group']['id'])

    def _create_setup(self):
        self.admin_client = self.os_admin.network_client
        net_kwargs = {'tenant_id': self.client.tenant_id}
        for sub, net_type in (
                ('10.100.0.0/16', 'vxlan'), ('10.200.0.0/16', 'gre')):
            net_kwargs['name'] = '-'.join([net_type, 'net'])
            net_kwargs['provider:network_type'] = net_type
            network = self.admin_client.create_network(**net_kwargs)[
                'network']
            self.networks.append(network)
            self.addCleanup(self.admin_client.delete_network, network['id'])
            cidr = netaddr.IPNetwork(sub)
            subnet = self.create_subnet(network, cidr=cidr)
            self.create_router_interface(self.router['id'], subnet['id'])
            self.addCleanup(self.client.remove_router_interface_with_subnet_id,
                            self.router['id'], subnet['id'])
        # check that MTUs are different for 2 networks
        self.assertNotEqual(self.networks[0]['mtu'], self.networks[1]['mtu'])
        self.networks.sort(key=lambda net: net['mtu'])
        server1, fip1 = self.create_pingable_vm(self.networks[0])
        server_ssh_client1 = ssh.Client(
            self.floating_ips[0]['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        server2, fip2 = self.create_pingable_vm(self.networks[1])
        server_ssh_client2 = ssh.Client(
            self.floating_ips[0]['floating_ip_address'],
            CONF.validation.image_ssh_user,
            pkey=self.keypair['private_key'])
        for fip in (fip1, fip2):
            self.check_connectivity(fip['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
        return server_ssh_client1, fip1, server_ssh_client2, fip2

    def create_pingable_vm(self, net):
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': net['id']}],
            security_groups=[{'name': self.secgroup[
                'security_group']['name']}])
        waiters.wait_for_server_status(
            self.os_primary.servers_client, server['server']['id'],
            constants.SERVER_STATUS_ACTIVE)
        port = self.client.list_ports(
            network_id=net['id'], device_id=server['server']['id'])['ports'][0]
        fip = self.create_and_associate_floatingip(port['id'])
        return server, fip

    @decorators.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a273d9d344')
    def test_connectivity_min_max_mtu(self):
        server_ssh_client, _, _, fip2 = self._create_setup()
        # ping with min mtu of 2 networks succeeds even when
        # fragmentation is disabled
        self.check_remote_connectivity(
            server_ssh_client, fip2['fixed_ip_address'],
            mtu=self.networks[0]['mtu'], fragmentation=False)

        # ping with the size above min mtu of 2 networks
        # fails when fragmentation is disabled
        self.check_remote_connectivity(
            server_ssh_client, fip2['fixed_ip_address'], should_succeed=False,
            mtu=self.networks[0]['mtu'] + 1, fragmentation=False)

        # ping with max mtu of 2 networks succeeds when
        # fragmentation is enabled
        self.check_remote_connectivity(
            server_ssh_client, fip2['fixed_ip_address'],
            mtu=self.networks[1]['mtu'])

        # ping with max mtu of 2 networks fails when fragmentation is disabled
        self.check_remote_connectivity(
            server_ssh_client, fip2['fixed_ip_address'], should_succeed=False,
            mtu=self.networks[1]['mtu'], fragmentation=False)
