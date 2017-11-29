# Copyright 2017 Red Hat, Inc.
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
from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron.tests.tempest.common import ssh
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants as const

CONF = config.CONF


class FloatingIpTestCasesAdmin(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(FloatingIpTestCasesAdmin, cls).resource_setup()
        cls.network = cls.create_network()
        cls.create_subnet(cls.network)
        router = cls.create_router_by_client()
        cls.create_router_interface(router['id'], cls.subnets[0]['id'])
        # Create keypair with admin privileges
        cls.keypair = cls.create_keypair(client=cls.os_admin.keypairs_client)
        # Create security group with admin privileges
        cls.secgroup = cls.os_admin.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))['security_group']
        # Execute funcs to achieve ssh and ICMP capabilities
        funcs = [cls.create_loginable_secgroup_rule,
                 cls.create_pingable_secgroup_rule]
        for func in funcs:
            func(secgroup_id=cls.secgroup['id'],
                 client=cls.os_admin.network_client)

    @classmethod
    def resource_cleanup(cls):
        # Cleanup for security group
        cls.os_admin.network_client.delete_security_group(
            security_group_id=cls.secgroup['id'])
        super(FloatingIpTestCasesAdmin, cls).resource_cleanup()

    def _list_hypervisors(self):
        # List of hypervisors
        return self.os_admin.hv_client.list_hypervisors()['hypervisors']

    def _list_availability_zones(self):
        # List of availability zones
        func = self.os_admin.az_client.list_availability_zones
        return func()['availabilityZoneInfo']

    def _create_vms(self, hyper, avail_zone, num_servers=2):
        servers, fips, server_ssh_clients = ([], [], [])
        # Create the availability zone with default zone and
        # a specific mentioned hypervisor.
        az = avail_zone + ':' + hyper
        for i in range(num_servers):
            servers.append(self.create_server(
                flavor_ref=CONF.compute.flavor_ref,
                image_ref=CONF.compute.image_ref,
                key_name=self.keypair['name'],
                networks=[{'uuid': self.network['id']}],
                security_groups=[{'name': self.secgroup['name']}],
                availability_zone=az))
        for i, server in enumerate(servers):
            waiters.wait_for_server_status(
                self.os_admin.servers_client, server['server']['id'],
                const.SERVER_STATUS_ACTIVE)
            port = self.client.list_ports(
                network_id=self.network['id'],
                device_id=server['server']['id']
            )['ports'][0]
            fips.append(self.create_and_associate_floatingip(
                port['id'], client=self.os_admin.network_client))
            server_ssh_clients.append(ssh.Client(
                fips[i]['floating_ip_address'], CONF.validation.image_ssh_user,
                pkey=self.keypair['private_key']))
            self.addCleanup(self.os_admin.network_client.delete_floatingip,
                            fips[i]['id'])
        return server_ssh_clients, fips

    @decorators.idempotent_id('6bba729b-3fb6-494b-9e1e-82bbd89a1045')
    def test_two_vms_fips(self):
        """This test verifies the ability of two instances
        that were created in the same compute node and same availability zone
        to reach each other.
        """
        # Get hypervisor list to pass it for vm creation
        hyper = self._list_hypervisors()[0]['hypervisor_hostname']
        # Get availability zone list to pass it for vm creation
        avail_zone = self._list_availability_zones()[0]['zoneName']
        server_ssh_clients, fips = self._create_vms(hyper, avail_zone)
        self.check_remote_connectivity(
            server_ssh_clients[0], fips[1]['floating_ip_address'])
