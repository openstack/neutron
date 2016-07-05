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
from tempest.common import waiters
from tempest import test

from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants

CONF = config.CONF


class NetworkBasicTest(base.BaseTempestTestCase):
    credentials = ['primary']
    force_tenant_isolation = False

    # Default to ipv4.
    _ip_version = 4

    @test.idempotent_id('de07fe0a-e955-449e-b48b-8641c14cd52e')
    def test_basic_instance(self):
        network = self.create_network()
        subnet = self.create_subnet(network)

        self.create_router_and_interface(subnet['id'])
        keypair = self.create_keypair()
        self.create_loginable_secgroup_rule()
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=keypair['name'],
            networks=[{'uuid': network['id']}])
        waiters.wait_for_server_status(self.manager.servers_client,
                                       server['server']['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        port = self.client.list_ports(network_id=network['id'],
                                      device_id=server[
                                          'server']['id'])['ports'][0]
        fip = self.create_and_associate_floatingip(port['id'])
        self.check_connectivity(fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                keypair['private_key'])
