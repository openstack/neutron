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
from tempest import test

from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron_lib import constants

CONF = config.CONF


class NetworkDvrTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    @classmethod
    @test.requires_ext(extension="dvr", service="network")
    def skip_checks(cls):
        super(NetworkDvrTest, cls).skip_checks()

    def _check_connectivity(self):
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

    def _check_snat_port_connectivity(self):
        self._check_connectivity()

        # Put the Router_SNAT port down to make sure the traffic flows through
        # Compute node.
        self._put_snat_port_down(self.network['id'])
        self._check_connectivity()

    def _put_snat_port_down(self, network_id):
        port_id = self.client.list_ports(
            network_id=network_id,
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT)['ports'][0]['id']
        self.admin_manager.network_client.update_port(
            port_id, admin_state_up=False)

    @test.idempotent_id('3d73ec1a-2ec6-45a9-b0f8-04a283d9d344')
    def test_vm_reachable_through_compute(self):
        """Check that the VM is reachable through compute node.

        The test is done by putting the SNAT port down on controller node.
        """
        router = self.create_router_by_client(
            distributed=True, tenant_id=self.client.tenant_id, is_admin=True)
        self.setup_network_and_server(router=router)
        self._check_snat_port_connectivity()

    @test.idempotent_id('23724222-483a-4129-bc15-7a9278f3828b')
    def test_update_centralized_router_to_dvr(self):
        """Check that updating centralized router to be distributed works.
        """
        # Created a centralized router on a DVR setup
        router = self.create_router_by_client(
            distributed=False, tenant_id=self.client.tenant_id, is_admin=True)
        self.setup_network_and_server(router=router)
        self._check_connectivity()

        # Update router to be distributed
        self.admin_manager.network_client.update_router(
            router_id=router['id'], admin_state_up=False)
        self.admin_manager.network_client.update_router(
            router_id=router['id'], distributed=True)
        self.admin_manager.network_client.update_router(
            router_id=router['id'], admin_state_up=True)
        self._check_snat_port_connectivity()
