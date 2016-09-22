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

from oslo_log import log as logging
from tempest.common import waiters
from tempest import test

from neutron.common import utils
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TrunkTest(base.BaseTempestTestCase):
    credentials = ['primary']
    force_tenant_isolation = False

    @classmethod
    @test.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(TrunkTest, cls).resource_setup()
        # setup basic topology for servers we can log into
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.create_router_and_interface(cls.subnet['id'])
        cls.keypair = cls.create_keypair()
        cls.create_loginable_secgroup_rule()

    def _create_server_with_trunk_port(self):
        port = self.create_port(self.network)
        trunk = self.client.create_trunk(port['id'], subports=[])['trunk']
        fip = self.create_and_associate_floatingip(port['id'])
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])['server']
        self.addCleanup(self._detach_and_delete_trunk, server, trunk)
        return {'port': port, 'trunk': trunk, 'fip': fip,
                'server': server}

    def _detach_and_delete_trunk(self, server, trunk):
        # we have to detach the interface from the server before
        # the trunk can be deleted.
        self.manager.compute.InterfacesClient().delete_interface(
            server['id'], trunk['port_id'])

        def is_port_detached():
            p = self.client.show_port(trunk['port_id'])['port']
            return p['device_id'] == ''
        utils.wait_until_true(is_port_detached)
        self.client.delete_trunk(trunk['id'])

    def _is_port_down(self, port_id):
        p = self.client.show_port(port_id)['port']
        return p['status'] == 'DOWN'

    def _is_port_active(self, port_id):
        p = self.client.show_port(port_id)['port']
        return p['status'] == 'ACTIVE'

    def _is_trunk_active(self, trunk_id):
        t = self.client.show_trunk(trunk_id)['trunk']
        return t['status'] == 'ACTIVE'

    @test.idempotent_id('bb13fe28-f152-4000-8131-37890a40c79e')
    def test_trunk_subport_lifecycle(self):
        """Test trunk creation and subport transition to ACTIVE status.

        This is a basic test for the trunk extension to ensure that we
        can create a trunk, attach it to a server, add/remove subports,
        while ensuring the status transitions as appropriate.

        This test does not assert any dataplane behavior for the subports.
        It's just a high-level check to ensure the agents claim to have
        wired the port correctly and that the trunk port itself maintains
        connectivity.
        """
        server1 = self._create_server_with_trunk_port()
        server2 = self._create_server_with_trunk_port()
        for server in (server1, server2):
            waiters.wait_for_server_status(self.manager.servers_client,
                                           server['server']['id'],
                                           constants.SERVER_STATUS_ACTIVE)
            self.check_connectivity(server['fip']['floating_ip_address'],
                                    CONF.validation.image_ssh_user,
                                    self.keypair['private_key'])
        trunk1_id, trunk2_id = server1['trunk']['id'], server2['trunk']['id']
        # trunks should transition to ACTIVE without any subports
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # create a few more networks and ports for subports
        subports = [{'port_id': self.create_port(self.create_network())['id'],
                     'segmentation_type': 'vlan', 'segmentation_id': seg_id}
                    for seg_id in range(3, 7)]
        # add all subports to server1
        self.client.add_subports(trunk1_id, subports)
        # ensure trunk transitions to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        # ensure all underlying subports transitioned to ACTIVE
        for s in subports:
            utils.wait_until_true(lambda: self._is_port_active(s['port_id']))
        # ensure main dataplane wasn't interrupted
        self.check_connectivity(server1['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        # move subports over to other server
        self.client.remove_subports(trunk1_id, subports)
        # ensure all subports go down
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_down(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to DOWN." % s['port_id']))
        self.client.add_subports(trunk2_id, subports)
        # wait for both trunks to go back to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # ensure subports come up on other trunk
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_active(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to ACTIVE." % s['port_id']))
        # final connectivity check
        self.check_connectivity(server1['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        self.check_connectivity(server2['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
