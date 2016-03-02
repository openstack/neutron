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

from oslo_config import cfg
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from neutron.tests.api import base


class ExternalNetworksTestJSON(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(ExternalNetworksTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_client.delete_network, network['id'])
        return network

    @test.idempotent_id('462be770-b310-4df9-9c42-773217e4c8b1')
    def test_create_external_network(self):
        # Create a network as an admin user specifying the
        # external network extension attribute
        ext_network = self._create_network()
        # Verifies router:external parameter
        self.assertIsNotNone(ext_network['id'])
        self.assertTrue(ext_network['router:external'])

    @test.idempotent_id('4db5417a-e11c-474d-a361-af00ebef57c5')
    def test_update_external_network(self):
        # Update a network as an admin user specifying the
        # external network extension attribute
        network = self._create_network(external=False)
        self.assertFalse(network.get('router:external', False))
        update_body = {'router:external': True}
        body = self.admin_client.update_network(network['id'],
                                                **update_body)
        updated_network = body['network']
        # Verify that router:external parameter was updated
        self.assertTrue(updated_network['router:external'])

    @test.idempotent_id('39be4c9b-a57e-4ff9-b7c7-b218e209dfcc')
    def test_list_external_networks(self):
        # Create external_net
        external_network = self._create_network()
        # List networks as a normal user and confirm the external
        # network extension attribute is returned for those networks
        # that were created as external
        body = self.client.list_networks()
        networks_list = [net['id'] for net in body['networks']]
        self.assertIn(external_network['id'], networks_list)
        self.assertIn(self.network['id'], networks_list)
        for net in body['networks']:
            if net['id'] == self.network['id']:
                self.assertFalse(net['router:external'])
            elif net['id'] == external_network['id']:
                self.assertTrue(net['router:external'])

    @test.idempotent_id('2ac50ab2-7ebd-4e27-b3ce-a9e399faaea2')
    def test_show_external_networks_attribute(self):
        # Create external_net
        external_network = self._create_network()
        # Show an external network as a normal user and confirm the
        # external network extension attribute is returned.
        body = self.client.show_network(external_network['id'])
        show_ext_net = body['network']
        self.assertEqual(external_network['name'], show_ext_net['name'])
        self.assertEqual(external_network['id'], show_ext_net['id'])
        self.assertTrue(show_ext_net['router:external'])
        body = self.client.show_network(self.network['id'])
        show_net = body['network']
        # Verify with show that router:external is False for network
        self.assertEqual(self.network['name'], show_net['name'])
        self.assertEqual(self.network['id'], show_net['id'])
        self.assertFalse(show_net['router:external'])

    @test.idempotent_id('82068503-2cf2-4ed4-b3be-ecb89432e4bb')
    def test_delete_external_networks_with_floating_ip(self):
        """Verifies external network can be deleted while still holding
        (unassociated) floating IPs

        """
        # Set cls.client to admin to use base.create_subnet()
        client = self.admin_client
        body = client.create_network(**{'router:external': True})
        external_network = body['network']
        self.addCleanup(self._try_delete_resource,
                        client.delete_network,
                        external_network['id'])
        subnet = self.create_subnet(external_network, client=client,
                                    enable_dhcp=False)
        body = client.create_floatingip(
            floating_network_id=external_network['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self._try_delete_resource,
                        client.delete_floatingip,
                        created_floating_ip['id'])
        floatingip_list = client.list_floatingips(
            network=external_network['id'])
        self.assertIn(created_floating_ip['id'],
                      (f['id'] for f in floatingip_list['floatingips']))
        client.delete_network(external_network['id'])
        # Verifies floating ip is deleted
        floatingip_list = client.list_floatingips()
        self.assertNotIn(created_floating_ip['id'],
                         (f['id'] for f in floatingip_list['floatingips']))
        # Verifies subnet is deleted
        subnet_list = client.list_subnets()
        self.assertNotIn(subnet['id'],
                         (s['id'] for s in subnet_list))
        # Removes subnet from the cleanup list
        self.subnets.remove(subnet)


class ExternalNetworksRBACTestJSON(base.BaseAdminNetworkTest):

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def resource_setup(cls):
        if not test.is_extension_enabled('rbac_policies', 'network'):
            msg = "rbac extension not enabled."
            raise cls.skipException(msg)
        super(ExternalNetworksRBACTestJSON, cls).resource_setup()
        cls.client2 = cls.alt_manager.network_client

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_client.delete_network, network['id'])
        return network

    @test.attr(type='smoke')
    @test.idempotent_id('afd8f1b7-a81e-4629-bca8-a367b3a144bb')
    def test_regular_client_shares_with_another(self):
        net = self.create_network()
        self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant=self.client2.tenant_id)
        body = self.client2.list_networks()
        networks_list = [n['id'] for n in body['networks']]
        self.assertIn(net['id'], networks_list)
        r = self.client2.create_router(
            data_utils.rand_name('router-'),
            external_gateway_info={'network_id': net['id']})['router']
        self.addCleanup(self.admin_client.delete_router, r['id'])

    @test.idempotent_id('afd8f1b7-a81e-4629-bca8-a367b3a144bb')
    def test_regular_client_blocked_from_creating_external_wild_policies(self):
        net = self.create_network()
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.client.create_rbac_policy(
                object_type='network', object_id=net['id'],
                action='access_as_external',
                target_tenant='*')

    @test.attr(type='smoke')
    @test.idempotent_id('a2e19f06-48a9-4e4c-b717-08cb2008707d')
    def test_wildcard_policy_created_from_external_network_api(self):
        # create external makes wildcard
        net_id = self._create_network(external=True)['id']
        self.assertEqual(1, len(self.admin_client.list_rbac_policies(
            object_id=net_id, action='access_as_external',
            target_tenant='*')['rbac_policies']))
        # update to non-external clears wildcard
        self.admin_client.update_network(net_id, **{'router:external': False})
        self.assertEqual(0, len(self.admin_client.list_rbac_policies(
            object_id=net_id, action='access_as_external',
            target_tenant='*')['rbac_policies']))
        # create non-external has no wildcard
        net_id = self._create_network(external=False)['id']
        self.assertEqual(0, len(self.admin_client.list_rbac_policies(
            object_id=net_id, action='access_as_external',
            target_tenant='*')['rbac_policies']))
        # update to external makes wildcard
        self.admin_client.update_network(net_id, **{'router:external': True})
        self.assertEqual(1, len(self.admin_client.list_rbac_policies(
            object_id=net_id, action='access_as_external',
            target_tenant='*')['rbac_policies']))

    @test.idempotent_id('a5539002-5bdb-48b5-b124-e9eedd5975e6')
    def test_external_conversion_on_policy_create(self):
        net_id = self._create_network(external=False)['id']
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net_id,
            action='access_as_external',
            target_tenant=self.client2.tenant_id)
        body = self.admin_client.show_network(net_id)['network']
        self.assertTrue(body['router:external'])

    @test.idempotent_id('01364c50-bfb6-46c4-b44c-edc4564d61cf')
    def test_policy_allows_tenant_to_allocate_floatingip(self):
        net = self._create_network(external=False)
        # share to the admin client so it gets converted to external but
        # not shared to everyone
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant=self.admin_client.tenant_id)
        self.create_subnet(net, client=self.admin_client, enable_dhcp=False)
        with testtools.ExpectedException(lib_exc.NotFound):
            self.client2.create_floatingip(
                floating_network_id=net['id'])
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant=self.client2.tenant_id)
        self.client2.create_floatingip(
            floating_network_id=net['id'])

    @test.idempotent_id('476be1e0-f72e-47dc-9a14-4435926bbe82')
    def test_policy_allows_tenant_to_attach_ext_gw(self):
        net = self._create_network(external=False)
        self.create_subnet(net, client=self.admin_client, enable_dhcp=False)
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant=self.client2.tenant_id)
        r = self.client2.create_router(
            data_utils.rand_name('router-'),
            external_gateway_info={'network_id': net['id']})['router']
        self.addCleanup(self.admin_client.delete_router, r['id'])

    @test.idempotent_id('d54decee-4203-4ced-91a2-ea42ca63e154')
    def test_delete_policies_while_tenant_attached_to_net(self):
        net = self._create_network(external=False)
        self.create_subnet(net, client=self.admin_client, enable_dhcp=False)
        wildcard = self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant='*')['rbac_policy']
        r = self.client2.create_router(
            data_utils.rand_name('router-'),
            external_gateway_info={'network_id': net['id']})['router']
        # delete should fail because the wildcard is required for the tenant's
        # access
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(wildcard['id'])
        tenant = self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant=self.client2.tenant_id)['rbac_policy']
        # now we can delete the policy because the tenant has its own policy
        # to allow it access
        self.admin_client.delete_rbac_policy(wildcard['id'])
        # but now we can't delete the tenant's policy without the wildcard
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(tenant['id'])
        wildcard = self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_external',
            target_tenant='*')['rbac_policy']
        # with the wildcard added back we can delete the tenant's policy
        self.admin_client.delete_rbac_policy(tenant['id'])
        self.admin_client.delete_router(r['id'])
        # now without the tenant attached, the wildcard can be deleted
        self.admin_client.delete_rbac_policy(wildcard['id'])
        # finally we ensure that the tenant can't attach to the network since
        # there are no policies allowing it
        with testtools.ExpectedException(lib_exc.NotFound):
            self.client2.create_router(
                data_utils.rand_name('router-'),
                external_gateway_info={'network_id': net['id']})

    @test.idempotent_id('7041cec7-d8fe-4c78-9b04-b51b2fd49dc9')
    def test_wildcard_policy_delete_blocked_on_default_ext(self):
        public_net_id = cfg.CONF.network.public_network_id
        # ensure it is default before so we don't wipe out the policy
        self.admin_client.update_network(public_net_id, is_default=True)
        policy = self.admin_client.list_rbac_policies(
            object_id=public_net_id, action='access_as_external',
            target_tenant='*')['rbac_policies'][0]
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(policy['id'])
