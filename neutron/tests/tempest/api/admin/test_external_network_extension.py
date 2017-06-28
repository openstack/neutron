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
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron.tests.tempest.api import base


class ExternalNetworksRBACTestJSON(base.BaseAdminNetworkTest):

    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['rbac-policies']

    @classmethod
    def resource_setup(cls):
        super(ExternalNetworksRBACTestJSON, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_client.delete_network, network['id'])
        return network

    @decorators.idempotent_id('afd8f1b7-a81e-4629-bca8-a367b3a144bb')
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

    @decorators.idempotent_id('eff9443a-2d04-48ee-840e-d955ac564bcd')
    def test_regular_client_blocked_from_creating_external_wild_policies(self):
        net = self.create_network()
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.client.create_rbac_policy(
                object_type='network', object_id=net['id'],
                action='access_as_external',
                target_tenant='*')

    @decorators.idempotent_id('a2e19f06-48a9-4e4c-b717-08cb2008707d')
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

    @decorators.idempotent_id('a5539002-5bdb-48b5-b124-abcd12347865')
    def test_external_update_policy_from_wildcard_to_specific_tenant(self):
        net_id = self._create_network(external=True)['id']
        rbac_pol = self.admin_client.list_rbac_policies(
            object_id=net_id, action='access_as_external',
            target_tenant='*')['rbac_policies'][0]
        r = self.client2.create_router(
            data_utils.rand_name('router-'),
            external_gateway_info={'network_id': net_id})['router']
        self.addCleanup(self.admin_client.delete_router, r['id'])
        # changing wildcard to specific tenant should be okay since its the
        # only one using the network
        self.admin_client.update_rbac_policy(
            rbac_pol['id'], target_tenant=self.client2.tenant_id)

    @decorators.idempotent_id('a5539002-5bdb-48b5-b124-e9eedd5975e6')
    def test_external_conversion_on_policy_create(self):
        net_id = self._create_network(external=False)['id']
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net_id,
            action='access_as_external',
            target_tenant=self.client2.tenant_id)
        body = self.admin_client.show_network(net_id)['network']
        self.assertTrue(body['router:external'])

    @decorators.idempotent_id('01364c50-bfb6-46c4-b44c-edc4564d61cf')
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

    @decorators.idempotent_id('476be1e0-f72e-47dc-9a14-4435926bbe82')
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

    @decorators.idempotent_id('d54decee-4203-4ced-91a2-ea42ca63e154')
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

    @decorators.idempotent_id('7041cec7-d8fe-4c78-9b04-b51b2fd49dc9')
    def test_wildcard_policy_delete_blocked_on_default_ext(self):
        public_net_id = cfg.CONF.network.public_network_id
        # ensure it is default before so we don't wipe out the policy
        self.admin_client.update_network(public_net_id, is_default=True)
        policy = self.admin_client.list_rbac_policies(
            object_id=public_net_id, action='access_as_external',
            target_tenant='*')['rbac_policies'][0]
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(policy['id'])
