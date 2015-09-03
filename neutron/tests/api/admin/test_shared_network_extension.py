# Copyright 2015 Hewlett-Packard Development Company, L.P.dsvsv
# Copyright 2015 OpenStack Foundation
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

from tempest_lib import exceptions as lib_exc
import testtools

from neutron.tests.api import base
from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import test
from tempest_lib.common.utils import data_utils

CONF = config.CONF


class SharedNetworksTest(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(SharedNetworksTest, cls).resource_setup()
        cls.shared_network = cls.create_shared_network()

    @test.idempotent_id('6661d219-b96d-4597-ad10-55766123421a')
    def test_filtering_shared_networks(self):
        # this test is necessary because the 'shared' column does not actually
        # exist on networks so the filter function has to translate it into
        # queries against the RBAC table
        self.create_network()
        self._check_shared_correct(
            self.client.list_networks(shared=True)['networks'], True)
        self._check_shared_correct(
            self.admin_client.list_networks(shared=True)['networks'], True)
        self._check_shared_correct(
            self.client.list_networks(shared=False)['networks'], False)
        self._check_shared_correct(
            self.admin_client.list_networks(shared=False)['networks'], False)

    def _check_shared_correct(self, items, shared):
        self.assertNotEmpty(items)
        self.assertTrue(all(n['shared'] == shared for n in items))

    @test.idempotent_id('6661d219-b96d-4597-ad10-51672353421a')
    def test_filtering_shared_subnets(self):
        # shared subnets need to be tested because their shared status isn't
        # visible as a regular API attribute and it's solely dependent on the
        # parent network
        reg = self.create_network()
        priv = self.create_subnet(reg, client=self.client)
        shared = self.create_subnet(self.shared_network,
                                    client=self.admin_client)
        self.assertIn(shared, self.client.list_subnets(shared=True)['subnets'])
        self.assertIn(shared,
            self.admin_client.list_subnets(shared=True)['subnets'])
        self.assertNotIn(priv,
            self.client.list_subnets(shared=True)['subnets'])
        self.assertNotIn(priv,
            self.admin_client.list_subnets(shared=True)['subnets'])
        self.assertIn(priv, self.client.list_subnets(shared=False)['subnets'])
        self.assertIn(priv,
            self.admin_client.list_subnets(shared=False)['subnets'])
        self.assertNotIn(shared,
            self.client.list_subnets(shared=False)['subnets'])
        self.assertNotIn(shared,
            self.admin_client.list_subnets(shared=False)['subnets'])

    @test.idempotent_id('6661d219-b96d-4597-ad10-55766ce4abf7')
    def test_create_update_shared_network(self):
        shared_network = self.create_shared_network()
        net_id = shared_network['id']
        self.assertEqual('ACTIVE', shared_network['status'])
        self.assertIsNotNone(shared_network['id'])
        self.assertTrue(self.shared_network['shared'])
        new_name = "New_shared_network"
        body = self.admin_client.update_network(net_id, name=new_name,
                                                admin_state_up=False,
                                                shared=False)
        updated_net = body['network']
        self.assertEqual(new_name, updated_net['name'])
        self.assertFalse(updated_net['shared'])
        self.assertFalse(updated_net['admin_state_up'])

    @test.idempotent_id('9c31fabb-0181-464f-9ace-95144fe9ca77')
    def test_create_port_shared_network_as_non_admin_tenant(self):
        # create a port as non admin
        body = self.client.create_port(network_id=self.shared_network['id'])
        port = body['port']
        self.addCleanup(self.admin_client.delete_port, port['id'])
        # verify the tenant id of admin network and non admin port
        self.assertNotEqual(self.shared_network['tenant_id'],
                            port['tenant_id'])

    @test.idempotent_id('3e39c4a6-9caf-4710-88f1-d20073c6dd76')
    def test_create_bulk_shared_network(self):
        # Creates 2 networks in one request
        net_nm = [data_utils.rand_name('network'),
                  data_utils.rand_name('network')]
        body = self.admin_client.create_bulk_network(net_nm, shared=True)
        created_networks = body['networks']
        for net in created_networks:
            self.addCleanup(self.admin_client.delete_network, net['id'])
            self.assertIsNotNone(net['id'])
            self.assertTrue(net['shared'])

    def _list_shared_networks(self, user):
        body = user.list_networks(shared=True)
        networks_list = [net['id'] for net in body['networks']]
        self.assertIn(self.shared_network['id'], networks_list)
        self.assertTrue(self.shared_network['shared'])

    @test.idempotent_id('a064a9fd-e02f-474a-8159-f828cd636a28')
    def test_list_shared_networks(self):
        # List the shared networks and confirm that
        # shared network extension attribute is returned for those networks
        # that are created as shared
        self._list_shared_networks(self.admin_client)
        self._list_shared_networks(self.client)

    def _show_shared_network(self, user):
        body = user.show_network(self.shared_network['id'])
        show_shared_net = body['network']
        self.assertEqual(self.shared_network['name'], show_shared_net['name'])
        self.assertEqual(self.shared_network['id'], show_shared_net['id'])
        self.assertTrue(show_shared_net['shared'])

    @test.idempotent_id('e03c92a2-638d-4bfa-b50a-b1f66f087e58')
    def test_show_shared_networks_attribute(self):
        # Show a shared network and confirm that
        # shared network extension attribute is returned.
        self._show_shared_network(self.admin_client)
        self._show_shared_network(self.client)


class AllowedAddressPairSharedNetworkTest(base.BaseAdminNetworkTest):
    allowed_address_pairs = [{'ip_address': '1.1.1.1'}]

    @classmethod
    def skip_checks(cls):
        super(AllowedAddressPairSharedNetworkTest, cls).skip_checks()
        if not test.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairSharedNetworkTest, cls).resource_setup()
        cls.network = cls.create_shared_network()
        cls.create_subnet(cls.network, client=cls.admin_client)

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-ffffffff1fff')
    def test_create_with_address_pair_blocked_on_other_network(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_port(self.network,
                             allowed_address_pairs=self.allowed_address_pairs)

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-ffffffff2fff')
    def test_update_with_address_pair_blocked_on_other_network(self):
        port = self.create_port(self.network)
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.update_port(
                port, allowed_address_pairs=self.allowed_address_pairs)


class RBACSharedNetworksTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True

    @classmethod
    def resource_setup(cls):
        super(RBACSharedNetworksTest, cls).resource_setup()
        extensions = cls.admin_client.list_extensions()
        if not test.is_extension_enabled('rbac_policies', 'network'):
            msg = "rbac extension not enabled."
            raise cls.skipException(msg)
        # NOTE(kevinbenton): the following test seems to be necessary
        # since the default is 'all' for the above check and these tests
        # need to get into the gate and be disabled until the service plugin
        # is enabled in devstack. Is there a better way to do this?
        if 'rbac-policies' not in [x['alias']
                                   for x in extensions['extensions']]:
            msg = "rbac extension is not in extension listing."
            raise cls.skipException(msg)
        creds = cls.isolated_creds.get_alt_creds()
        cls.client2 = clients.Manager(credentials=creds).network_client

    def _make_admin_net_and_subnet_shared_to_tenant_id(self, tenant_id):
        net = self.admin_client.create_network(
            name=data_utils.rand_name('test-network-'))['network']
        self.addCleanup(self.admin_client.delete_network, net['id'])
        subnet = self.create_subnet(net, client=self.admin_client)
        # network is shared to first unprivileged client by default
        pol = self.admin_client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=tenant_id
        )['rbac_policy']
        return {'network': net, 'subnet': subnet, 'policy': pol}

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff1fff')
    def test_network_only_visible_to_policy_target(self):
        net = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['network']
        self.client.show_network(net['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            # client2 has not been granted access
            self.client2.show_network(net['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff2fff')
    def test_subnet_on_network_only_visible_to_policy_target(self):
        sub = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['subnet']
        self.client.show_subnet(sub['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            # client2 has not been granted access
            self.client2.show_subnet(sub['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff2eee')
    def test_policy_target_update(self):
        res = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        # change to client2
        update_res = self.admin_client.update_rbac_policy(
                res['policy']['id'], target_tenant=self.client2.tenant_id)
        self.assertEqual(self.client2.tenant_id,
                         update_res['rbac_policy']['target_tenant'])
        # make sure everything else stayed the same
        res['policy'].pop('target_tenant')
        update_res['rbac_policy'].pop('target_tenant')
        self.assertEqual(res['policy'], update_res['rbac_policy'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff3fff')
    def test_port_presence_prevents_network_rbac_policy_deletion(self):
        res = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        port = self.client.create_port(network_id=res['network']['id'])['port']
        # a port on the network should prevent the deletion of a policy
        # required for it to exist
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(res['policy']['id'])

        # a wildcard policy should allow the specific policy to be deleted
        # since it allows the remaining port
        wild = self.admin_client.create_rbac_policy(
            object_type='network', object_id=res['network']['id'],
            action='access_as_shared', target_tenant='*')['rbac_policy']
        self.admin_client.delete_rbac_policy(res['policy']['id'])

        # now that wilcard is the only remainin, it should be subjected to
        # to the same restriction
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(wild['id'])
        # similarily, we can't update the policy to a different tenant
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.update_rbac_policy(
                wild['id'], target_tenant=self.client2.tenant_id)

        self.client.delete_port(port['id'])
        # anchor is gone, delete should pass
        self.admin_client.delete_rbac_policy(wild['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-beefbeefbeef')
    def test_tenant_can_delete_port_on_own_network(self):
        # TODO(kevinbenton): make adjustments to the db lookup to
        # make this work.
        msg = "Non-admin cannot currently delete other's ports."
        raise self.skipException(msg)
        # pylint: disable=unreachable
        net = self.create_network()  # owned by self.client
        self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        port = self.client2.create_port(network_id=net['id'])['port']
        self.client.delete_port(port['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff4fff')
    def test_regular_client_shares_to_another_regular_client(self):
        net = self.create_network()  # owned by self.client
        with testtools.ExpectedException(lib_exc.NotFound):
            self.client2.show_network(net['id'])
        pol = self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        self.client2.show_network(net['id'])

        self.assertIn(pol['rbac_policy'],
                      self.client.list_rbac_policies()['rbac_policies'])
        # ensure that 'client2' can't see the policy sharing the network to it
        # because the policy belongs to 'client'
        self.assertNotIn(pol['rbac_policy']['id'],
            [p['id']
             for p in self.client2.list_rbac_policies()['rbac_policies']])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff5fff')
    def test_policy_show(self):
        res = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        p1 = res['policy']
        p2 = self.admin_client.create_rbac_policy(
            object_type='network', object_id=res['network']['id'],
            action='access_as_shared',
            target_tenant='*')['rbac_policy']

        self.assertEqual(
            p1, self.admin_client.show_rbac_policy(p1['id'])['rbac_policy'])
        self.assertEqual(
            p2, self.admin_client.show_rbac_policy(p2['id'])['rbac_policy'])

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff6fff')
    def test_regular_client_blocked_from_sharing_anothers_network(self):
        net = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['network']
        with testtools.ExpectedException(lib_exc.BadRequest):
            self.client.create_rbac_policy(
                object_type='network', object_id=net['id'],
                action='access_as_shared', target_tenant=self.client.tenant_id)

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-afffffff7fff')
    def test_regular_client_blocked_from_sharing_with_wildcard(self):
        net = self.create_network()
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.client.create_rbac_policy(
                object_type='network', object_id=net['id'],
                action='access_as_shared', target_tenant='*')
        # ensure it works on update as well
        pol = self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.client.update_rbac_policy(pol['rbac_policy']['id'],
                                           target_tenant='*')
