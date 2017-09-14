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

from oslo_utils import uuidutils
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron.tests.tempest.api import base


class SharedNetworksTest(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(SharedNetworksTest, cls).resource_setup()
        cls.shared_network = cls.create_shared_network()

    @decorators.idempotent_id('6661d219-b96d-4597-ad10-55766123421a')
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

    def _list_subnets_ids(self, client, shared):
        body = client.list_subnets(shared=shared)
        return [subnet['id'] for subnet in body['subnets']]

    @decorators.idempotent_id('6661d219-b96d-4597-ad10-51672353421a')
    def test_filtering_shared_subnets(self):
        # shared subnets need to be tested because their shared status isn't
        # visible as a regular API attribute and it's solely dependent on the
        # parent network
        reg = self.create_network()
        priv = self.create_subnet(reg, client=self.client)
        shared = self.create_subnet(self.shared_network,
                                    client=self.admin_client)
        self.assertIn(shared['id'],
                      self._list_subnets_ids(self.client, shared=True))
        self.assertIn(shared['id'],
                      self._list_subnets_ids(self.admin_client, shared=True))
        self.assertNotIn(priv['id'],
                         self._list_subnets_ids(self.client, shared=True))
        self.assertNotIn(
            priv['id'],
            self._list_subnets_ids(self.admin_client, shared=True))
        self.assertIn(priv['id'],
                      self._list_subnets_ids(self.client, shared=False))
        self.assertIn(priv['id'],
                      self._list_subnets_ids(self.admin_client, shared=False))
        self.assertNotIn(shared['id'],
                         self._list_subnets_ids(self.client, shared=False))
        self.assertNotIn(
            shared['id'],
            self._list_subnets_ids(self.admin_client, shared=False))

    @decorators.idempotent_id('6661d219-b96d-4597-ad10-55766ce4abf7')
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

    @decorators.idempotent_id('9c31fabb-0181-464f-9ace-95144fe9ca77')
    def test_create_port_shared_network_as_non_admin_tenant(self):
        # create a port as non admin
        body = self.client.create_port(network_id=self.shared_network['id'])
        port = body['port']
        self.addCleanup(self.admin_client.delete_port, port['id'])
        # verify the tenant id of admin network and non admin port
        self.assertNotEqual(self.shared_network['tenant_id'],
                            port['tenant_id'])

    @decorators.idempotent_id('3e39c4a6-9caf-4710-88f1-d20073c6dd76')
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

    @decorators.idempotent_id('a064a9fd-e02f-474a-8159-f828cd636a28')
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

    @decorators.idempotent_id('e03c92a2-638d-4bfa-b50a-b1f66f087e58')
    def test_show_shared_networks_attribute(self):
        # Show a shared network and confirm that
        # shared network extension attribute is returned.
        self._show_shared_network(self.admin_client)
        self._show_shared_network(self.client)


class AllowedAddressPairSharedNetworkTest(base.BaseAdminNetworkTest):
    allowed_address_pairs = [{'ip_address': '1.1.1.1'}]
    required_extensions = ['allowed-address-pairs']

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairSharedNetworkTest, cls).resource_setup()
        cls.network = cls.create_shared_network()
        cls.create_subnet(cls.network, client=cls.admin_client)

    @decorators.idempotent_id('86c3529b-1231-40de-803c-ffffffff1fff')
    def test_create_with_address_pair_blocked_on_other_network(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_port(self.network,
                             allowed_address_pairs=self.allowed_address_pairs)

    @decorators.idempotent_id('86c3529b-1231-40de-803c-ffffffff2fff')
    def test_update_with_address_pair_blocked_on_other_network(self):
        port = self.create_port(self.network)
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.update_port(
                port, allowed_address_pairs=self.allowed_address_pairs)


class RBACSharedNetworksTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['rbac-policies']

    @classmethod
    def resource_setup(cls):
        super(RBACSharedNetworksTest, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

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

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('86c3529b-1231-40de-803c-bfffffff1eee')
    def test_create_rbac_policy_with_target_tenant_none(self):
        with testtools.ExpectedException(lib_exc.BadRequest):
            self._make_admin_net_and_subnet_shared_to_tenant_id(
                tenant_id=None)

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('86c3529b-1231-40de-803c-bfffffff1fff')
    def test_create_rbac_policy_with_target_tenant_too_long_id(self):
        with testtools.ExpectedException(lib_exc.BadRequest):
            target_tenant = '1234' * 100
            self._make_admin_net_and_subnet_shared_to_tenant_id(
                tenant_id=target_tenant)

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff1fff')
    def test_network_only_visible_to_policy_target(self):
        net = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['network']
        self.client.show_network(net['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            # client2 has not been granted access
            self.client2.show_network(net['id'])

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff2fff')
    def test_subnet_on_network_only_visible_to_policy_target(self):
        sub = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['subnet']
        self.client.show_subnet(sub['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            # client2 has not been granted access
            self.client2.show_subnet(sub['id'])

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff2eee')
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

    @decorators.idempotent_id('86c3529b-1231-40de-803c-affefefef321')
    def test_duplicate_policy_error(self):
        res = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.create_rbac_policy(
                object_type='network', object_id=res['network']['id'],
                action='access_as_shared', target_tenant=self.client.tenant_id)

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff3fff')
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

        # now that wildcard is the only remaining, it should be subjected to
        # to the same restriction
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.delete_rbac_policy(wild['id'])
        # similarly, we can't update the policy to a different tenant
        with testtools.ExpectedException(lib_exc.Conflict):
            self.admin_client.update_rbac_policy(
                wild['id'], target_tenant=self.client2.tenant_id)

        self.client.delete_port(port['id'])
        # anchor is gone, delete should pass
        self.admin_client.delete_rbac_policy(wild['id'])

    @decorators.idempotent_id('34d627da-a732-68c0-2e1a-bc4a19246698')
    def test_delete_self_share_rule(self):
        net = self.create_network()
        self_share = self.client.create_rbac_policy(
                         object_type='network', object_id=net['id'],
                         action='access_as_shared',
                         target_tenant=net['tenant_id'])['rbac_policy']
        port = self.client.create_port(network_id=net['id'])['port']
        self.client.delete_rbac_policy(self_share['id'])
        self.client.delete_port(port['id'])

    @decorators.idempotent_id('86c3529b-1231-40de-803c-beefbeefbeef')
    def test_tenant_can_delete_port_on_own_network(self):
        net = self.create_network()  # owned by self.client
        self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        port = self.client2.create_port(network_id=net['id'])['port']
        self.client.delete_port(port['id'])

    @decorators.idempotent_id('f7539232-389a-4e9c-9e37-e42a129eb541')
    def test_tenant_cant_delete_other_tenants_ports(self):
        net = self.create_network()
        port = self.client.create_port(network_id=net['id'])['port']
        self.addCleanup(self.client.delete_port, port['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            self.client2.delete_port(port['id'])

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff4fff')
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

    @decorators.idempotent_id('bf5052b8-b11e-407c-8e43-113447404d3e')
    def test_filter_fields(self):
        net = self.create_network()
        self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        field_args = (('id',), ('id', 'action'), ('object_type', 'object_id'),
                      ('tenant_id', 'target_tenant'))
        for fields in field_args:
            res = self.client.list_rbac_policies(fields=fields)
            self.assertEqual(set(fields), set(res['rbac_policies'][0].keys()))

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff5fff')
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

    @decorators.idempotent_id('e7bcb1ea-4877-4266-87bb-76f68b421f31')
    def test_filter_policies(self):
        net = self.create_network()
        pol1 = self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared',
            target_tenant=self.client2.tenant_id)['rbac_policy']
        pol2 = self.client.create_rbac_policy(
            object_type='network', object_id=net['id'],
            action='access_as_shared',
            target_tenant=self.client.tenant_id)['rbac_policy']
        res1 = self.client.list_rbac_policies(id=pol1['id'])['rbac_policies']
        res2 = self.client.list_rbac_policies(id=pol2['id'])['rbac_policies']
        self.assertEqual(1, len(res1))
        self.assertEqual(1, len(res2))
        self.assertEqual(pol1['id'], res1[0]['id'])
        self.assertEqual(pol2['id'], res2[0]['id'])

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff6fff')
    def test_regular_client_blocked_from_sharing_anothers_network(self):
        net = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)['network']
        with testtools.ExpectedException(lib_exc.BadRequest):
            self.client.create_rbac_policy(
                object_type='network', object_id=net['id'],
                action='access_as_shared', target_tenant=self.client.tenant_id)

    @decorators.idempotent_id('c5f8f785-ce8d-4430-af7e-a236205862fb')
    @utils.requires_ext(extension="quotas", service="network")
    def test_rbac_policy_quota(self):
        quota = self.client.show_quotas(self.client.tenant_id)['quota']
        max_policies = quota['rbac_policy']
        self.assertGreater(max_policies, 0)
        net = self.client.create_network(
            name=data_utils.rand_name('test-network-'))['network']
        self.addCleanup(self.client.delete_network, net['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            for i in range(0, max_policies + 1):
                self.admin_client.create_rbac_policy(
                    object_type='network', object_id=net['id'],
                    action='access_as_shared',
                    target_tenant=uuidutils.generate_uuid().replace('-', ''))

    @decorators.idempotent_id('86c3529b-1231-40de-803c-afffffff7fff')
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

    @decorators.idempotent_id('34d627da-869f-68c0-2e1a-bc4a19246698')
    def test_update_self_share_rule(self):
        net = self.create_network()
        self_share = self.client.create_rbac_policy(
                         object_type='network', object_id=net['id'],
                         action='access_as_shared',
                         target_tenant=net['tenant_id'])['rbac_policy']
        port = self.client.create_port(network_id=net['id'])['port']
        self.client.update_rbac_policy(self_share['id'],
                                       target_tenant=self.client2.tenant_id)
        self.client.delete_port(port['id'])

    @utils.requires_ext(extension="standard-attr-revisions", service="network")
    @decorators.idempotent_id('86c3529b-1231-40de-1234-89664291a4cb')
    def test_rbac_bumps_network_revision(self):
        resp = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        net_id = resp['network']['id']
        rev = self.client.show_network(net_id)['network']['revision_number']
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net_id,
            action='access_as_shared', target_tenant='*')
        self.assertGreater(
            self.client.show_network(net_id)['network']['revision_number'],
            rev
        )

    @decorators.idempotent_id('86c3529b-1231-40de-803c-aeeeeeee7fff')
    def test_filtering_works_with_rbac_records_present(self):
        resp = self._make_admin_net_and_subnet_shared_to_tenant_id(
            self.client.tenant_id)
        net = resp['network']['id']
        sub = resp['subnet']['id']
        self.admin_client.create_rbac_policy(
            object_type='network', object_id=net,
            action='access_as_shared', target_tenant='*')
        self._assert_shared_object_id_listing_presence('subnets', False, sub)
        self._assert_shared_object_id_listing_presence('subnets', True, sub)
        self._assert_shared_object_id_listing_presence('networks', False, net)
        self._assert_shared_object_id_listing_presence('networks', True, net)

    def _assert_shared_object_id_listing_presence(self, resource, shared, oid):
        lister = getattr(self.admin_client, 'list_%s' % resource)
        objects = [o['id'] for o in lister(shared=shared)[resource]]
        if shared:
            self.assertIn(oid, objects)
        else:
            self.assertNotIn(oid, objects)
