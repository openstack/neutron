# Copyright 2013 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils
from tempest_lib import decorators

from neutron.tests.api import base
from neutron.tests.tempest import test


class LoadBalancerTestJSON(base.BaseNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        create vIP, and Pool
        show vIP
        list vIP
        update vIP
        delete vIP
        update pool
        delete pool
        show pool
        list pool
        health monitoring operations
    """

    @classmethod
    def resource_setup(cls):
        super(LoadBalancerTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('lbaas', 'network'):
            msg = "lbaas extension not enabled."
            raise cls.skipException(msg)
        cls.network = cls.create_network()
        cls.name = cls.network['name']
        cls.subnet = cls.create_subnet(cls.network)
        pool_name = data_utils.rand_name('pool-')
        vip_name = data_utils.rand_name('vip-')
        cls.pool = cls.create_pool(pool_name, "ROUND_ROBIN",
                                   "HTTP", cls.subnet)
        cls.vip = cls.create_vip(name=vip_name,
                                 protocol="HTTP",
                                 protocol_port=80,
                                 subnet=cls.subnet,
                                 pool=cls.pool)
        cls.member = cls.create_member(80, cls.pool, cls._ip_version)
        cls.member_address = ("10.0.9.47" if cls._ip_version == 4
                              else "2015::beef")
        cls.health_monitor = cls.create_health_monitor(delay=4,
                                                       max_retries=3,
                                                       Type="TCP",
                                                       timeout=1)

    def _check_list_with_filter(self, obj_name, attr_exceptions, **kwargs):
        create_obj = getattr(self.client, 'create_' + obj_name)
        delete_obj = getattr(self.client, 'delete_' + obj_name)
        list_objs = getattr(self.client, 'list_' + obj_name + 's')

        body = create_obj(**kwargs)
        obj = body[obj_name]
        self.addCleanup(delete_obj, obj['id'])
        for key, value in obj.iteritems():
            # It is not relevant to filter by all arguments. That is why
            # there is a list of attr to except
            if key not in attr_exceptions:
                body = list_objs(**{key: value})
                objs = [v[key] for v in body[obj_name + 's']]
                self.assertIn(value, objs)

    @test.attr(type='smoke')
    @test.idempotent_id('c96dbfab-4a80-4e74-a535-e950b5bedd47')
    def test_list_vips(self):
        # Verify the vIP exists in the list of all vIPs
        body = self.client.list_vips()
        vips = body['vips']
        self.assertIn(self.vip['id'], [v['id'] for v in vips])

    @test.attr(type='smoke')
    @test.idempotent_id('b8853f65-5089-4e69-befd-041a143427ff')
    def test_list_vips_with_filter(self):
        name = data_utils.rand_name('vip-')
        body = self.client.create_pool(name=data_utils.rand_name("pool-"),
                                       lb_method="ROUND_ROBIN",
                                       protocol="HTTPS",
                                       subnet_id=self.subnet['id'])
        pool = body['pool']
        self.addCleanup(self.client.delete_pool, pool['id'])
        attr_exceptions = ['status', 'session_persistence',
                           'status_description']
        self._check_list_with_filter(
            'vip', attr_exceptions, name=name, protocol="HTTPS",
            protocol_port=81, subnet_id=self.subnet['id'], pool_id=pool['id'],
            description=data_utils.rand_name('description-'),
            admin_state_up=False)

    @test.attr(type='smoke')
    @test.idempotent_id('27f56083-9af9-4a48-abe9-ca1bcc6c9035')
    def test_create_update_delete_pool_vip(self):
        # Creates a vip
        name = data_utils.rand_name('vip-')
        address = self.subnet['allocation_pools'][0]['end']
        body = self.client.create_pool(
            name=data_utils.rand_name("pool-"),
            lb_method='ROUND_ROBIN',
            protocol='HTTP',
            subnet_id=self.subnet['id'])
        pool = body['pool']
        body = self.client.create_vip(name=name,
                                      protocol="HTTP",
                                      protocol_port=80,
                                      subnet_id=self.subnet['id'],
                                      pool_id=pool['id'],
                                      address=address)
        vip = body['vip']
        vip_id = vip['id']
        # Confirm VIP's address correctness with a show
        body = self.client.show_vip(vip_id)
        vip = body['vip']
        self.assertEqual(address, vip['address'])
        # Verification of vip update
        new_name = "New_vip"
        new_description = "New description"
        persistence_type = "HTTP_COOKIE"
        update_data = {"session_persistence": {
            "type": persistence_type}}
        body = self.client.update_vip(vip_id,
                                      name=new_name,
                                      description=new_description,
                                      connection_limit=10,
                                      admin_state_up=False,
                                      **update_data)
        updated_vip = body['vip']
        self.assertEqual(new_name, updated_vip['name'])
        self.assertEqual(new_description, updated_vip['description'])
        self.assertEqual(10, updated_vip['connection_limit'])
        self.assertFalse(updated_vip['admin_state_up'])
        self.assertEqual(persistence_type,
                         updated_vip['session_persistence']['type'])
        self.client.delete_vip(vip['id'])
        self.client.wait_for_resource_deletion('vip', vip['id'])
        # Verification of pool update
        new_name = "New_pool"
        body = self.client.update_pool(pool['id'],
                                       name=new_name,
                                       description="new_description",
                                       lb_method='LEAST_CONNECTIONS')
        updated_pool = body['pool']
        self.assertEqual(new_name, updated_pool['name'])
        self.assertEqual('new_description', updated_pool['description'])
        self.assertEqual('LEAST_CONNECTIONS', updated_pool['lb_method'])
        self.client.delete_pool(pool['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('0435a95e-1d19-4d90-9e9f-3b979e9ad089')
    def test_show_vip(self):
        # Verifies the details of a vip
        body = self.client.show_vip(self.vip['id'])
        vip = body['vip']
        for key, value in vip.iteritems():
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.vip[key], value)

    @test.attr(type='smoke')
    @test.idempotent_id('6e7a7d31-8451-456d-b24a-e50479ce42a7')
    def test_show_pool(self):
        # Here we need to new pool without any dependence with vips
        body = self.client.create_pool(name=data_utils.rand_name("pool-"),
                                       lb_method='ROUND_ROBIN',
                                       protocol='HTTP',
                                       subnet_id=self.subnet['id'])
        pool = body['pool']
        self.addCleanup(self.client.delete_pool, pool['id'])
        # Verifies the details of a pool
        body = self.client.show_pool(pool['id'])
        shown_pool = body['pool']
        for key, value in pool.iteritems():
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(value, shown_pool[key])

    @test.attr(type='smoke')
    @test.idempotent_id('d1ab1ffa-e06a-487f-911f-56418cb27727')
    def test_list_pools(self):
        # Verify the pool exists in the list of all pools
        body = self.client.list_pools()
        pools = body['pools']
        self.assertIn(self.pool['id'], [p['id'] for p in pools])

    @test.attr(type='smoke')
    @test.idempotent_id('27cc4c1a-caac-4273-b983-2acb4afaad4f')
    def test_list_pools_with_filters(self):
        attr_exceptions = ['status', 'vip_id', 'members', 'provider',
                           'status_description']
        self._check_list_with_filter(
            'pool', attr_exceptions, name=data_utils.rand_name("pool-"),
            lb_method="ROUND_ROBIN", protocol="HTTPS",
            subnet_id=self.subnet['id'],
            description=data_utils.rand_name('description-'),
            admin_state_up=False)

    @test.attr(type='smoke')
    @test.idempotent_id('282d0dfd-5c3a-4c9b-b39c-c99782f39193')
    def test_list_members(self):
        # Verify the member exists in the list of all members
        body = self.client.list_members()
        members = body['members']
        self.assertIn(self.member['id'], [m['id'] for m in members])

    @test.attr(type='smoke')
    @test.idempotent_id('243b5126-24c6-4879-953e-7c7e32d8a57f')
    def test_list_members_with_filters(self):
        attr_exceptions = ['status', 'status_description']
        self._check_list_with_filter('member', attr_exceptions,
                                     address=self.member_address,
                                     protocol_port=80,
                                     pool_id=self.pool['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('fb833ee8-9e69-489f-b540-a409762b78b2')
    def test_create_update_delete_member(self):
        # Creates a member
        body = self.client.create_member(address=self.member_address,
                                         protocol_port=80,
                                         pool_id=self.pool['id'])
        member = body['member']
        # Verification of member update
        body = self.client.update_member(member['id'],
                                         admin_state_up=False)
        updated_member = body['member']
        self.assertFalse(updated_member['admin_state_up'])
        # Verification of member delete
        self.client.delete_member(member['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('893cd71f-a7dd-4485-b162-f6ab9a534914')
    def test_show_member(self):
        # Verifies the details of a member
        body = self.client.show_member(self.member['id'])
        member = body['member']
        for key, value in member.iteritems():
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.member[key], value)

    @test.attr(type='smoke')
    @test.idempotent_id('8e5822c5-68a4-4224-8d6c-a617741ebc2d')
    def test_list_health_monitors(self):
        # Verify the health monitor exists in the list of all health monitors
        body = self.client.list_health_monitors()
        health_monitors = body['health_monitors']
        self.assertIn(self.health_monitor['id'],
                      [h['id'] for h in health_monitors])

    @test.attr(type='smoke')
    @test.idempotent_id('49bac58a-511c-4875-b794-366698211d25')
    def test_list_health_monitors_with_filters(self):
        attr_exceptions = ['status', 'status_description', 'pools']
        self._check_list_with_filter('health_monitor', attr_exceptions,
                                     delay=5, max_retries=4, type="TCP",
                                     timeout=2)

    @test.attr(type='smoke')
    @test.idempotent_id('e8ce05c4-d554-4d1e-a257-ad32ce134bb5')
    def test_create_update_delete_health_monitor(self):
        # Creates a health_monitor
        body = self.client.create_health_monitor(delay=4,
                                                 max_retries=3,
                                                 type="TCP",
                                                 timeout=1)
        health_monitor = body['health_monitor']
        # Verification of health_monitor update
        body = (self.client.update_health_monitor
                (health_monitor['id'],
                 admin_state_up=False))
        updated_health_monitor = body['health_monitor']
        self.assertFalse(updated_health_monitor['admin_state_up'])
        # Verification of health_monitor delete
        body = self.client.delete_health_monitor(health_monitor['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('d3e1aebc-06c2-49b3-9816-942af54012eb')
    def test_create_health_monitor_http_type(self):
        hm_type = "HTTP"
        body = self.client.create_health_monitor(delay=4,
                                                 max_retries=3,
                                                 type=hm_type,
                                                 timeout=1)
        health_monitor = body['health_monitor']
        self.addCleanup(self.client.delete_health_monitor,
                        health_monitor['id'])
        self.assertEqual(hm_type, health_monitor['type'])

    @test.attr(type='smoke')
    @test.idempotent_id('0eff9f67-90fb-4bb1-b4ed-c5fda99fff0c')
    def test_update_health_monitor_http_method(self):
        body = self.client.create_health_monitor(delay=4,
                                                 max_retries=3,
                                                 type="HTTP",
                                                 timeout=1)
        health_monitor = body['health_monitor']
        self.addCleanup(self.client.delete_health_monitor,
                        health_monitor['id'])
        body = (self.client.update_health_monitor
                (health_monitor['id'],
                 http_method="POST",
                 url_path="/home/user",
                 expected_codes="290"))
        updated_health_monitor = body['health_monitor']
        self.assertEqual("POST", updated_health_monitor['http_method'])
        self.assertEqual("/home/user", updated_health_monitor['url_path'])
        self.assertEqual("290", updated_health_monitor['expected_codes'])

    @test.attr(type='smoke')
    @test.idempotent_id('08e126ab-1407-483f-a22e-b11cc032ca7c')
    def test_show_health_monitor(self):
        # Verifies the details of a health_monitor
        body = self.client.show_health_monitor(self.health_monitor['id'])
        health_monitor = body['health_monitor']
        for key, value in health_monitor.iteritems():
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.health_monitor[key], value)

    @test.attr(type='smoke')
    @test.idempotent_id('87f7628e-8918-493d-af50-0602845dbb5b')
    def test_associate_disassociate_health_monitor_with_pool(self):
        # Verify that a health monitor can be associated with a pool
        self.client.associate_health_monitor_with_pool(
            self.health_monitor['id'], self.pool['id'])
        body = self.client.show_health_monitor(
            self.health_monitor['id'])
        health_monitor = body['health_monitor']
        body = self.client.show_pool(self.pool['id'])
        pool = body['pool']
        self.assertIn(pool['id'],
                      [p['pool_id'] for p in health_monitor['pools']])
        self.assertIn(health_monitor['id'], pool['health_monitors'])
        # Verify that a health monitor can be disassociated from a pool
        (self.client.disassociate_health_monitor_with_pool
            (self.health_monitor['id'], self.pool['id']))
        body = self.client.show_pool(self.pool['id'])
        pool = body['pool']
        body = self.client.show_health_monitor(
            self.health_monitor['id'])
        health_monitor = body['health_monitor']
        self.assertNotIn(health_monitor['id'], pool['health_monitors'])
        self.assertNotIn(pool['id'],
                         [p['pool_id'] for p in health_monitor['pools']])

    @test.attr(type='smoke')
    @test.idempotent_id('525fc7dc-be24-408d-938d-822e9783e027')
    def test_get_lb_pool_stats(self):
        # Verify the details of pool stats
        body = self.client.list_lb_pool_stats(self.pool['id'])
        stats = body['stats']
        self.assertIn("bytes_in", stats)
        self.assertIn("total_connections", stats)
        self.assertIn("active_connections", stats)
        self.assertIn("bytes_out", stats)

    @test.attr(type='smoke')
    @test.idempotent_id('66236be2-5121-4047-8cde-db4b83b110a5')
    def test_update_list_of_health_monitors_associated_with_pool(self):
        (self.client.associate_health_monitor_with_pool
            (self.health_monitor['id'], self.pool['id']))
        self.client.update_health_monitor(
            self.health_monitor['id'], admin_state_up=False)
        body = self.client.show_pool(self.pool['id'])
        health_monitors = body['pool']['health_monitors']
        for health_monitor_id in health_monitors:
            body = self.client.show_health_monitor(health_monitor_id)
            self.assertFalse(body['health_monitor']['admin_state_up'])
            (self.client.disassociate_health_monitor_with_pool
                (self.health_monitor['id'], self.pool['id']))

    @test.attr(type='smoke')
    @test.idempotent_id('44ec9b40-b501-41e2-951f-4fc673b15ac0')
    def test_update_admin_state_up_of_pool(self):
        self.client.update_pool(self.pool['id'],
                                admin_state_up=False)
        body = self.client.show_pool(self.pool['id'])
        pool = body['pool']
        self.assertFalse(pool['admin_state_up'])

    @test.attr(type='smoke')
    @test.idempotent_id('466a9d4c-37c6-4ea2-b807-133437beb48c')
    def test_show_vip_associated_with_pool(self):
        body = self.client.show_pool(self.pool['id'])
        pool = body['pool']
        body = self.client.show_vip(pool['vip_id'])
        vip = body['vip']
        self.assertEqual(self.vip['name'], vip['name'])
        self.assertEqual(self.vip['id'], vip['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('7b97694e-69d0-4151-b265-e1052a465aa8')
    def test_show_members_associated_with_pool(self):
        body = self.client.show_pool(self.pool['id'])
        members = body['pool']['members']
        for member_id in members:
            body = self.client.show_member(member_id)
            self.assertIsNotNone(body['member']['status'])
            self.assertEqual(member_id, body['member']['id'])
            self.assertIsNotNone(body['member']['admin_state_up'])

    @test.attr(type='smoke')
    @test.idempotent_id('73ed6f27-595b-4b2c-969c-dbdda6b8ab34')
    def test_update_pool_related_to_member(self):
        # Create new pool
        body = self.client.create_pool(name=data_utils.rand_name("pool-"),
                                       lb_method='ROUND_ROBIN',
                                       protocol='HTTP',
                                       subnet_id=self.subnet['id'])
        new_pool = body['pool']
        self.addCleanup(self.client.delete_pool, new_pool['id'])
        # Update member with new pool's id
        body = self.client.update_member(self.member['id'],
                                         pool_id=new_pool['id'])
        # Confirm with show that pool_id change
        body = self.client.show_member(self.member['id'])
        member = body['member']
        self.assertEqual(member['pool_id'], new_pool['id'])
        # Update member with old pool id, this is needed for clean up
        body = self.client.update_member(self.member['id'],
                                         pool_id=self.pool['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('cf63f071-bbe3-40ba-97a0-a33e11923162')
    def test_update_member_weight(self):
        self.client.update_member(self.member['id'],
                                  weight=2)
        body = self.client.show_member(self.member['id'])
        member = body['member']
        self.assertEqual(2, member['weight'])


@decorators.skip_because(bug="1402007")
class LoadBalancerIpV6TestJSON(LoadBalancerTestJSON):
    _ip_version = 6
