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

import netaddr
from tempest_lib.common.utils import data_utils

from neutron.tests.api import base_routers as base
from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF


class RoutersTest(base.BaseRouterTest):

    @classmethod
    def resource_setup(cls):
        super(RoutersTest, cls).resource_setup()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        admin_manager = clients.AdminManager()
        cls.identity_admin_client = admin_manager.identity_client
        cls.tenant_cidr = (CONF.network.tenant_network_cidr
                           if cls._ip_version == 4 else
                           CONF.network.tenant_network_v6_cidr)

    @test.attr(type='smoke')
    @test.idempotent_id('f64403e2-8483-4b34-8ccd-b09a87bcc68c')
    def test_create_show_list_update_delete_router(self):
        # Create a router
        # NOTE(salv-orlando): Do not invoke self.create_router
        # as we need to check the response code
        name = data_utils.rand_name('router-')
        create_body = self.client.create_router(
            name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        self.addCleanup(self._delete_router, create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], name)
        self.assertEqual(
            create_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(create_body['router']['admin_state_up'], False)
        # Show details of the created router
        show_body = self.client.show_router(create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(
            show_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(show_body['router']['admin_state_up'], False)
        # List routers and verify if created router is there in response
        list_body = self.client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertIn(create_body['router']['id'], routers_list)
        # Update the name of router and verify if it is updated
        updated_name = 'updated ' + name
        update_body = self.client.update_router(create_body['router']['id'],
                                                name=updated_name)
        self.assertEqual(update_body['router']['name'], updated_name)
        show_body = self.client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], updated_name)

    @test.attr(type='smoke')
    @test.idempotent_id('e54dd3a3-4352-4921-b09d-44369ae17397')
    def test_create_router_setting_tenant_id(self):
        # Test creating router from admin user setting tenant_id.
        test_tenant = data_utils.rand_name('test_tenant_')
        test_description = data_utils.rand_name('desc_')
        tenant = self.identity_admin_client.create_tenant(
            name=test_tenant, description=test_description)
        tenant_id = tenant['id']
        self.addCleanup(self.identity_admin_client.delete_tenant, tenant_id)

        name = data_utils.rand_name('router-')
        create_body = self.admin_client.create_router(name,
                                                      tenant_id=tenant_id)
        self.addCleanup(self.admin_client.delete_router,
                        create_body['router']['id'])
        self.assertEqual(tenant_id, create_body['router']['tenant_id'])

    @test.idempotent_id('847257cc-6afd-4154-b8fb-af49f5670ce8')
    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_create_router_with_default_snat_value(self):
        # Create a router with default snat rule
        name = data_utils.rand_name('router')
        router = self._create_router(
            name, external_network_id=CONF.network.public_network_id)
        self._verify_router_gateway(
            router['id'], {'network_id': CONF.network.public_network_id,
                           'enable_snat': True})

    @test.idempotent_id('ea74068d-09e9-4fd7-8995-9b6a1ace920f')
    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_create_router_with_snat_explicit(self):
        name = data_utils.rand_name('snat-router')
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': CONF.network.public_network_id,
                'enable_snat': enable_snat}
            create_body = self.admin_client.create_router(
                name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)

    @test.attr(type='smoke')
    @test.idempotent_id('b42e6e39-2e37-49cc-a6f4-8467e940900a')
    def test_add_remove_router_interface_with_subnet_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self._create_router(data_utils.rand_name('router-'))
        # Add router interface with subnet id
        interface = self.client.add_router_interface_with_subnet_id(
            router['id'], subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('2b7d2f37-6748-4d78-92e5-1d590234f0d5')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()
        self.create_subnet(network)
        router = self._create_router(data_utils.rand_name('router-'))
        port_body = self.client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.client.add_router_interface_with_port_id(
            router['id'], port_body['port']['id'])
        self.addCleanup(self._remove_router_interface_with_port_id,
                        router['id'], port_body['port']['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    def _verify_router_gateway(self, router_id, exp_ext_gw_info=None):
        show_body = self.admin_client.show_router(router_id)
        actual_ext_gw_info = show_body['router']['external_gateway_info']
        if exp_ext_gw_info is None:
            self.assertIsNone(actual_ext_gw_info)
            return
        # Verify only keys passed in exp_ext_gw_info
        for k, v in exp_ext_gw_info.iteritems():
            self.assertEqual(v, actual_ext_gw_info[k])

    def _verify_gateway_port(self, router_id):
        list_body = self.admin_client.list_ports(
            network_id=CONF.network.public_network_id,
            device_id=router_id)
        self.assertEqual(len(list_body['ports']), 1)
        gw_port = list_body['ports'][0]
        fixed_ips = gw_port['fixed_ips']
        self.assertGreaterEqual(len(fixed_ips), 1)
        public_net_body = self.admin_client.show_network(
            CONF.network.public_network_id)
        public_subnet_id = public_net_body['network']['subnets'][0]
        self.assertIn(public_subnet_id,
                      map(lambda x: x['subnet_id'], fixed_ips))

    @test.attr(type='smoke')
    @test.idempotent_id('6cc285d8-46bf-4f36-9b1a-783e3008ba79')
    def test_update_router_set_gateway(self):
        router = self._create_router(data_utils.rand_name('router-'))
        self.client.update_router(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id})
        # Verify operation - router
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id})
        self._verify_gateway_port(router['id'])

    @test.idempotent_id('b386c111-3b21-466d-880c-5e72b01e1a33')
    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_set_gateway_with_snat_explicit(self):
        router = self._create_router(data_utils.rand_name('router-'))
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': True})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': True})
        self._verify_gateway_port(router['id'])

    @test.idempotent_id('96536bc7-8262-4fb2-9967-5c46940fa279')
    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_set_gateway_without_snat(self):
        router = self._create_router(data_utils.rand_name('router-'))
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('ad81b7ee-4f81-407b-a19c-17e623f763e8')
    def test_update_router_unset_gateway(self):
        router = self._create_router(
            data_utils.rand_name('router-'),
            external_network_id=CONF.network.public_network_id)
        self.client.update_router(router['id'], external_gateway_info={})
        self._verify_router_gateway(router['id'])
        # No gateway port expected
        list_body = self.admin_client.list_ports(
            network_id=CONF.network.public_network_id,
            device_id=router['id'])
        self.assertFalse(list_body['ports'])

    @test.idempotent_id('f2faf994-97f4-410b-a831-9bc977b64374')
    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_reset_gateway_without_snat(self):
        router = self._create_router(
            data_utils.rand_name('router-'),
            external_network_id=CONF.network.public_network_id)
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])

    @test.idempotent_id('c86ac3a8-50bd-4b00-a6b8-62af84a0765c')
    @test.requires_ext(extension='extraroute', service='network')
    @test.attr(type='smoke')
    def test_update_extra_route(self):
        self.network = self.create_network()
        self.name = self.network['name']
        self.subnet = self.create_subnet(self.network)
        # Add router interface with subnet id
        self.router = self._create_router(
            data_utils.rand_name('router-'), True)
        self.create_router_interface(self.router['id'], self.subnet['id'])
        self.addCleanup(
            self._delete_extra_routes,
            self.router['id'])
        # Update router extra route, second ip of the range is
        # used as next hop
        cidr = netaddr.IPNetwork(self.subnet['cidr'])
        next_hop = str(cidr[2])
        destination = str(self.subnet['cidr'])
        extra_route = self.client.update_extra_routes(self.router['id'],
                                                      next_hop, destination)
        self.assertEqual(1, len(extra_route['router']['routes']))
        self.assertEqual(destination,
                         extra_route['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         extra_route['router']['routes'][0]['nexthop'])
        show_body = self.client.show_router(self.router['id'])
        self.assertEqual(destination,
                         show_body['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         show_body['router']['routes'][0]['nexthop'])

    def _delete_extra_routes(self, router_id):
        self.client.delete_extra_routes(router_id)

    @test.attr(type='smoke')
    @test.idempotent_id('a8902683-c788-4246-95c7-ad9c6d63a4d9')
    def test_update_router_admin_state(self):
        self.router = self._create_router(data_utils.rand_name('router-'))
        self.assertFalse(self.router['admin_state_up'])
        # Update router admin state
        update_body = self.client.update_router(self.router['id'],
                                                admin_state_up=True)
        self.assertTrue(update_body['router']['admin_state_up'])
        show_body = self.client.show_router(self.router['id'])
        self.assertTrue(show_body['router']['admin_state_up'])

    @test.attr(type='smoke')
    @test.idempotent_id('802c73c9-c937-4cef-824b-2191e24a6aab')
    def test_add_multiple_router_interfaces(self):
        network01 = self.create_network(
            network_name=data_utils.rand_name('router-network01-'))
        network02 = self.create_network(
            network_name=data_utils.rand_name('router-network02-'))
        subnet01 = self.create_subnet(network01)
        sub02_cidr = netaddr.IPNetwork(self.tenant_cidr).next()
        subnet02 = self.create_subnet(network02, cidr=sub02_cidr)
        router = self._create_router(data_utils.rand_name('router-'))
        interface01 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet01['id'])
        self._verify_router_interface(router['id'], subnet01['id'],
                                      interface01['port_id'])
        interface02 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet02['id'])
        self._verify_router_interface(router['id'], subnet02['id'],
                                      interface02['port_id'])

    def _verify_router_interface(self, router_id, subnet_id, port_id):
        show_port_body = self.client.show_port(port_id)
        interface_port = show_port_body['port']
        self.assertEqual(router_id, interface_port['device_id'])
        self.assertEqual(subnet_id,
                         interface_port['fixed_ips'][0]['subnet_id'])


class RoutersIpV6Test(RoutersTest):
    _ip_version = 6


class DvrRoutersTest(base.BaseRouterTest):

    @classmethod
    def skip_checks(cls):
        super(DvrRoutersTest, cls).skip_checks()
        if not test.is_extension_enabled('dvr', 'network'):
            msg = "DVR extension not enabled."
            raise cls.skipException(msg)

    @test.attr(type='smoke')
    @test.idempotent_id('141297aa-3424-455d-aa8d-f2d95731e00a')
    def test_create_distributed_router(self):
        name = data_utils.rand_name('router')
        create_body = self.admin_client.create_router(
            name, distributed=True)
        self.addCleanup(self._delete_router,
                        create_body['router']['id'],
                        self.admin_client)
        self.assertTrue(create_body['router']['distributed'])

    @test.attr(type='smoke')
    @test.idempotent_id('644d7a4a-01a1-4b68-bb8d-0c0042cb1729')
    def test_convert_centralized_router(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertNotIn('distributed', router)
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=True)
        self.assertTrue(update_body['router']['distributed'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertTrue(show_body['router']['distributed'])
        show_body = self.client.show_router(router['id'])
        self.assertNotIn('distributed', show_body['router'])
