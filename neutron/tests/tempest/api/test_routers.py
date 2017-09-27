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
from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron.common import utils
from neutron.tests.tempest.api import base
from neutron.tests.tempest.api import base_routers
from neutron.tests.tempest import config

CONF = config.CONF


class RoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(RoutersTest, cls).resource_setup()
        cls.tenant_cidr = (
            config.safe_get_config_value('network', 'project_network_cidr')
            if cls._ip_version == 4 else
            config.safe_get_config_value('network', 'project_network_v6_cidr'))

    @decorators.idempotent_id('c72c1c0c-2193-4aca-eeee-b1442640eeee')
    @tutils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_router_description(self):
        body = self.create_router(description='d1', router_name='test')
        self.assertEqual('d1', body['description'])
        body = self.client.show_router(body['id'])['router']
        self.assertEqual('d1', body['description'])
        body = self.client.update_router(body['id'], description='d2')
        self.assertEqual('d2', body['router']['description'])
        body = self.client.show_router(body['router']['id'])['router']
        self.assertEqual('d2', body['description'])

    @decorators.idempotent_id('847257cc-6afd-4154-b8fb-af49f5670ce8')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
    def test_create_router_with_default_snat_value(self):
        # Create a router with default snat rule
        name = data_utils.rand_name('router')
        router = self._create_router(
            name, external_network_id=CONF.network.public_network_id)
        self._verify_router_gateway(
            router['id'], {'network_id': CONF.network.public_network_id,
                           'enable_snat': True})

    @decorators.idempotent_id('ea74068d-09e9-4fd7-8995-9b6a1ace920f')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
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

    def _verify_router_gateway(self, router_id, exp_ext_gw_info=None):
        show_body = self.admin_client.show_router(router_id)
        actual_ext_gw_info = show_body['router']['external_gateway_info']
        if exp_ext_gw_info is None:
            self.assertIsNone(actual_ext_gw_info)
            return
        # Verify only keys passed in exp_ext_gw_info
        for k, v in exp_ext_gw_info.items():
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
        public_subnet_ids = public_net_body['network']['subnets']
        for fixed_ip in fixed_ips:
            self.assertIn(fixed_ip['subnet_id'],
                          public_subnet_ids)

    @decorators.idempotent_id('b386c111-3b21-466d-880c-5e72b01e1a33')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
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

    @decorators.idempotent_id('96536bc7-8262-4fb2-9967-5c46940fa279')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
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

    @decorators.idempotent_id('f2faf994-97f4-410b-a831-9bc977b64374')
    @tutils.requires_ext(extension='ext-gw-mode', service='network')
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

    @decorators.idempotent_id('db3093b1-93b6-4893-be83-c4716c251b3e')
    def test_router_interface_status(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Add router interface with subnet id
        router = self._create_router(data_utils.rand_name('router-'), True)
        intf = self.create_router_interface(router['id'], subnet['id'])
        status_active = lambda: self.client.show_port(
            intf['port_id'])['port']['status'] == 'ACTIVE'
        utils.wait_until_true(status_active, exception=AssertionError)

    @decorators.idempotent_id('c86ac3a8-50bd-4b00-a6b8-62af84a0765c')
    @tutils.requires_ext(extension='extraroute', service='network')
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

    @decorators.idempotent_id('01f185d1-d1a6-4cf9-abf7-e0e1384c169c')
    def test_network_attached_with_two_routers(self):
        network = self.create_network(data_utils.rand_name('network1'))
        self.create_subnet(network)
        port1 = self.create_port(network)
        port2 = self.create_port(network)
        router1 = self._create_router(data_utils.rand_name('router1'))
        router2 = self._create_router(data_utils.rand_name('router2'))
        self.client.add_router_interface_with_port_id(
            router1['id'], port1['id'])
        self.client.add_router_interface_with_port_id(
            router2['id'], port2['id'])
        self.addCleanup(self.client.remove_router_interface_with_port_id,
                        router1['id'], port1['id'])
        self.addCleanup(self.client.remove_router_interface_with_port_id,
                        router2['id'], port2['id'])
        body = self.client.show_port(port1['id'])
        port_show1 = body['port']
        body = self.client.show_port(port2['id'])
        port_show2 = body['port']
        self.assertEqual(port_show1['network_id'], network['id'])
        self.assertEqual(port_show2['network_id'], network['id'])
        self.assertEqual(port_show1['device_id'], router1['id'])
        self.assertEqual(port_show2['device_id'], router2['id'])


class RoutersIpV6Test(RoutersTest):
    _ip_version = 6


class DvrRoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['dvr']

    @decorators.idempotent_id('141297aa-3424-455d-aa8d-f2d95731e00a')
    def test_create_distributed_router(self):
        name = data_utils.rand_name('router')
        create_body = self.admin_client.create_router(
            name, distributed=True)
        self.addCleanup(self._delete_router,
                        create_body['router']['id'],
                        self.admin_client)
        self.assertTrue(create_body['router']['distributed'])

    @decorators.idempotent_id('644d7a4a-01a1-4b68-bb8d-0c0042cb1729')
    def test_convert_centralized_router(self):
        router_args = {'tenant_id': self.client.tenant_id,
                       'distributed': False, 'ha': False}
        router = self.admin_client.create_router(
            data_utils.rand_name('router'), admin_state_up=False,
            **router_args)['router']
        self.addCleanup(self.admin_client.delete_router,
                        router['id'])
        self.assertFalse(router['distributed'])
        self.assertFalse(router['ha'])
        update_body = self.admin_client.update_router(router['id'],
                                                      distributed=True)
        self.assertTrue(update_body['router']['distributed'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertTrue(show_body['router']['distributed'])
        show_body = self.client.show_router(router['id'])
        self.assertNotIn('distributed', show_body['router'])
        self.assertNotIn('ha', show_body['router'])


class HaRoutersTest(base_routers.BaseRouterTest):

    required_extensions = ['l3-ha']

    @decorators.idempotent_id('77db8eae-3aa3-4e61-bf2a-e739ce042e53')
    def test_convert_legacy_router(self):
        router = self._create_router(data_utils.rand_name('router'))
        self.assertNotIn('ha', router)
        update_body = self.admin_client.update_router(router['id'],
                                                      ha=True)
        self.assertTrue(update_body['router']['ha'])
        show_body = self.admin_client.show_router(router['id'])
        self.assertTrue(show_body['router']['ha'])
        show_body = self.client.show_router(router['id'])
        self.assertNotIn('ha', show_body['router'])


class RoutersSearchCriteriaTest(base.BaseSearchCriteriaTest):

    required_extensions = ['router']
    resource = 'router'

    @classmethod
    def resource_setup(cls):
        super(RoutersSearchCriteriaTest, cls).resource_setup()
        for name in cls.resource_names:
            cls.create_router(router_name=name)

    @decorators.idempotent_id('03a69efb-90a7-435b-bb5c-3add3612085a')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('95913d30-ff41-4b17-9f44-5258c651e78c')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('7f7d40b1-e165-4817-8dc5-02f8e2f0dff3')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('a5b83e83-3d98-45bb-a2c7-0ee179ffd42c')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('40804af8-c25d-45f8-b8a8-b4c70345215d')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('77b9676c-d3cb-43af-a0e8-a5b8c6099e70')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('3133a2c5-1bb9-4fc7-833e-cf9a1d160255')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('8252e2f0-b3da-4738-8e25-f6f8d878a2da')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

    @decorators.idempotent_id('fb102124-20f8-4cb3-8c81-f16f5e41d192')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()
