# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from neutron.tests.api import base
from neutron.tests.tempest.common import tempest_fixtures as fixtures

CONF = config.CONF


class BgpSpeakerTestJSONBase(base.BaseAdminNetworkTest):

    default_bgp_speaker_args = {'local_as': '1234',
                                'ip_version': 4,
                                'name': 'my-bgp-speaker',
                                'advertise_floating_ip_host_routes': True,
                                'advertise_tenant_networks': True}
    default_bgp_peer_args = {'remote_as': '4321',
                             'name': 'my-bgp-peer',
                             'peer_ip': '192.168.1.1',
                             'auth_type': 'md5', 'password': 'my-secret'}

    @classmethod
    def resource_setup(cls):
        super(BgpSpeakerTestJSONBase, cls).resource_setup()
        if not test.is_extension_enabled('bgp_speaker', 'network'):
            msg = "BGP Speaker extension is not enabled."
            raise cls.skipException(msg)

        cls.admin_routerports = []
        cls.admin_floatingips = []
        cls.admin_routers = []
        cls.ext_net_id = CONF.network.public_network_id

    @classmethod
    def resource_cleanup(cls):
        for floatingip in cls.admin_floatingips:
            cls._try_delete_resource(cls.admin_client.delete_floatingip,
                                     floatingip['id'])
        for routerport in cls.admin_routerports:
            cls._try_delete_resource(
                      cls.admin_client.remove_router_interface_with_subnet_id,
                      routerport['router_id'], routerport['subnet_id'])
        for router in cls.admin_routers:
            cls._try_delete_resource(cls.admin_client.delete_router,
                                     router['id'])
        super(BgpSpeakerTestJSONBase, cls).resource_cleanup()

    def create_bgp_speaker(self, auto_delete=True, **args):
        data = {'bgp_speaker': args}
        bgp_speaker = self.admin_client.create_bgp_speaker(data)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        if auto_delete:
            self.addCleanup(self.delete_bgp_speaker, bgp_speaker_id)
        return bgp_speaker

    def create_bgp_peer(self, **args):
        bgp_peer = self.admin_client.create_bgp_peer({'bgp_peer': args})
        bgp_peer_id = bgp_peer['bgp-peer']['id']
        self.addCleanup(self.delete_bgp_peer, bgp_peer_id)
        return bgp_peer

    def update_bgp_speaker(self, id, **args):
        data = {'bgp_speaker': args}
        return self.admin_client.update_bgp_speaker(id, data)

    def delete_bgp_speaker(self, id):
        return self.admin_client.delete_bgp_speaker(id)

    def get_bgp_speaker(self, id):
        return self.admin_client.get_bgp_speaker(id)

    def create_bgp_speaker_and_peer(self):
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_peer = self.create_bgp_peer(**self.default_bgp_peer_args)
        return (bgp_speaker, bgp_peer)

    def delete_bgp_peer(self, id):
        return self.admin_client.delete_bgp_peer(id)

    def add_bgp_peer(self, bgp_speaker_id, bgp_peer_id):
        return self.admin_client.add_bgp_peer_with_id(bgp_speaker_id,
                                                      bgp_peer_id)

    def remove_bgp_peer(self, bgp_speaker_id, bgp_peer_id):
        return self.admin_client.remove_bgp_peer_with_id(bgp_speaker_id,
                                                         bgp_peer_id)

    def delete_address_scope(self, id):
        return self.admin_client.delete_address_scope(id)


class BgpSpeakerTestJSON(BgpSpeakerTestJSONBase):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        Create bgp-speaker
        Delete bgp-speaker
        Create bgp-peer
        Update bgp-peer
        Delete bgp-peer
    """

    @test.idempotent_id('df259771-7104-4ffa-b77f-bd183600d7f9')
    def test_delete_bgp_speaker(self):
        bgp_speaker = self.create_bgp_speaker(auto_delete=False,
                                              **self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.delete_bgp_speaker(bgp_speaker_id)
        self.assertRaises(lib_exc.NotFound,
                          self.get_bgp_speaker,
                          bgp_speaker_id)

    @test.idempotent_id('81d9dc45-19f8-4c6e-88b8-401d965cd1b0')
    def test_create_bgp_peer(self):
        self.create_bgp_peer(**self.default_bgp_peer_args)

    @test.idempotent_id('6ade0319-1ee2-493c-ac4b-5eb230ff3a77')
    def test_add_bgp_peer(self):
        bgp_speaker, bgp_peer = self.create_bgp_speaker_and_peer()
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        bgp_peer_id = bgp_peer['bgp-peer']['id']

        self.add_bgp_peer(bgp_speaker_id, bgp_peer_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        bgp_peers_list = bgp_speaker['bgp-speaker']['peers']
        self.assertEqual(1, len(bgp_peers_list))
        self.assertTrue(bgp_peer_id in bgp_peers_list)

    @test.idempotent_id('f9737708-1d79-440b-8350-779f97d882ee')
    def test_remove_bgp_peer(self):
        bgp_peer = self.create_bgp_peer(**self.default_bgp_peer_args)
        bgp_peer_id = bgp_peer['bgp-peer']['id']
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.add_bgp_peer(bgp_speaker_id, bgp_peer_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        bgp_peers_list = bgp_speaker['bgp-speaker']['peers']
        self.assertTrue(bgp_peer_id in bgp_peers_list)

        bgp_speaker = self.remove_bgp_peer(bgp_speaker_id, bgp_peer_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        bgp_peers_list = bgp_speaker['bgp-speaker']['peers']
        self.assertTrue(not bgp_peers_list)

    @testtools.skip('bug/1553374')
    @test.idempotent_id('23c8eb37-d10d-4f43-b2e7-6542cb6a4405')
    def test_add_gateway_network(self):
        self.useFixture(fixtures.LockFixture('gateway_network_binding'))
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']

        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  self.ext_net_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        network_list = bgp_speaker['bgp-speaker']['networks']
        self.assertEqual(1, len(network_list))
        self.assertTrue(self.ext_net_id in network_list)

    @testtools.skip('bug/1553374')
    @test.idempotent_id('6cfc7137-0d99-4a3d-826c-9d1a3a1767b0')
    def test_remove_gateway_network(self):
        self.useFixture(fixtures.LockFixture('gateway_network_binding'))
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  self.ext_net_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        networks = bgp_speaker['bgp-speaker']['networks']

        self.assertTrue(self.ext_net_id in networks)
        self.admin_client.remove_bgp_gateway_network(bgp_speaker_id,
                                                     self.ext_net_id)
        bgp_speaker = self.admin_client.get_bgp_speaker(bgp_speaker_id)
        network_list = bgp_speaker['bgp-speaker']['networks']
        self.assertTrue(not network_list)

    @testtools.skip('bug/1553374')
    @test.idempotent_id('5bef22ad-5e70-4f7b-937a-dc1944642996')
    def test_get_advertised_routes_null_address_scope(self):
        self.useFixture(fixtures.LockFixture('gateway_network_binding'))
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  self.ext_net_id)
        routes = self.admin_client.get_bgp_advertised_routes(bgp_speaker_id)
        self.assertEqual(0, len(routes['advertised_routes']))

    @testtools.skip('bug/1553374')
    @test.idempotent_id('cae9cdb1-ad65-423c-9604-d4cd0073616e')
    def test_get_advertised_routes_floating_ips(self):
        self.useFixture(fixtures.LockFixture('gateway_network_binding'))
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  self.ext_net_id)
        tenant_net = self.create_network()
        tenant_subnet = self.create_subnet(tenant_net)
        ext_gw_info = {'network_id': self.ext_net_id}
        router = self.admin_client.create_router(
                                            'my-router',
                                            external_gateway_info=ext_gw_info,
                                            admin_state_up=True,
                                            distributed=False)
        self.admin_routers.append(router['router'])
        self.admin_client.add_router_interface_with_subnet_id(
                                                       router['router']['id'],
                                                       tenant_subnet['id'])
        self.admin_routerports.append({'router_id': router['router']['id'],
                                       'subnet_id': tenant_subnet['id']})
        tenant_port = self.create_port(tenant_net)
        floatingip = self.create_floatingip(self.ext_net_id)
        self.admin_floatingips.append(floatingip)
        self.client.update_floatingip(floatingip['id'],
                                      port_id=tenant_port['id'])
        routes = self.admin_client.get_bgp_advertised_routes(bgp_speaker_id)
        self.assertEqual(1, len(routes['advertised_routes']))
        self.assertEqual(floatingip['floating_ip_address'] + '/32',
                         routes['advertised_routes'][0]['destination'])

    @testtools.skip('bug/1553374')
    @test.idempotent_id('c9ad566e-fe8f-4559-8303-bbad9062a30c')
    def test_get_advertised_routes_tenant_networks(self):
        self.useFixture(fixtures.LockFixture('gateway_network_binding'))
        addr_scope = self.create_address_scope('my-scope', ip_version=4)
        ext_net = self.create_shared_network(**{'router:external': True})
        tenant_net = self.create_network()
        ext_subnetpool = self.create_subnetpool(
                                            'test-pool-ext',
                                            is_admin=True,
                                            default_prefixlen=24,
                                            address_scope_id=addr_scope['id'],
                                            prefixes=['8.0.0.0/8'])
        tenant_subnetpool = self.create_subnetpool(
                                            'tenant-test-pool',
                                            default_prefixlen=25,
                                            address_scope_id=addr_scope['id'],
                                            prefixes=['10.10.0.0/16'])
        self.create_subnet({'id': ext_net['id']},
                           cidr=netaddr.IPNetwork('8.0.0.0/24'),
                           ip_version=4,
                           client=self.admin_client,
                           subnetpool_id=ext_subnetpool['id'])
        tenant_subnet = self.create_subnet(
                                       {'id': tenant_net['id']},
                                       cidr=netaddr.IPNetwork('10.10.0.0/24'),
                                       ip_version=4,
                                       subnetpool_id=tenant_subnetpool['id'])
        ext_gw_info = {'network_id': ext_net['id']}
        router = self.admin_client.create_router(
                                            'my-router',
                                            external_gateway_info=ext_gw_info,
                                            distributed=False)['router']
        self.admin_routers.append(router)
        self.admin_client.add_router_interface_with_subnet_id(
                                                       router['id'],
                                                       tenant_subnet['id'])
        self.admin_routerports.append({'router_id': router['id'],
                                       'subnet_id': tenant_subnet['id']})
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  ext_net['id'])
        routes = self.admin_client.get_bgp_advertised_routes(bgp_speaker_id)
        self.assertEqual(1, len(routes['advertised_routes']))
        self.assertEqual(tenant_subnet['cidr'],
                         routes['advertised_routes'][0]['destination'])
        fixed_ip = router['external_gateway_info']['external_fixed_ips'][0]
        self.assertEqual(fixed_ip['ip_address'],
                         routes['advertised_routes'][0]['next_hop'])
