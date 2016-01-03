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
from tempest.lib import exceptions as lib_exc

from neutron.tests.api import test_bgp_speaker_extensions as test_base
from tempest import test


class BgpSpeakerTestJSONNegative(test_base.BgpSpeakerTestJSONBase):

    """Negative test cases asserting proper behavior of BGP API extension"""

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('75e9ee2f-6efd-4320-bff7-ae24741c8b06')
    def test_create_bgp_speaker_illegal_local_asn(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_bgp_speaker,
                          local_as='65537')

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('6742ec2e-382a-4453-8791-13a19b47cd13')
    def test_create_bgp_speaker_non_admin(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.client.create_bgp_speaker,
                          {'bgp_speaker': self.default_bgp_speaker_args})

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('33f7aaf0-9786-478b-b2d1-a51086a50eb4')
    def test_create_bgp_peer_non_admin(self):
        self.assertRaises(lib_exc.Forbidden,
                          self.client.create_bgp_peer,
                          {'bgp_peer': self.default_bgp_peer_args})

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('39435932-0266-4358-899b-0e9b1e53c3e9')
    def test_update_bgp_speaker_local_asn(self):
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']

        self.assertRaises(lib_exc.BadRequest, self.update_bgp_speaker,
                          bgp_speaker_id, local_as='4321')

    @test.idempotent_id('9cc33701-51e5-421f-a5d5-fd7b330e550f')
    def test_get_advertised_routes_tenant_networks(self):
        addr_scope1 = self.create_address_scope('my-scope1', ip_version=4)
        addr_scope2 = self.create_address_scope('my-scope2', ip_version=4)
        ext_net = self.create_shared_network(**{'router:external': True})
        tenant_net1 = self.create_network()
        tenant_net2 = self.create_network()
        ext_subnetpool = self.create_subnetpool(
                                           'test-pool-ext',
                                           is_admin=True,
                                           default_prefixlen=24,
                                           address_scope_id=addr_scope1['id'],
                                           prefixes=['8.0.0.0/8'])
        tenant_subnetpool1 = self.create_subnetpool(
                                           'tenant-test-pool',
                                           default_prefixlen=25,
                                           address_scope_id=addr_scope1['id'],
                                           prefixes=['10.10.0.0/16'])
        tenant_subnetpool2 = self.create_subnetpool(
                                           'tenant-test-pool',
                                           default_prefixlen=25,
                                           address_scope_id=addr_scope2['id'],
                                           prefixes=['11.10.0.0/16'])
        self.create_subnet({'id': ext_net['id']},
                           cidr=netaddr.IPNetwork('8.0.0.0/24'),
                           ip_version=4,
                           client=self.admin_client,
                           subnetpool_id=ext_subnetpool['id'])
        tenant_subnet1 = self.create_subnet(
                                       {'id': tenant_net1['id']},
                                       cidr=netaddr.IPNetwork('10.10.0.0/24'),
                                       ip_version=4,
                                       subnetpool_id=tenant_subnetpool1['id'])
        tenant_subnet2 = self.create_subnet(
                                       {'id': tenant_net2['id']},
                                       cidr=netaddr.IPNetwork('11.10.0.0/24'),
                                       ip_version=4,
                                       subnetpool_id=tenant_subnetpool2['id'])
        ext_gw_info = {'network_id': ext_net['id']}
        router = self.admin_client.create_router(
                                  'my-router',
                                  distributed=False,
                                  external_gateway_info=ext_gw_info)['router']
        self.admin_routers.append(router)
        self.admin_client.add_router_interface_with_subnet_id(
                                                       router['id'],
                                                       tenant_subnet1['id'])
        self.admin_routerports.append({'router_id': router['id'],
                                       'subnet_id': tenant_subnet1['id']})
        self.admin_client.add_router_interface_with_subnet_id(
                                                       router['id'],
                                                       tenant_subnet2['id'])
        self.admin_routerports.append({'router_id': router['id'],
                                       'subnet_id': tenant_subnet2['id']})
        bgp_speaker = self.create_bgp_speaker(**self.default_bgp_speaker_args)
        bgp_speaker_id = bgp_speaker['bgp-speaker']['id']
        self.admin_client.add_bgp_gateway_network(bgp_speaker_id,
                                                  ext_net['id'])
        routes = self.admin_client.get_bgp_advertised_routes(bgp_speaker_id)
        self.assertEqual(1, len(routes['advertised_routes']))
        self.assertEqual(tenant_subnet1['cidr'],
                         routes['advertised_routes'][0]['destination'])
        fixed_ip = router['external_gateway_info']['external_fixed_ips'][0]
        self.assertEqual(fixed_ip['ip_address'],
                         routes['advertised_routes'][0]['next_hop'])
