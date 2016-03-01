# Copyright 2016 Hewlett Packard Enterprise Development Company LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import contextlib
from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc
from neutron.extensions import bgp
from neutron import manager
from neutron.plugins.common import constants as p_const
from neutron.services.bgp import bgp_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin

_uuid = uuidutils.generate_uuid

ADVERTISE_FIPS_KEY = 'advertise_floating_ip_host_routes'


class BgpEntityCreationMixin(object):

    @contextlib.contextmanager
    def bgp_speaker(self, ip_version, local_as, name='my-speaker',
                    advertise_fip_host_routes=True,
                    advertise_tenant_networks=True,
                    networks=None, peers=None):
        data = {'ip_version': ip_version,
                ADVERTISE_FIPS_KEY: advertise_fip_host_routes,
                'advertise_tenant_networks': advertise_tenant_networks,
                'local_as': local_as, 'name': name}
        bgp_speaker = self.bgp_plugin.create_bgp_speaker(self.context,
                                                        {'bgp_speaker': data})
        bgp_speaker_id = bgp_speaker['id']

        if networks:
            for network_id in networks:
                self.bgp_plugin.add_gateway_network(
                                                   self.context,
                                                   bgp_speaker_id,
                                                   {'network_id': network_id})
        if peers:
            for peer_id in peers:
                self.bgp_plugin.add_bgp_peer(self.context, bgp_speaker_id,
                                             {'bgp_peer_id': peer_id})

        yield self.bgp_plugin.get_bgp_speaker(self.context, bgp_speaker_id)

    @contextlib.contextmanager
    def bgp_peer(self, tenant_id=_uuid(), remote_as='4321',
                 peer_ip="192.168.1.1", auth_type="md5",
                 password="my-secret", name="my-peer"):
        data = {'peer_ip': peer_ip, 'tenant_id': tenant_id,
                'remote_as': remote_as, 'auth_type': auth_type,
                'password': password, 'name': name}
        bgp_peer = self.bgp_plugin.create_bgp_peer(self.context,
                                                   {'bgp_peer': data})
        yield bgp_peer
        self.bgp_plugin.delete_bgp_peer(self.context, bgp_peer['id'])


class BgpTests(test_plugin.Ml2PluginV2TestCase,
               BgpEntityCreationMixin):
    #FIXME(tidwellr) Lots of duplicated setup code, try to streamline
    fmt = 'json'

    def setUp(self):
        super(BgpTests, self).setUp()
        self.l3plugin = manager.NeutronManager.get_service_plugins().get(
            p_const.L3_ROUTER_NAT)
        self.bgp_plugin = bgp_plugin.BgpPlugin()
        self.plugin = manager.NeutronManager.get_plugin()

    @contextlib.contextmanager
    def subnetpool_with_address_scope(self, ip_version, prefixes=None,
                                      shared=False, admin=True,
                                      name='test-pool', is_default_pool=False,
                                      tenant_id=None, **kwargs):
        if not tenant_id:
            tenant_id = _uuid()

        scope_data = {'tenant_id': tenant_id, 'ip_version': ip_version,
                      'shared': shared, 'name': name + '-scope'}
        address_scope = self.plugin.create_address_scope(
                                                self.context,
                                                {'address_scope': scope_data})
        address_scope_id = address_scope['id']
        pool_data = {'tenant_id': tenant_id, 'shared': shared, 'name': name,
                     'address_scope_id': address_scope_id,
                     'prefixes': prefixes, 'is_default': is_default_pool}
        for key in kwargs:
            pool_data[key] = kwargs[key]

        yield self.plugin.create_subnetpool(self.context,
                                            {'subnetpool': pool_data})

    @contextlib.contextmanager
    def floatingip_from_address_scope_assoc(self, prefixes,
                                            address_scope_id,
                                            ext_prefixlen=24,
                                            int_prefixlen=24):
        pass

    def test_add_duplicate_bgp_peer_ip(self):
        peer_ip = '192.168.1.10'
        with self.bgp_peer(peer_ip=peer_ip) as peer1,\
            self.bgp_peer(peer_ip=peer_ip) as peer2,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:

            with self.bgp_speaker(sp['ip_version'], 1234,
                                  peers=[peer1['id']]) as speaker:
                self.assertRaises(bgp.DuplicateBgpPeerIpException,
                                  self.bgp_plugin.add_bgp_peer,
                                  self.context, speaker['id'],
                                  {'bgp_peer_id': peer2['id']})

    def test_bgpspeaker_create(self):
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            speaker_name = 'test-speaker'
            expected_values = [('ip_version', sp['ip_version']),
                               ('name', speaker_name)]
            with self.bgp_speaker(sp['ip_version'], 1234,
                                  name=speaker_name) as bgp_speaker:
                for k, v in expected_values:
                    self.assertEqual(v, bgp_speaker[k])

    def test_bgp_speaker_list(self):
        with self.subnetpool_with_address_scope(4,
                                              prefixes=['8.0.0.0/8']) as sp1,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['9.0.0.0/8']) as sp2:
            with self.bgp_speaker(sp1['ip_version'], 1234,
                                  name='speaker1'),\
                self.bgp_speaker(sp2['ip_version'], 4321,
                                 name='speaker2'):
                    speakers = self.bgp_plugin.get_bgp_speakers(self.context)
                    self.assertEqual(2, len(speakers))

    def test_bgp_speaker_update_local_as(self):
        local_as_1 = 1234
        local_as_2 = 4321
        with self.subnetpool_with_address_scope(4,
                                              prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], local_as_1) as speaker:
                self.assertEqual(local_as_1, speaker['local_as'])
                new_speaker = self.bgp_plugin.update_bgp_speaker(
                                                self.context,
                                                speaker['id'],
                                                {'bgp_speaker':
                                                    {'local_as': local_as_2}})
                self.assertEqual(local_as_2, new_speaker['local_as'])

    def test_bgp_speaker_show_non_existent(self):
        self.assertRaises(bgp.BgpSpeakerNotFound,
                          self.bgp_plugin.get_bgp_speaker,
                          self.context, _uuid())

    def test_create_bgp_peer(self):
        args = {'tenant_id': _uuid(),
                'remote_as': '1111',
                'peer_ip': '10.10.10.10',
                'auth_type': 'md5'}
        with self.bgp_peer(tenant_id=args['tenant_id'],
                           remote_as=args['remote_as'],
                           peer_ip=args['peer_ip'],
                           auth_type='md5',
                           password='my-secret') as peer:
            self.assertIsNone(peer.get('password'))
            for key in args:
                self.assertEqual(args[key], peer[key])

    def test_bgp_peer_show_non_existent(self):
        self.assertRaises(bgp.BgpPeerNotFound,
                          self.bgp_plugin.get_bgp_peer,
                          self.context,
                          'unreal-bgp-peer-id')

    def test_associate_bgp_peer(self):
        with self.bgp_peer() as peer,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.bgp_plugin.add_bgp_peer(self.context, speaker['id'],
                                             {'bgp_peer_id': peer['id']})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertIn('peers', new_speaker)
                self.assertIn(peer['id'], new_speaker['peers'])
                self.assertEqual(1, len(new_speaker['peers']))

    def test_remove_bgp_peer(self):
        with self.bgp_peer() as peer,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234,
                                  peers=[peer['id']]) as speaker:
                self.bgp_plugin.remove_bgp_peer(self.context, speaker['id'],
                                                {'bgp_peer_id': peer['id']})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertIn('peers', new_speaker)
                self.assertTrue(not new_speaker['peers'])

    def test_remove_unassociated_bgp_peer(self):
        with self.bgp_peer() as peer,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(bgp.BgpSpeakerPeerNotAssociated,
                                  self.bgp_plugin.remove_bgp_peer,
                                  self.context,
                                  speaker['id'],
                                  {'bgp_peer_id': peer['id']})

    def test_remove_non_existent_bgp_peer(self):
        bgp_peer_id = "imaginary"
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(bgp.BgpSpeakerPeerNotAssociated,
                                  self.bgp_plugin.remove_bgp_peer,
                                  self.context,
                                  speaker['id'],
                                  {'bgp_peer_id': bgp_peer_id})

    def test_add_non_existent_bgp_peer(self):
        bgp_peer_id = "imaginary"
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(bgp.BgpPeerNotFound,
                                  self.bgp_plugin.add_bgp_peer,
                                  self.context,
                                  speaker['id'],
                                  {'bgp_peer_id': bgp_peer_id})

    def test_add_gateway_network(self):
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker,\
                self.network() as network:
                network_id = network['network']['id']
                self.bgp_plugin.add_gateway_network(self.context,
                                                   speaker['id'],
                                                   {'network_id': network_id})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertEqual(1, len(new_speaker['networks']))
                self.assertTrue(network_id in new_speaker['networks'])

    def test_create_bgp_speaker_with_network(self):
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            network = self.plugin.create_network(self.context,
                                                {'network':
                                                    {'name': 'test-net',
                                                     'tenant_id': _uuid(),
                                                     'admin_state_up': True,
                                                     'shared': True}})
            with self.bgp_speaker(sp['ip_version'], 1234,
                                  networks=[network['id']]) as speaker:
                self.assertEqual(1, len(speaker['networks']))
                self.assertTrue(network['id'] in speaker['networks'])

    def test_remove_gateway_network(self):
        with self.network() as network,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:
            network_id = network['network']['id']
            with self.bgp_speaker(sp['ip_version'], 1234,
                                  networks=[network_id]) as speaker:
                self.bgp_plugin.remove_gateway_network(
                                                self.context,
                                                speaker['id'],
                                                {'network_id': network_id})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertEqual(0, len(new_speaker['networks']))

    def test_add_non_existent_gateway_network(self):
        network_id = "imaginary"
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(n_exc.NetworkNotFound,
                                  self.bgp_plugin.add_gateway_network,
                                  self.context, speaker['id'],
                                  {'network_id': network_id})

    def test_remove_non_existent_gateway_network(self):
        network_id = "imaginary"
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(bgp.BgpSpeakerNetworkNotAssociated,
                                  self.bgp_plugin.remove_gateway_network,
                                  self.context, speaker['id'],
                                  {'network_id': network_id})

    def test_add_gateway_network_two_bgp_speakers_same_scope(self):
        with self.subnetpool_with_address_scope(4,
                                                prefixes=['8.0.0.0/8']) as sp:
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker1,\
                self.bgp_speaker(sp['ip_version'], 4321) as speaker2,\
                self.network() as network:
                network_id = network['network']['id']
                self.bgp_plugin.add_gateway_network(self.context,
                                                   speaker1['id'],
                                                   {'network_id': network_id})
                self.bgp_plugin.add_gateway_network(self.context,
                                                   speaker2['id'],
                                                   {'network_id': network_id})
                speaker1 = self.bgp_plugin.get_bgp_speaker(self.context,
                                                           speaker1['id'])
                speaker2 = self.bgp_plugin.get_bgp_speaker(self.context,
                                                           speaker2['id'])
                for speaker in [speaker1, speaker2]:
                    self.assertEqual(1, len(speaker['networks']))
                    self.assertEqual(network_id,
                                     speaker['networks'][0])

    def test_create_bgp_peer_md5_auth_no_password(self):
        bgp_peer = {'bgp_peer': {'auth_type': 'md5', 'password': None}}
        self.assertRaises(bgp.InvalidBgpPeerMd5Authentication,
                          self.bgp_plugin.create_bgp_peer,
                          self.context, bgp_peer)
