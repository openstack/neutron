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
