# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.services.bgp.driver import utils
from neutron.tests import base

FAKE_LOCAL_AS = 12345
FAKE_RYU_SPEAKER = {}


class TestBgpMultiSpeakerCache(base.BaseTestCase):

    def setUp(self):
        super(TestBgpMultiSpeakerCache, self).setUp()
        self.expected_cache = {FAKE_LOCAL_AS: FAKE_RYU_SPEAKER}
        self.bs_cache = utils.BgpMultiSpeakerCache()

    def test_put_bgp_speaker(self):
        self.bs_cache.put_bgp_speaker(FAKE_LOCAL_AS, FAKE_RYU_SPEAKER)
        self.assertEqual(self.expected_cache, self.bs_cache.cache)

    def test_remove_bgp_speaker(self):
        self.bs_cache.put_bgp_speaker(FAKE_LOCAL_AS, FAKE_RYU_SPEAKER)
        self.assertEqual(1, len(self.bs_cache.cache))
        self.bs_cache.remove_bgp_speaker(FAKE_LOCAL_AS)
        self.assertEqual(0, len(self.bs_cache.cache))

    def test_get_bgp_speaker(self):
        self.bs_cache.put_bgp_speaker(FAKE_LOCAL_AS, FAKE_RYU_SPEAKER)
        self.assertEqual(
            FAKE_RYU_SPEAKER,
            self.bs_cache.get_bgp_speaker(FAKE_LOCAL_AS))

    def test_get_hosted_bgp_speakers_count(self):
        self.bs_cache.put_bgp_speaker(FAKE_LOCAL_AS, FAKE_RYU_SPEAKER)
        self.assertEqual(1, self.bs_cache.get_hosted_bgp_speakers_count())
