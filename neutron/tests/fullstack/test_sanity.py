# Copyright 2015 Red Hat, Inc.
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

#TODO(jschwarz): This is an example test file which demonstrates the
# general usage of fullstack. Once we add more FullStack tests, this should
# be deleted.

from neutron.tests.fullstack import base


class TestSanity(base.BaseFullStackTestCase):

    def test_sanity(self):
        self.assertEqual(self.client.list_networks(), {'networks': []})
