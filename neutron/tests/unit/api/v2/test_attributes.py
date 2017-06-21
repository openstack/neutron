# Copyright 2012 OpenStack Foundation
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

from neutron.api.v2 import attributes
from neutron.tests import base


class TestHelpers(base.DietTestCase):

    def _verify_port_attributes(self, attrs):
        for test_attribute in ('id', 'name', 'mac_address', 'network_id',
                               'tenant_id', 'fixed_ips', 'status'):
            self.assertIn(test_attribute, attrs)

    def test_get_collection_info(self):
        attrs = attributes.get_collection_info('ports')
        self._verify_port_attributes(attrs)

    def test_get_collection_info_missing(self):
        self.assertFalse(attributes.get_collection_info('meh'))
