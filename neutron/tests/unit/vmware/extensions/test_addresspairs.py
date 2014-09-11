# Copyright (c) 2014 OpenStack Foundation.
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

from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.tests.unit import test_extension_allowedaddresspairs as ext_pairs
from neutron.tests.unit.vmware import test_nsx_plugin


class TestAllowedAddressPairs(test_nsx_plugin.NsxPluginV2TestCase,
                              ext_pairs.TestAllowedAddressPairs):

    # TODO(arosen): move to ext_pairs.TestAllowedAddressPairs once all
    # plugins do this correctly.
    def test_create_port_no_allowed_address_pairs(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS], [])
            self._delete('ports', port['port']['id'])
