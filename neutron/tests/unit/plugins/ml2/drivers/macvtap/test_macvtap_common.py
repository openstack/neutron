# Copyright (c) 2016 IBM Corp.
#
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

import hashlib

from oslo_utils import encodeutils

from neutron.plugins.ml2.drivers.macvtap import macvtap_common as m_common
from neutron.tests import base


class MacvtapCommonTestCase(base.BaseTestCase):

    def _hash_prefix(self, value):
        hashed_name = hashlib.new('sha1', usedforsecurity=False)
        hashed_name.update(encodeutils.to_utf8(value))
        # only the first six chars of the hash are being used in the algorithm
        return hashed_name.hexdigest()[0:6]

    def test_get_vlan_device_name(self):
        self.assertEqual('10charrrrr.1',
                         m_common.get_vlan_device_name('10charrrrr', "1"))
        self.assertEqual('11ch' + self._hash_prefix('11charrrrrr') + '.1',
                         m_common.get_vlan_device_name('11charrrrrr', "1"))
        self.assertEqual('14ch' + self._hash_prefix('14charrrrrrrrr') + '.1',
                         m_common.get_vlan_device_name('14charrrrrrrrr', "1"))
        self.assertEqual(
            '14ch' + self._hash_prefix('14charrrrrrrrr') + '.1111',
            m_common.get_vlan_device_name('14charrrrrrrrr', "1111"))

    def test_get_vlan_subinterface_name_advanced(self):
        """Ensure the same hash is used for long interface names.

        If the generated vlan device name would be too long, make sure that
        everything before the '.' is equal. This might be helpful when
        debugging problems.
        """

        max_device_name = "15charrrrrrrrrr"
        vlan_dev_name1 = m_common.get_vlan_device_name(max_device_name,
                                                       "1")
        vlan_dev_name2 = m_common.get_vlan_device_name(max_device_name,
                                                       "1111")
        self.assertEqual(vlan_dev_name1.partition(".")[0],
                         vlan_dev_name2.partition(".")[0])
