# Copyright 2015 IBM Corp.
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

import os
import pprint

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fixture

from neutron import objects
from neutron.tests import base as test_base
from neutron.tests import tools


# NOTE: The hashes in this list should only be changed if they come with a
# corresponding version bump in the affected objects.
object_data = {
    'AddressScope': '1.0-25560799db384acfe1549634959a82b4',
    'DNSNameServer': '1.0-bf87a85327e2d812d1666ede99d9918b',
    'ExtraDhcpOpt': '1.0-632f689cbeb36328995a7aed1d0a78d3',
    'IPAllocationPool': '1.0-371016a6480ed0b4299319cb46d9215d',
    'PortSecurity': '1.0-cf5b382a0112080ec4e0f23f697c7ab2',
    'AllowedAddressPair': '1.0-9f9186b6f952fbf31d257b0458b852c0',
    'QosBandwidthLimitRule': '1.1-4e44a8f5c2895ab1278399f87b40a13d',
    'QosDscpMarkingRule': '1.1-0313c6554b34fd10c753cb63d638256c',
    'QosRuleType': '1.1-8a53fef4c6a43839d477a85b787d22ce',
    'QosPolicy': '1.1-7c5659e1c1f64395223592d3d3293e22',
    'Route': '1.0-a9883a63b416126f9e345523ec09483b',
    'Subnet': '1.0-3737cdae6fe084d0ea5e191ec64e806a',
    'SubnetPool': '1.0-e8300bfbc4762cc88a7f6205b52da2f8',
    'SubnetPoolPrefix': '1.0-13c15144135eb869faa4a76dc3ee3b6c',
    'SubPort': '1.0-72c8471068db1f0491b5480fe49b52bb',
    'Trunk': '1.0-ee3f16ebc40c16bda7be6dcd963895cc',
}


class TestObjectVersions(test_base.BaseTestCase):

    def setUp(self):
        super(TestObjectVersions, self).setUp()
        # NOTE(ihrachys): seed registry with all objects under neutron.objects
        # before validating the hashes
        tools.import_modules_recursively(os.path.dirname(objects.__file__))

    def test_versions(self):
        checker = fixture.ObjectVersionChecker(
            obj_base.VersionedObjectRegistry.obj_classes())
        fingerprints = checker.get_hashes()

        if os.getenv('GENERATE_HASHES'):
            file('object_hashes.txt', 'w').write(
                pprint.pformat(fingerprints))

        expected, actual = checker.test_hashes(object_data)
        self.assertEqual(expected, actual,
                         'Some objects have changed; please make sure the '
                         'versions have been bumped, and then update their '
                         'hashes in the object_data map in this test module.')
