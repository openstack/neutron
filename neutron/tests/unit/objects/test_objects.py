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

from neutron.common import utils
from neutron import objects
from neutron.tests import base as test_base


# NOTE: The hashes in this list should only be changed if they come with a
# corresponding version bump in the affected objects. Please keep the list in
# alphabetic order.
object_data = {
    '_DefaultSecurityGroup': '1.0-971520cb2e0ec06d747885a0cf78347f',
    'AddressScope': '1.0-dd0dfdb67775892d3adc090e28e43bd8',
    'Agent': '1.0-7106cb40117a8d1f042545796ed8787d',
    'AllowedAddressPair': '1.0-9f9186b6f952fbf31d257b0458b852c0',
    'AutoAllocatedTopology': '1.0-74642e58c53bf3610dc224c59f81b242',
    'DistributedPortBinding': '1.0-39c0d17b281991dcb66716fee5a8bef2',
    'DNSNameServer': '1.0-bf87a85327e2d812d1666ede99d9918b',
    'ExtraDhcpOpt': '1.0-632f689cbeb36328995a7aed1d0a78d3',
    'FlatAllocation': '1.0-bf666f24f4642b047eeca62311fbcb41',
    'Flavor': '1.0-82194de5c9aafce08e8527bb7977f5c6',
    'FlavorServiceProfileBinding': '1.0-a2c8731e16cefdac4571f80abf1f8930',
    'FloatingIPDNS': '1.0-ee3db848500fa1825235f701828c06d5',
    'GeneveAllocation': '1.0-d5f76e8eac60a778914d61dd8e23e90f',
    'GeneveEndpoint': '1.0-040f026996b5952e2ae4ccd40ac61ca6',
    'GreAllocation': '1.0-9ee1bbc4d999bea84c99425484b11ac5',
    'GreEndpoint': '1.0-040f026996b5952e2ae4ccd40ac61ca6',
    'IPAllocation': '1.0-47251b4c6d45c3b5feb0297fe5c461f2',
    'IPAllocationPool': '1.0-371016a6480ed0b4299319cb46d9215d',
    'IpamAllocation': '1.0-ace65431abd0a7be84cc4a5f32d034a3',
    'IpamAllocationPool': '1.0-c4fa1460ed1b176022ede7af7d1510d5',
    'IpamSubnet': '1.0-713de401682a70f34891e13af645fa08',
    'Network': '1.0-f2f6308f79731a767b92b26b0f4f3849',
    'NetworkDNSDomain': '1.0-420db7910294608534c1e2e30d6d8319',
    'NetworkPortSecurity': '1.0-b30802391a87945ee9c07582b4ff95e3',
    'NetworkSegment': '1.0-40707ef6bd9a0bf095038158d995cc7d',
    'Port': '1.0-638f6b09a3809ebd8b2b46293f56871b',
    'PortBinding': '1.0-3306deeaa6deb01e33af06777d48d578',
    'PortBindingLevel': '1.0-de66a4c61a083b8f34319fa9dde5b060',
    'PortDNS': '1.0-201cf6d057fde75539c3d1f2bbf05902',
    'PortSecurity': '1.0-b30802391a87945ee9c07582b4ff95e3',
    'ProviderResourceAssociation': '1.0-05ab2d5a3017e5ce9dd381328f285f34',
    'ProvisioningBlock': '1.0-c19d6d05bfa8143533471c1296066125',
    'QosBandwidthLimitRule': '1.2-4e44a8f5c2895ab1278399f87b40a13d',
    'QosDscpMarkingRule': '1.2-0313c6554b34fd10c753cb63d638256c',
    'QosMinimumBandwidthRule': '1.2-314c3419f4799067cc31cc319080adff',
    'QosRuleType': '1.2-e6fd08fcca152c339cbd5e9b94b1b8e7',
    'QosPolicy': '1.4-50460f619c34428ec5651916e938e5a0',
    'Route': '1.0-a9883a63b416126f9e345523ec09483b',
    'RouterExtraAttributes': '1.0-ef8d61ae2864f0ec9af0ab7939cab318',
    'RouterRoute': '1.0-07fc5337c801fb8c6ccfbcc5afb45907',
    'SecurityGroup': '1.0-e26b90c409b31fd2e3c6fcec402ac0b9',
    'SecurityGroupRule': '1.0-e9b8dace9d48b936c62ad40fe1f339d5',
    'SegmentHostMapping': '1.0-521597cf82ead26217c3bd10738f00f0',
    'ServiceProfile': '1.0-9beafc9e7d081b8258f3c5cb66ac5eed',
    'Subnet': '1.0-9c19023a61b42d29fbf3766df380e5b7',
    'SubnetPool': '1.0-a0e03895d1a6e7b9d4ab7b0ca13c3867',
    'SubnetPoolPrefix': '1.0-13c15144135eb869faa4a76dc3ee3b6c',
    'SubnetServiceType': '1.0-05ae4cdb2a9026a697b143926a1add8c',
    'SubPort': '1.0-72c8471068db1f0491b5480fe49b52bb',
    'Trunk': '1.1-aa3922b39e37fbb89886c2ee8715cf49',
    'VlanAllocation': '1.0-72636c1b7d5c8eef987bd09666e64f3e',
    'VxlanAllocation': '1.0-934638cd32d00f81d6fbf93c8eb5755a',
    'VxlanEndpoint': '1.0-40522eafdcf838758711dfa886cbdb2e',
}


class TestObjectVersions(test_base.BaseTestCase):

    def setUp(self):
        super(TestObjectVersions, self).setUp()
        # NOTE(ihrachys): seed registry with all objects under neutron.objects
        # before validating the hashes
        utils.import_modules_recursively(os.path.dirname(objects.__file__))

    def test_versions(self):
        checker = fixture.ObjectVersionChecker(
            obj_base.VersionedObjectRegistry.obj_classes())
        fingerprints = checker.get_hashes()

        if os.getenv('GENERATE_HASHES'):
            with open('object_hashes.txt', 'w') as hashes_file:
                hashes_file.write(pprint.pformat(fingerprints))

        expected, actual = checker.test_hashes(object_data)
        self.assertEqual(expected, actual,
                         'Some objects have changed; please make sure the '
                         'versions have been bumped, and then update their '
                         'hashes in the object_data map in this test module.')
