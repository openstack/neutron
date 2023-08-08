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

from oslo_versionedobjects import fixture

from neutron import objects
from neutron.objects import base
from neutron.tests import base as test_base


# NOTE: The hashes in this list should only be changed if they come with a
# corresponding version bump in the affected objects. Please keep the list in
# alphabetic order.
object_data = {
    'AddressAssociation': '1.0-b92160a3dd2fb7b951adcd2e6ae1665a',
    'AddressGroup': '1.2-1ddbf0a9f61785033ce31818ac62687e',
    'AddressGroupRBAC': '1.1-be82ed54376b85ee4f963d479ac48c91',
    'AddressScope': '1.1-dd0dfdb67775892d3adc090e28e43bd8',
    'AddressScopeRBAC': '1.1-be82ed54376b85ee4f963d479ac48c91',
    'Agent': '1.1-64b670752d57b3c7602cb136e0338507',
    'AllowedAddressPair': '1.0-9f9186b6f952fbf31d257b0458b852c0',
    'AutoAllocatedTopology': '1.0-74642e58c53bf3610dc224c59f81b242',
    'ConntrackHelper': '1.0-b1a50cfe18178db50c7f206e75613f4b',
    'DefaultSecurityGroup': '1.0-971520cb2e0ec06d747885a0cf78347f',
    'DistributedPortBinding': '1.0-39c0d17b281991dcb66716fee5a8bef2',
    'DNSNameServer': '1.0-bf87a85327e2d812d1666ede99d9918b',
    'ExternalNetwork': '1.0-53d885e033cb931f9bb3bdd6bbe3f0ce',
    'DvrFipGatewayPortAgentBinding': '1.0-ee2af3296265a5463de0bc3695b35b51',
    'DVRMacAddress': '1.0-d3c61a8338d20da74db2364d4d6554f2',
    'ExtraDhcpOpt': '1.1-8f5639ccbe4eb2173a185183d34c01e7',
    'FlatAllocation': '1.0-bf666f24f4642b047eeca62311fbcb41',
    'Flavor': '1.0-82194de5c9aafce08e8527bb7977f5c6',
    'FlavorServiceProfileBinding': '1.0-a2c8731e16cefdac4571f80abf1f8930',
    'FloatingIP': '1.2-fb6675ea98d2a37e5883dc5962ec401c',
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
    'L3HARouterAgentPortBinding': '1.0-d1d7ee13f35d56d7e225def980612ee5',
    'L3HARouterNetwork': '1.0-87acea732853f699580179a94d2baf91',
    'L3HARouterVRIdAllocation': '1.0-37502aebdbeadc4f9e3bd5e9da714ab9',
    'LocalIP': '1.0-85843868a01585c4e2614f2f635159ca',
    'LocalIPAssociation': '1.0-4febb23ad22f11a69c431b077b3aac21',
    'MeteringLabel': '1.0-cc4b620a3425222447cbe459f62de533',
    'MeteringLabelRule': '2.0-0ad09894c62e1ce6e868f725158959ba',
    'Log': '1.0-6391351c0f34ed34375a19202f361d24',
    'NDPProxy': '1.0-a6597d9caac3bb0d63f943f82e4dda8c',
    'Network': '1.1-c3e9ecc0618ee934181d91b143a48901',
    'NetworkDhcpAgentBinding': '1.1-d9443c88809ffa4c45a0a5a48134b54a',
    'NetworkDNSDomain': '1.0-420db7910294608534c1e2e30d6d8319',
    'NetworkPortSecurity': '1.0-b30802391a87945ee9c07582b4ff95e3',
    'NetworkRBAC': '1.3-be82ed54376b85ee4f963d479ac48c91',
    'NetworkSegment': '1.0-57b7f2960971e3b95ded20cbc59244a8',
    'NetworkSegmentRange': '1.0-bdec1fffc9058ea676089b1f2f2b3cf3',
    'NetworkSubnetLock': '1.0-140de39d4b86ae346dc3d70b885bea53',
    'Port': '1.8-1aa850ab5529128de07e82c6fb75fcb5',
    'PortDeviceProfile': '1.0-b98c7083cc3e93d176fd7a91ae13af32',
    'PortHints': '1.0-9ebf6e12fa427809476a92c7432352b8',
    'PortNumaAffinityPolicy': '1.0-38fcea43e7bfb2536461f3d053c43aa3',
    'PortBinding': '1.0-3306deeaa6deb01e33af06777d48d578',
    'PortBindingLevel': '1.1-50d47f63218f87581b6cd9a62db574e5',
    'PortDataPlaneStatus': '1.0-25be74bda46c749653a10357676c0ab2',
    'PortDNS': '1.1-c5ca2dc172bdd5fafee3fc986d1d7023',
    'PortForwarding': '1.3-402b1fb5a754808b82a966c95f468113',
    'PortSecurity': '1.0-b30802391a87945ee9c07582b4ff95e3',
    'PortUplinkStatusPropagation': '1.1-f0a4ca451a941910376c33616dea5de2',
    'ProviderResourceAssociation': '1.0-05ab2d5a3017e5ce9dd381328f285f34',
    'ProvisioningBlock': '1.0-c19d6d05bfa8143533471c1296066125',
    'QosBandwidthLimitRule': '1.5-51b662b12a8d1dfa89288d826c6d26d3',
    'QosDscpMarkingRule': '1.5-0313c6554b34fd10c753cb63d638256c',
    'QosMinimumBandwidthRule': '1.5-314c3419f4799067cc31cc319080adff',
    'QosMinimumPacketRateRule': '1.5-d0516c55aa2f310a2646c7d243cb8620',
    'QosPacketRateLimitRule': '1.5-18411fa95f54602b8c8a5da2d3194b31',
    'QosPolicyRBAC': '1.2-be82ed54376b85ee4f963d479ac48c91',
    'QosRuleType': '1.5-ea51a164013e05d5956d8bf538622b33',
    'QosRuleTypeDriver': '1.0-7d8cb9f0ef661ac03700eae97118e3db',
    'QosPolicy': '1.10-4adb0cde3102c10d8970ec9487fd7fe7',
    'QosPolicyDefault': '1.0-59e5060eedb1f06dd0935a244d27d11c',
    'QosPolicyFloatingIPBinding': '1.0-5625df4205a18778cd6aa40f99be024e',
    'QosPolicyRouterGatewayIPBinding': '1.0-da064fbfe5ee18c950b905b483bf59e3',
    'QosPolicyNetworkBinding': '1.0-df53a1e0f675aab8d27a1ccfed38dc42',
    'QosPolicyPortBinding': '1.0-66cb364ac99aa64523ade07f9f868ea6',
    'Quota': '1.0-6bb6a0f1bd5d66a2134ffa1a61873097',
    'QuotaUsage': '1.0-6fbf820368681aac7c5d664662605cf9',
    'Reservation': '1.0-49929fef8e82051660342eed51b48f2a',
    'ResourceDelta': '1.0-a980b37e0a52618b5af8db29af18be76',
    'Route': '1.0-a9883a63b416126f9e345523ec09483b',
    'Router': '1.1-614fa16cc99c60e4fc19ac1b31a52291',
    'RouterExtraAttributes': '1.1-19c45c32098d2aae8e1a22d18944a954',
    'RouterL3AgentBinding': '1.0-c5ba6c95e3a4c1236a55f490cd67da82',
    'RouterNDPProxyState': '1.0-4042e475bf173d1d8d17adb962eae1b2',
    'RouterPort': '1.0-c8c8f499bcdd59186fcd83f323106908',
    'RouterRoute': '1.0-07fc5337c801fb8c6ccfbcc5afb45907',
    'SecurityGroup': '1.5-7eb8e44c327512e7bb1759ab41ede44b',
    'SecurityGroupDefaultRule': '1.0-d498fd4993b6732f3f266c4b7e292e22',
    'SecurityGroupPortBinding': '1.0-6879d5c0af80396ef5a72934b6a6ef20',
    'SecurityGroupRBAC': '1.1-be82ed54376b85ee4f963d479ac48c91',
    'SecurityGroupRule': '1.2-27793368d4ac35f2ed6e0bb653c6aaad',
    'SegmentHostMapping': '1.0-521597cf82ead26217c3bd10738f00f0',
    'ServiceProfile': '1.0-9beafc9e7d081b8258f3c5cb66ac5eed',
    'StandardAttribute': '1.0-617d4f46524c4ce734a6fc1cc0ac6a0b',
    'Subnet': '1.1-5b7e1789a1732259d1e28b4bd87eb1c2',
    'SubnetDNSPublishFixedIP': '1.0-db22af6fa20b143986f0cbe06cbfe0ea',
    'SubnetPool': '1.1-a0e03895d1a6e7b9d4ab7b0ca13c3867',
    'SubnetPoolPrefix': '1.0-13c15144135eb869faa4a76dc3ee3b6c',
    'SubnetPoolRBAC': '1.1-be82ed54376b85ee4f963d479ac48c91',
    'SubnetServiceType': '1.0-05ae4cdb2a9026a697b143926a1add8c',
    'SubPort': '1.0-72c8471068db1f0491b5480fe49b52bb',
    'Tag': '1.0-1a0d20379920ffa3cebfd3e016d2f7a0',
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
        objects.register_objects()

    def test_versions(self):
        checker = fixture.ObjectVersionChecker(
            base.NeutronObjectRegistry.obj_classes())
        fingerprints = checker.get_hashes()

        if os.getenv('GENERATE_HASHES'):
            with open('object_hashes.txt', 'w') as hashes_file:
                hashes_file.write(pprint.pformat(fingerprints))

        expected, actual = checker.test_hashes(object_data)
        self.assertEqual(expected, actual,
                         'Some objects have changed; please make sure the '
                         'versions have been bumped, and then update their '
                         'hashes in the object_data map in this test module.')
