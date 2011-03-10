# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Shweta Padubidri, Cisco Systems, Inc.
#

import logging
import unittest

from quantum.plugins.cisco.ucs import cisco_ucs_network_driver

LOG = logging.getLogger('quantum.tests.test_ucs_driver')

CREATE_VLAN_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"true\"> <inConfigs><pair key=\"fabric/lan/net-New Vlan\"> "\
"<fabricVlan defaultNet=\"no\" dn=\"fabric/lan/net-New Vlan\" id=\"200\" "\
"name=\"New Vlan\" status=\"created\"></fabricVlan> </pair> </inConfigs> "\
"</configConfMos>"

CREATE_PROFILE_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"true\"> <inConfigs><pair key=\"fabric/lan/profiles/vnic-"\
"New Profile\"> <vnicProfile descr=\"Profile created by Cisco OpenStack "\
"Quantum Plugin\" dn=\"fabric/lan/profiles/vnic-New Profile\" maxPorts="\
"\"64\" name=\"New Profile\" nwCtrlPolicyName=\"\" pinToGroupName=\"\" "\
"qosPolicyName=\"\" status=\"created\"> <vnicEtherIf defaultNet=\"yes\" "\
"name=\"New Vlan\" rn=\"if-New Vlan\" > </vnicEtherIf> </vnicProfile> "\
"</pair> </inConfigs> </configConfMos>"

CHANGE_VLAN_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"true\"> <inConfigs><pair key=\""\
"fabric/lan/profiles/vnic-New Profile\"> <vnicProfile descr=\"Profile "\
"created by Cisco OpenStack Quantum Plugin\" "\
"dn=\"fabric/lan/profiles/vnic-New Profile\" maxPorts=\"64\" "\
"name=\"New Profile\" nwCtrlPolicyName=\"\" pinToGroupName=\"\" "\
"qosPolicyName=\"\" status=\"created,modified\"><vnicEtherIf "\
"rn=\"if-Old Vlan\" status=\"deleted\"> </vnicEtherIf> "\
"<vnicEtherIf defaultNet=\"yes\" name=\"New Vlan\" rn=\"if-New Vlan\" > "\
"</vnicEtherIf> </vnicProfile> </pair></inConfigs> </configConfMos>"

DELETE_VLAN_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"true\"> <inConfigs><pair key=\"fabric/lan/net-New Vlan\"> "\
"<fabricVlan dn=\"fabric/lan/net-New Vlan\" status=\"deleted\"> "\
"</fabricVlan> </pair> </inConfigs></configConfMos>"

DELETE_PROFILE_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"false\"> <inConfigs><pair key=\""\
"fabric/lan/profiles/vnic-New Profile\"> <vnicProfile "\
"dn=\"fabric/lan/profiles/vnic-New Profile\" status=\"deleted\"> "\
"</vnicProfile></pair> </inConfigs> </configConfMos>"

ASSOCIATE_PROFILE_OUTPUT = "<configConfMos cookie=\"cookie_placeholder\" "\
"inHierarchical=\"true\"> <inConfigs> <pair key="\
"\"fabric/lan/profiles/vnic-New Profile/cl-New Profile Client\">"\
" <vmVnicProfCl dcName=\".*\" descr=\"\" dn=\"fabric/lan/profiles/vnic-"\
"New Profile/cl-New Profile Client\"name=\"New Profile Client\" "\
"orgPath=\".*\" status=\"created\" swName=\"default$\"> </vmVnicProfCl>" \
"</pair> </inConfigs> </configConfMos>"


class TestUCSDriver(unittest.TestCase):

    def setUp(self):
        """ Set up function"""
        self.ucsm_driver = cisco_ucs_network_driver.CiscoUCSMDriver()
        self.vlan_name = 'New Vlan'
        self.vlan_id = '200'
        self.profile_name = 'New Profile'
        self.old_vlan_name = 'Old Vlan'
        self.profile_client_name = 'New Profile Client'

    def test_create_vlan_post_data(self, expected_output=CREATE_VLAN_OUTPUT):
        """
        Tests creation of vlan post Data
        """

        LOG.debug("test_create_vlan")
        vlan_details = self.ucsm_driver._create_vlan_post_data(
                                self.vlan_name, self.vlan_id)
        self.assertEqual(vlan_details, expected_output)
        LOG.debug("test_create_vlan - END")

    def test_create_profile_post_data(
                self, expected_output=CREATE_PROFILE_OUTPUT):
        """
        Tests creation of profile post Data
        """

        LOG.debug("test_create_profile_post_data - START")
        profile_details = self.ucsm_driver._create_profile_post_data(
                                self.profile_name, self.vlan_name)
        self.assertEqual(profile_details, expected_output)
        LOG.debug("test_create_profile_post - END")

    def test_change_vlan_profile_data(
                self, expected_output=CHANGE_VLAN_OUTPUT):
        """
        Tests creation of change vlan in profile post Data
        """

        LOG.debug("test_create_profile_post_data - START")
        profile_details = self.ucsm_driver._change_vlaninprof_post_data(
                        self.profile_name, self.old_vlan_name, self.vlan_name)
        self.assertEqual(profile_details, expected_output)
        LOG.debug("test_create_profile_post - END")

    def test_delete_vlan_post_data(self, expected_output=DELETE_VLAN_OUTPUT):
        """
        Tests deletion of vlan post Data
        """

        LOG.debug("test_create_profile_post_data - START")

        self.ucsm_driver._create_vlan_post_data(
                                self.vlan_name, self.vlan_id)
        vlan_delete_details = self.ucsm_driver._delete_vlan_post_data(
                                                self.vlan_name)
        self.assertEqual(vlan_delete_details, expected_output)
        LOG.debug("test_create_profile_post - END")

    def test_delete_profile_post_data(
                        self, expected_output=DELETE_PROFILE_OUTPUT):
        """
        Tests deletion of profile post Data
        """

        LOG.debug("test_create_profile_post_data - START")
        self.ucsm_driver._create_profile_post_data(
                                self.profile_name, self.vlan_name)
        profile_delete_details = self.ucsm_driver._delete_profile_post_data(
                                        self.profile_name)
        self.assertEqual(profile_delete_details, expected_output)
        LOG.debug("test_create_profile_post - END")

    def test_create_profile_client_data(
                        self, expected_output=ASSOCIATE_PROFILE_OUTPUT):
        """
        Tests creation of profile client post Data
        """

        LOG.debug("test_create_profile_client_data - START")
        profile_details = self.ucsm_driver._create_pclient_post_data(
                                self.profile_name, self.profile_client_name)
        self.assertEqual(profile_details, expected_output)
        LOG.debug("test_create_profile_post - END")
