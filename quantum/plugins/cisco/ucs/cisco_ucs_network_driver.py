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
# @author: Sumit Naiksatam, Cisco Systems Inc.
#

"""
Implements a UCSM XML API Client
"""

import httplib
import logging
from xml.etree import ElementTree as et

from quantum.plugins.cisco.common import cisco_constants as const


LOG = logging.getLogger(__name__)


COOKIE_VALUE = "cookie_placeholder"
PROFILE_NAME = "profilename_placeholder"
PROFILE_CLIENT = "profileclient_placeholder"
VLAN_NAME = "vlanname_placeholder"
VLAN_ID = "vlanid_placeholder"
OLD_VLAN_NAME = "old_vlanname_placeholder"
BLADE_VALUE = "blade_number_placeholder"
BLADE_DN_VALUE = "blade_dn_placeholder"
CHASSIS_VALUE = "chassis_number_placeholder"
DYNAMIC_NIC_PREFIX = "eth"

# The following are standard strings, messages used to communicate with UCSM,
#only place holder values change for each message
HEADERS = {"Content-Type": "text/xml"}
METHOD = "POST"
URL = "/nuova"

CREATE_VLAN = ('<configConfMos cookie="' + COOKIE_VALUE +
               '" inHierarchical="true"> <inConfigs>'
               '<pair key="fabric/lan/net-"' + VLAN_NAME +
               '"> <fabricVlan defaultNet="no" '
               'dn="fabric/lan/net-' + VLAN_NAME +
               '" id="' + VLAN_ID + '" name="' +
               VLAN_NAME + '" status="created">'
               '</fabricVlan> </pair> </inConfigs> </configConfMos>')

CREATE_PROFILE = ('<configConfMos cookie="' + COOKIE_VALUE +
                  '" inHierarchical="true"> <inConfigs>'
                  '<pair key="fabric/lan/profiles/vnic-' + PROFILE_NAME +
                  '"> <vnicProfile descr="Profile created by '
                  'Cisco OpenStack Quantum Plugin" '
                  'dn="fabric/lan/profiles/vnic' + PROFILE_NAME +
                  '" maxPorts="64" name="' + PROFILE_NAME +
                  '" nwCtrlPolicyName="" pinToGroupName="" '
                  'qosPolicyName="" status="created"> '
                  '<vnicEtherIf defaultNet="yes" name="' + VLAN_NAME +
                  '" rn="if' + VLAN_NAME + '" > </vnicEtherIf> '
                  '</vnicProfile> </pair> </inConfigs> </configConfMos>')

ASSOCIATE_PROFILE = ('<configConfMos cookie="' + COOKIE_VALUE +
                     '" inHierarchical="true"> <inConfigs> <pair '
                     'key="fabric/lan/profiles/vnic' + PROFILE_NAME +
                     '/cl' + PROFILE_CLIENT + '"> <vmVnicProfCl dcName=".*" '
                     'descr="" dn="fabric/lan/profiles/vnic' +
                     PROFILE_NAME + '/cl' + PROFILE_CLIENT +
                     '"name="' + PROFILE_CLIENT + '" orgPath=".*" '
                     'status="created" swName="default$"> </vmVnicProfCl>'
                     '</pair> </inConfigs> </configConfMos>')

CHANGE_VLAN_IN_PROFILE = ('<configConfMos cookie="' + COOKIE_VALUE +
                          '" inHierarchical="true"> <inConfigs'
                          '<pair key="fabric/lan/profiles/vnic' +
                          PROFILE_NAME + '"> <vnicProfile descr="Profile'
                          'created by Cisco OpenStack Quantum Plugin"'
                          'dn="fabric/lan/profiles/vnic' +
                          PROFILE_NAME + '" maxPorts="64" name="' +
                          PROFILE_NAME + '" nwCtrlPolicyName=""'
                          'pinToGroupName="" qosPolicyName=""'
                          'status="created,modified"'
                          '<vnicEtherIf rn="if' + OLD_VLAN_NAME +
                          '" status="deleted"> </vnicEtherIf> <vnicEtherIf'
                          'defaultNet="yes" name="' +
                          VLAN_NAME + '" rn="if' + VLAN_NAME +
                          '" > </vnicEtherIf> </vnicProfile> </pair'
                          '</inConfigs> </configConfMos>')

DELETE_VLAN = ('<configConfMos cookie="' + COOKIE_VALUE +
               '" inHierarchical="true"> <inConfigs'
               '<pair key="fabric/lan/net' + VLAN_NAME +
               '"> <fabricVlan dn="fabric/lan/net' + VLAN_NAME +
               '" status="deleted"> </fabricVlan> </pair> </inConfigs'
               '</configConfMos')

DELETE_PROFILE = ('<configConfMos cookie="' + COOKIE_VALUE +
                  '" inHierarchical="false"> <inConfigs'
                  '<pair key="fabric/lan/profiles/vnic' + PROFILE_NAME +
                  '"> <vnicProfile dn="fabric/lan/profiles/vnic' +
                  PROFILE_NAME + '" status="deleted"> </vnicProfile'
                  '</pair> </inConfigs> </configConfMos')

GET_BLADE_INTERFACE_STATE = ('<configScope cookie="' + COOKIE_VALUE +
                             '" dn="' + BLADE_DN_VALUE + '" inClass="dcxVIf"' +
                             'inHierarchical="false" inRecursive="false">' +
                             '<inFilter> </inFilter> </configScope')

GET_BLADE_INTERFACE = ('<configResolveClass cookie="' + COOKIE_VALUE +
                       '" classId="vnicEther"' +
                       ' inHierarchical="false"' +
                       ' <inFilter> <eq class="vnicEther" ' +
                       'property="equipmentDn"' +
                       ' value="sys/chassis' + CHASSIS_VALUE + '/blade' +
                       BLADE_VALUE + '/adaptor-1/host-eth-?"/>' +
                       '</inFilter> </configResolveClass')

# TODO (Sumit): Assumes "adaptor-1", check if this has to be discovered too
GET_BLADE_INTERFACES = ('<configResolveChildren cookie="' +
                        COOKIE_VALUE + '" inDn="sys/chassis' +
                        CHASSIS_VALUE + '/blade' + BLADE_VALUE +
                        '/adaptor-1"' +
                        ' inHierarchical="false"> <inFilter> </inFilter' +
                        ' </configResolveChildren')


class CiscoUCSMDriver():
    """UCSM Driver"""

    def __init__(self):
        pass

    def _post_data(self, ucsm_ip, ucsm_username, ucsm_password, data):
        """Send command to UCSM in http request"""
        conn = httplib.HTTPSConnection(ucsm_ip)
        login_data = ("<aaaLogin inName=\"" + ucsm_username +
                      "\" inPassword=\"" + ucsm_password + "\" />")
        conn.request(METHOD, URL, login_data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        # TODO (Sumit): If login is not successful, throw exception
        xml_tree = et.XML(response_data)
        cookie = xml_tree.attrib["outCookie"]

        data = data.replace(COOKIE_VALUE, cookie)
        conn.request(METHOD, URL, data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        post_data_response = response_data

        logout_data = "<aaaLogout inCookie=\"" + cookie + "\" />"
        conn.request(METHOD, URL, logout_data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        return post_data_response

    def _create_vlan_post_data(self, vlan_name, vlan_id):
        """Create command"""
        data = CREATE_VLAN.replace(VLAN_NAME, vlan_name)
        data = data.replace(VLAN_ID, vlan_id)
        return data

    def _create_profile_post_data(self, profile_name, vlan_name):
        """Create command"""
        data = CREATE_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(VLAN_NAME, vlan_name)
        return data

    def _create_pclient_post_data(self, profile_name, profile_client_name):
        """Create command"""
        data = ASSOCIATE_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(PROFILE_CLIENT, profile_client_name)
        return data

    def _change_vlaninprof_post_data(self, profile_name, old_vlan_name,
                                     new_vlan_name):
        """Create command"""
        data = CHANGE_VLAN_IN_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(OLD_VLAN_NAME, old_vlan_name)
        data = data.replace(VLAN_NAME, new_vlan_name)
        return data

    def _delete_vlan_post_data(self, vlan_name):
        """Create command"""
        data = DELETE_VLAN.replace(VLAN_NAME, vlan_name)
        return data

    def _delete_profile_post_data(self, profile_name):
        """Create command"""
        data = DELETE_PROFILE.replace(PROFILE_NAME, profile_name)
        return data

    def _get_blade_interfaces_post_data(self, chassis_number, blade_number):
        """Create command"""
        data = GET_BLADE_INTERFACES.replace(CHASSIS_VALUE, chassis_number)
        data = data.replace(BLADE_VALUE, blade_number)
        return data

    def _get_blade_intf_st_post_data(self, blade_dn):
        """Create command"""
        data = GET_BLADE_INTERFACE_STATE.replace(BLADE_DN_VALUE, blade_dn)
        return data

    def _get_blade_interfaces(self, chassis_number, blade_number, ucsm_ip,
                              ucsm_username, ucsm_password):
        """Create command"""
        data = self._get_blade_interfaces_post_data(chassis_number,
                                                    blade_number)
        response = self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)
        elements = (
            et.XML(response).find("outConfigs").findall("adaptorHostEthIf")
        )
        blade_interfaces = {}
        for element in elements:
            dist_name = element.get("dn", default=None)
            if dist_name:
                order = element.get("order", default=None)
                blade_interface = {
                    const.BLADE_INTF_DN: dist_name,
                    const.BLADE_INTF_ORDER: order,
                    const.BLADE_INTF_LINK_STATE: None,
                    const.BLADE_INTF_OPER_STATE: None,
                    const.BLADE_INTF_INST_TYPE: None,
                    const.BLADE_INTF_RHEL_DEVICE_NAME:
                    self._get_rhel_device_name(order),
                }
                blade_interfaces[dist_name] = blade_interface

        return blade_interfaces

    def _get_blade_interface_state(self, blade_intf, ucsm_ip,
                                   ucsm_username, ucsm_password):
        """Create command"""
        data = (self._get_blade_intf_st_post_data(
                blade_intf[const.BLADE_INTF_DN]))
        response = self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)
        elements = et.XML(response).find("outConfigs").findall("dcxVIf")
        for element in elements:
            blade_intf[const.BLADE_INTF_LINK_STATE] = element.get("linkState",
                                                                  default=None)
            blade_intf[const.BLADE_INTF_OPER_STATE] = element.get("operState",
                                                                  default=None)
            blade_intf[const.BLADE_INTF_INST_TYPE] = element.get("instType",
                                                                 default=None)

    def _get_rhel_device_name(self, order):
        """Get the device name as on the RHEL host"""
        device_name = const.RHEL_DEVICE_NAME_REPFIX + str(int(order) - 1)
        return device_name

    def create_vlan(self, vlan_name, vlan_id, ucsm_ip, ucsm_username,
                    ucsm_password):
        """Create request for UCSM"""
        data = self._create_vlan_post_data(vlan_name, vlan_id)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def create_profile(self, profile_name, vlan_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        """Create request for UCSM"""
        data = self._create_profile_post_data(profile_name, vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)
        data = self._create_pclient_post_data(profile_name, profile_name[-16:])
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def change_vlan_in_profile(self, profile_name, old_vlan_name,
                               new_vlan_name, ucsm_ip, ucsm_username,
                               ucsm_password):
        """Create request for UCSM"""
        data = self._change_vlaninprof_post_data(profile_name,
                                                 old_vlan_name,
                                                 new_vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def get_blade_data(self, chassis_number, blade_number, ucsm_ip,
                       ucsm_username, ucsm_password):
        """
        Returns only the dynamic interfaces on the blade
        """
        blade_interfaces = self._get_blade_interfaces(chassis_number,
                                                      blade_number,
                                                      ucsm_ip,
                                                      ucsm_username,
                                                      ucsm_password)
        for blade_intf in blade_interfaces.keys():
            self._get_blade_interface_state(blade_interfaces[blade_intf],
                                            ucsm_ip, ucsm_username,
                                            ucsm_password)
            if ((blade_interfaces[blade_intf][const.BLADE_INTF_INST_TYPE] !=
                 const.BLADE_INTF_DYNAMIC)):
                blade_interfaces.pop(blade_intf)

        return blade_interfaces

    def delete_vlan(self, vlan_name, ucsm_ip, ucsm_username, ucsm_password):
        """Create request for UCSM"""
        data = self._delete_vlan_post_data(vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def delete_profile(self, profile_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        """Create request for UCSM"""
        data = self._delete_profile_post_data(profile_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)
