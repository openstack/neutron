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
import logging as LOG
import string
import subprocess
from xml.etree import ElementTree as et
import urllib

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.ucs import cisco_getvif as gvif


LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)

COOKIE_VALUE = "cookie_placeholder"
PROFILE_NAME = "profilename_placeholder"
PROFILE_CLIENT = "profileclient_placeholder"
VLAN_NAME = "vlanname_placeholder"
VLAN_ID = "vlanid_placeholder"
OLD_VLAN_NAME = "old_vlanname_placeholder"
DYNAMIC_NIC_PREFIX = "eth"

# The following are standard strings, messages used to communicate with UCSM,
#only place holder values change for each message
HEADERS = {"Content-Type": "text/xml"}
METHOD = "POST"
URL = "/nuova"

CREATE_VLAN = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"true\"> <inConfigs>" \
"<pair key=\"fabric/lan/net-" + VLAN_NAME + \
"\"> <fabricVlan defaultNet=\"no\" " \
"dn=\"fabric/lan/net-" + VLAN_NAME + \
"\" id=\"" + VLAN_ID + "\" name=\"" + \
VLAN_NAME + "\" status=\"created\">" \
"</fabricVlan> </pair> </inConfigs> </configConfMos>"

CREATE_PROFILE = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"true\"> <inConfigs>" \
"<pair key=\"fabric/lan/profiles/vnic-" + PROFILE_NAME + \
"\"> <vnicProfile descr=\"Profile created by " \
"Cisco OpenStack Quantum Plugin\" " \
"dn=\"fabric/lan/profiles/vnic-" + PROFILE_NAME + \
"\" maxPorts=\"64\" name=\"" + PROFILE_NAME + \
"\" nwCtrlPolicyName=\"\" pinToGroupName=\"\" " \
"qosPolicyName=\"\" status=\"created\"> " \
"<vnicEtherIf defaultNet=\"yes\" name=\"" + VLAN_NAME + \
"\" rn=\"if-" + VLAN_NAME + "\" > </vnicEtherIf> " \
"</vnicProfile> </pair> </inConfigs> </configConfMos>"

ASSOCIATE_PROFILE = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"true\"> <inConfigs> <pair " \
"key=\"fabric/lan/profiles/vnic-" + PROFILE_NAME + \
"/cl-" + PROFILE_CLIENT + "\"> <vmVnicProfCl dcName=\".*\" " \
"descr=\"\" dn=\"fabric/lan/profiles/vnic-" + \
PROFILE_NAME + "/cl-" + PROFILE_CLIENT + \
"\"name=\"" + PROFILE_CLIENT + "\" orgPath=\".*\" " \
"status=\"created\" swName=\"default$\"> </vmVnicProfCl>" \
"</pair> </inConfigs> </configConfMos>"

CHANGE_VLAN_IN_PROFILE = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"true\"> <inConfigs>" \
"<pair key=\"fabric/lan/profiles/vnic-" + \
PROFILE_NAME + "\"> <vnicProfile descr=\"Profile " \
"created by Cisco OpenStack Quantum Plugin\" " \
"dn=\"fabric/lan/profiles/vnic-" + \
PROFILE_NAME + "\" maxPorts=\"64\" name=\"" + \
PROFILE_NAME + "\" nwCtrlPolicyName=\"\" " \
"pinToGroupName=\"\" qosPolicyName=\"\" " \
"status=\"created,modified\">" \
"<vnicEtherIf rn=\"if-" + OLD_VLAN_NAME + \
"\" status=\"deleted\"> </vnicEtherIf> <vnicEtherIf " \
"defaultNet=\"yes\" name=\"" + \
VLAN_NAME + "\" rn=\"if-" + VLAN_NAME + \
"\" > </vnicEtherIf> </vnicProfile> </pair>" \
"</inConfigs> </configConfMos>"

DELETE_VLAN = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"true\"> <inConfigs>" \
"<pair key=\"fabric/lan/net-" + VLAN_NAME + \
"\"> <fabricVlan dn=\"fabric/lan/net-" + VLAN_NAME + \
"\" status=\"deleted\"> </fabricVlan> </pair> </inConfigs>" \
"</configConfMos>"

DELETE_PROFILE = "<configConfMos cookie=\"" + COOKIE_VALUE + \
"\" inHierarchical=\"false\"> <inConfigs>" \
"<pair key=\"fabric/lan/profiles/vnic-" + PROFILE_NAME + \
"\"> <vnicProfile dn=\"fabric/lan/profiles/vnic-" + \
PROFILE_NAME + "\" status=\"deleted\"> </vnicProfile>" \
"</pair> </inConfigs> </configConfMos>"


class CiscoUCSMDriver():

    def __init__(self):
        pass

    def _post_data(self, ucsm_ip, ucsm_username, ucsm_password, data):
        conn = httplib.HTTPConnection(ucsm_ip)
        login_data = "<aaaLogin inName=\"" + ucsm_username + \
        "\" inPassword=\"" + ucsm_password + "\" />"
        conn.request(METHOD, URL, login_data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        LOG.debug(response.status)
        LOG.debug(response.reason)
        LOG.debug(response_data)
        # TODO (Sumit): If login is not successful, throw exception
        xmlTree = et.XML(response_data)
        cookie = xmlTree.attrib["outCookie"]

        data = data.replace(COOKIE_VALUE, cookie)
        LOG.debug("POST: %s" % data)
        conn.request(METHOD, URL, data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        LOG.debug(response.status)
        LOG.debug(response.reason)
        LOG.debug("UCSM Response: %s" % response_data)

        logout_data = "<aaaLogout inCookie=\"" + cookie + "\" />"
        conn.request(METHOD, URL, logout_data, HEADERS)
        response = conn.getresponse()
        response_data = response.read()
        LOG.debug(response.status)
        LOG.debug(response.reason)
        LOG.debug(response_data)

    def _create_vlan_post_data(self, vlan_name, vlan_id):
        data = CREATE_VLAN.replace(VLAN_NAME, vlan_name)
        data = data.replace(VLAN_ID, vlan_id)
        return data

    def _create_profile_post_data(self, profile_name, vlan_name):
        data = CREATE_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(VLAN_NAME, vlan_name)
        return data

    def _create_profile_client_post_data(self, profile_name,
                                         profile_client_name):
        data = ASSOCIATE_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(PROFILE_CLIENT, profile_client_name)
        return data

    def _change_vlan_in_profile_post_data(self, profile_name, old_vlan_name,
                                          new_vlan_name):
        data = CHANGE_VLAN_IN_PROFILE.replace(PROFILE_NAME, profile_name)
        data = data.replace(OLD_VLAN_NAME, old_vlan_name)
        data = data.replace(VLAN_NAME, new_vlan_name)
        return data

    def _delete_vlan_post_data(self, vlan_name):
        data = DELETE_VLAN.replace(VLAN_NAME, vlan_name)
        return data

    def _delete_profile_post_data(self, profile_name):
        data = DELETE_PROFILE.replace(PROFILE_NAME, profile_name)
        return data

    def _get_next_dynamic_nic(self):
        dynamic_nic_id = gvif.get_next_dynic()
        if len(dynamic_nic_id) > 0:
            return dynamic_nic_id
        else:
            raise cisco_exceptions.NoMoreNics(net_id=net_id, port_id=port_id)

    def create_vlan(self, vlan_name, vlan_id, ucsm_ip, ucsm_username,
                    ucsm_password):
        data = self._create_vlan_post_data(vlan_name, vlan_id)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def create_profile(self, profile_name, vlan_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        data = self._create_profile_post_data(profile_name, vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)
        data = self._create_profile_client_post_data(profile_name,
                                                     profile_name[-16:])
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def change_vlan_in_profile(self, profile_name, old_vlan_name,
                               new_vlan_name, ucsm_ip, ucsm_username,
                               ucsm_password):
        data = self._change_vlan_in_profile_post_data(profile_name,
                                                      old_vlan_name,
                                                      new_vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def get_dynamic_nic(self, host):
        # TODO (Sumit): Check availability per host
        # TODO (Sumit): If not available raise exception
        # TODO (Sumit): This simple logic assumes that create-port and
        #               spawn-VM happens in lock-step
        #               But we should support multiple create-port calls,
        #               followed by spawn-VM calls
        #               That would require managing a pool of available
        #               dynamic vnics per host
        dynamic_nic_name = self._get_next_dynamic_nic()
        LOG.debug("Reserving dynamic nic %s" % dynamic_nic_name)
        return dynamic_nic_name

    def delete_vlan(self, vlan_name, ucsm_ip, ucsm_username, ucsm_password):
        data = self._delete_vlan_post_data(vlan_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def delete_profile(self, profile_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        data = self._delete_profile_post_data(profile_name)
        self._post_data(ucsm_ip, ucsm_username, ucsm_password, data)

    def release_dynamic_nic(self, host):
        # TODO (Sumit): Release on a specific host
        pass
