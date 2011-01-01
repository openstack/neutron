"""
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
# @author: Shubhangi Satras, Cisco Systems, Inc.
#
"""

import unittest
from copy import deepcopy
import inspect
import logging as LOG
import platform

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.plugins.cisco.l2network_model_base import L2NetworkModelBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.models import l2network_multi_blade
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(__name__)


class Test_L2NetworkMultiBlade(unittest.TestCase):
    """
    Implements the L2NetworkModelBase
    This implementation works with UCS and Nexus plugin for the
    following topology:
    One or more UCSM (each with one or more chasses connected)
    All UCSM connected to a single Nexus Switch
    """
    _plugins = {}
    _inventory = {}

    def setUp(self):
        cdb.initialize()
        creds.Store.initialize()
        self.tenant_id = "shubh"
        self.net_name = "TestNetwork1"
        self.profile_name = "test_tenant_port_profile"
        self.port_state = const.PORT_UP
        self.net_id = '44'
        self.net_id_DNE = '45'
        self.port_id = 'p0005'
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 102
        self.new_net_name="New_test_network"
        self._l2network_multiblade = l2network_multi_blade.\
                     L2NetworkMultiBlade()
        self.plugin_key = "quantum.plugins.cisco.ucs.cisco_ucs_plugin"+\
                            ".UCSVICPlugin"
        self.test_device_ip =  "172.18.117.45"

    def test_create_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_create_network - START")
        self._l2network_multiblade.create_network([self.tenant_id,
                                                   self.net_name,
                                                   self.net_id,
                                                   self.vlan_name,
                                                   self.vlan_id])
        device_params = self._l2network_multiblade._invoke_inventory(
                              self.plugin_key,
                              self._l2network_multiblade.create_network,
                              [self.tenant_id,
                              self.net_name,
                              self.net_id,
                              self.vlan_name,
                              self.vlan_id])
        print device_params
        print "asdfasdfasdfasdf"

        device_ips = device_params[const.DEVICE_IP]
        for device_ip in device_ips:
            new_device_params[const.DEVICE_IP] = device_ip
            self.assertEqual(self.test_device_ip,
                                       new_device_params[const.DEVICE_IP])
        self.tearDownNetwork(self.tenant_id, self.net_id)
        LOG.debug("test_create_network - END")

    def test_get_all_networks(self):
        """Not implemented for this model"""
        pass

    def test_delete_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_delete_network - START")
        self._l2network_multiblade.create_network([self.tenant_id,
                                                   self.net_name,
                                                   self.net_id,
                                                   self.vlan_name,
                                                   self.vlan_id])
        self._l2network_multiblade.delete_network([self.tenant_id,
                                                   self.net_id])
        device_params = self._l2network_multiblade._invoke_inventory(
                                self.plugin_key,
                                self._l2network_multiblade.delete_network,
                                [self.tenant_id,
                                self.net_id])
        device_ips = device_params[const.DEVICE_IP]
        for device_ip in device_ips:
           new_device_params[const.DEVICE_IP] = device_ip
           self.assertEqual(test_device_ip ,new_device_params[const.DEVICE_IP])
           LOG.debug("test_delete_network - END")

    def test_delete_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_delete_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.delete_network,
                          [self.tenant_id, self.net_id_DNE])
        LOG.debug("test_delete_networkDNE - END")

    def test_rename_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_rename_network - START")
        self._l2network_multiblade.create_network([self.tenant_id,
                                                   self.net_name,
                                                   self.net_id,
                                                   self.vlan_name,
                                                   self.vlan_id])
        self._l2network_multiblade.rename_network([self.tenant_id,
                                                   self.net_id,
                                                   self.new_net_name])
        device_params = self._l2network_multiblade._invoke_inventory(
                              self.plugin_key,
                              self._l2network_multiblade.rename_network,
                              [self.tenant_id,
                              self.net_id,
                              self.new_net_name])

        device_ips = device_params[const.DEVICE_IP]
        for device_ip in device_ips:
            new_device_params[const.DEVICE_IP] = device_ip
            self.assertEqual(test_device_ip ,
                                new_device_params[const.DEVICE_IP])
        self.tearDownNetwork(self.tenant_id, self.net_id)
        LOG.debug("test_rename_network - END")

    def test_rename_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_rename_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.rename_network,
                          [self.tenant_id, self.net_id_DNE,self.new_net_name])
        LOG.debug("test_rename_networkDNE - END")

    def test_get_network_details(self):
        """Not implemented for this model"""
        pass
        
    def test_create_port(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_create_port - START")
        port = db.port_create(self.net_id, self.port_state)
        port_id= port[const.UUID]
        self._l2network_multiblade.create_port([self.tenant_id,
                                                   self.net_id,
                                                   self.port_state,
                                                   port_id])
        device_params = self._l2network_multiblade._invoke_inventory(
                              self.plugin_key,
                              self._l2network_multiblade.create_port,
                              [self.tenant_id,
                              self.net_id,
                              self.port_state,
                              self.port_id])
        device_ips = device_params[const.DEVICE_IP]
        print device_params
        print "asdfasdfasdfasdf"
        for device_ip in device_ips:
            new_device_params[const.DEVICE_IP] = device_ip
            self.assertEqual(self.test_device_ip,
                 new_device_params[const.DEVICE_IP])
        self.tearDownNetwork(self.tenant_id, self.net_id)
        LOG.debug("test_create_network - END")

    def tearDownNetwork(self , tenant_id, net_id ):
        self._l2network_multiblade.delete_network([tenant_id, net_id])





