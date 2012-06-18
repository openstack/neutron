# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Peter Strunk, Cisco Systems, Inc.

import logging
import unittest

from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.segmentation.l2network_vlan_mgr import (
    L2NetworkVLANMgr,
)


logging.basicConfig(level=logging.WARN)
LOG = logging.getLogger(__name__)


class Test_L2Network_Vlan_Mgr(unittest.TestCase):

    _plugins = {}
    _inventory = {}

    def setUp(self):
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        cdb.initialize()
        creds.Store.initialize()
        self.tenant_id = "network_admin"
        self.net_name = "TestNetwork1"
        self.vlan_name = "TestVlan1"
        self.vlan_id = 300
        self.net_id = 100
        self.vlan_mgr = L2NetworkVLANMgr()
        self.plugin_key = (
            "quantum.plugins.cisco.ucs.cisco_ucs_plugin.UCSVICPlugin")

    def tearDown(self):
        db.clear_db()

    def test_reserve_segmentation_id(self):
        LOG.debug("test_reserve_segmentation_id - START")
        db.network_create(self.tenant_id, self.net_name)
        vlan_id = self.vlan_mgr.reserve_segmentation_id(self.tenant_id,
                                                        self.net_name)
        self.assertEqual(vlan_id, int(conf.VLAN_START))
        LOG.debug("test_reserve_segmentation_id - END")

    def test_reserve_segmentation_id_NA(self):
        LOG.debug("test_reserve_segmentation_id - START")
        db.clear_db()
        self.assertRaises(c_exc.VlanIDNotAvailable,
                          self.vlan_mgr.reserve_segmentation_id,
                          self.tenant_id,
                          self.net_name)
        LOG.debug("test_reserve_segmentation_id - END")

    def test_release_segmentation_id(self):
        LOG.debug("test_release_segmentation_id - START")
        db.network_create(self.tenant_id, self.net_name)
        vlan_id = self.vlan_mgr.reserve_segmentation_id(self.tenant_id,
                                                        self.net_name)
        cdb.add_vlan_binding(vlan_id, self.vlan_name, self.net_id)
        release_return = self.vlan_mgr.release_segmentation_id(self.tenant_id,
                                                               self.net_id)
        self.assertEqual(release_return, False)
        LOG.debug("test_release_segmentation_id - END")

    def test_release_segmentation_id_idDNE(self):
        LOG.debug("test_release_segmentation_idDNE - START")
        db.network_create(self.tenant_id, self.net_name)
        self.assertRaises(exc.NetworkNotFound,
                          self.vlan_mgr.release_segmentation_id,
                          self.tenant_id,
                          self.net_id)
        LOG.debug("test_release_segmentation_idDNE - END")
