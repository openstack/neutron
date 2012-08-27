# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import mox
import unittest

from quantum.common import utils
from quantum.plugins.nec import drivers
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec.common import ofc_client


class TestConfig(object):
    """Configuration for this test"""
    host = '127.0.0.1'
    port = 8888


class TremaDriverTestBase():

    driver_name = "trema"

    def setUp(self):
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')

    def tearDown(self):
        self.mox.UnsetStubs()

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        tenant_id = utils.str_uuid()
        network_id = utils.str_uuid()
        port_id = utils.str_uuid()
        portinfo = nmodels.PortInfo(id=port_id, datapath_id="0x123456789",
                                    port_no=1234, vlan_id=321,
                                    mac="11:22:33:44:55:66")
        return tenant_id, network_id, portinfo


class TremaDriverNetworkTestBase(TremaDriverTestBase):

    def testa_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n

        body = {'id': n, 'description': description}
        ofc_client.OFCClient.do_request("POST", "/networks", body=body)
        self.mox.ReplayAll()

        self.driver.create_network(t, description, n)
        self.mox.VerifyAll()

    def testb_update_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n

        body = {'description': description}
        ofc_client.OFCClient.do_request("PUT", "/networks/%s" % n, body=body)
        self.mox.ReplayAll()

        self.driver.update_network(t, n, description)
        self.mox.VerifyAll()

    def testc_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        ofc_client.OFCClient.do_request("DELETE", "/networks/%s" % n)
        self.mox.ReplayAll()

        self.driver.delete_network(t, n)
        self.mox.VerifyAll()


class TremaPortBaseDriverTest(TremaDriverNetworkTestBase, unittest.TestCase):

    driver_name = "trema_port"

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        body = {'id': p.id,
                'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        ofc_client.OFCClient.do_request("POST",
                                        "/networks/%s/ports" % n, body=body)
        self.mox.ReplayAll()

        self.driver.create_port(t, n, p, p.id)
        self.mox.VerifyAll()

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        ofc_client.OFCClient.do_request("DELETE",
                                        "/networks/%s/ports/%s" % (n, p.id))
        self.mox.ReplayAll()

        self.driver.delete_port(t, n, p.id)
        self.mox.VerifyAll()


class TremaPortMACBaseDriverTest(TremaDriverNetworkTestBase,
                                 unittest.TestCase):

    driver_name = "trema_portmac"

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        path_1 = "/networks/%s/ports" % n
        body_1 = {'id': dummy_port,
                  'datapath_id': p.datapath_id,
                  'port': str(p.port_no),
                  'vid': str(p.vlan_id)}
        ofc_client.OFCClient.do_request("POST", path_1, body=body_1)
        path_2 = "/networks/%s/ports/%s/attachments" % (n, dummy_port)
        body_2 = {'id': p.id, 'mac': p.mac}
        ofc_client.OFCClient.do_request("POST", path_2, body=body_2)
        path_3 = "/networks/%s/ports/%s" % (n, dummy_port)
        ofc_client.OFCClient.do_request("DELETE", path_3)
        self.mox.ReplayAll()

        self.driver.create_port(t, n, p, p.id)
        self.mox.VerifyAll()

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(t, n, p.id)
        self.mox.VerifyAll()


class TremaMACBaseDriverTest(TremaDriverNetworkTestBase, unittest.TestCase):

    driver_name = "trema_mac"

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/networks/%s/attachments" % n
        body = {'id': p.id, 'mac': p.mac}
        ofc_client.OFCClient.do_request("POST", path, body=body)
        self.mox.ReplayAll()

        self.driver.create_port(t, n, p, p.id)
        self.mox.VerifyAll()

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/networks/%s/attachments/%s" % (n, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(t, n, p.id)
        self.mox.VerifyAll()


class TremaFilterDriverTest(TremaDriverTestBase, unittest.TestCase):

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        t, n, p = (super(TremaFilterDriverTest, self).
                   get_ofc_item_random_params())
        filter_id = utils.str_uuid()
        filter_dict = {'tenant_id': t,
                       'id': filter_id,
                       'network_id': n,
                       'priority': 123,
                       'action': "ACCEPT",
                       'in_port': p.id,
                       'src_mac': p.mac,
                       'dst_mac': "",
                       'eth_type': 0,
                       'src_cidr': "",
                       'dst_cidr': "",
                       'src_port': 0,
                       'dst_port': 0,
                       'protocol': "TCP",
                       'admin_state_up': True,
                       'status': "ACTIVE"}
        filter_item = nmodels.PacketFilter(**filter_dict)
        return t, n, p, filter_item

    def testa_create_filter(self):
        t, n, p, f = self.get_ofc_item_random_params()

        ofp_wildcards = 'dl_vlan,dl_vlan_pcp,nw_tos,dl_dst,' + \
                        'nw_src:32,nw_dst:32,tp_src,tp_dst'
        body = {'id': f.id,
                'action': 'ALLOW',
                'priority': 123,
                'slice': n,
                'in_datapath_id': '0x123456789',
                'in_port': 1234,
                'nw_proto': '0x6',
                'dl_type': '0x800',
                'dl_src': p.mac,
                'ofp_wildcards': ofp_wildcards}
        ofc_client.OFCClient.do_request("POST", "/filters", body=body)
        self.mox.ReplayAll()

        self.driver.create_filter(t, n, f, p, f.id)
        self.mox.VerifyAll()

    def testb_delete_filter(self):
        t, n, p, f = self.get_ofc_item_random_params()

        ofc_client.OFCClient.do_request("DELETE", "/filters/%s" % f.id)
        self.mox.ReplayAll()

        self.driver.delete_filter(t, n, f.id)
        self.mox.VerifyAll()
