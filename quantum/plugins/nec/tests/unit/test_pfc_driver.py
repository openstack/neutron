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
from quantum.plugins.nec.common import ofc_client as ofc


class TestConfig(object):
    """Configuration for this test"""
    host = '127.0.0.1'
    port = 8888
    use_ssl = False
    key_file = None
    cert_file = None


def _ofc(id):
    """OFC ID converter"""
    return "ofc-%s" % id


class PFCDriverTestBase(unittest.TestCase):

    def setUp(self):
        self.mox = mox.Mox()
        self.driver = drivers.get_driver("pfc")(TestConfig)
        self.mox.StubOutWithMock(ofc.OFCClient, 'do_request')

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

    def testa_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % t

        path = "/tenants"
        body = {'id': t, 'description': description}
        tenant = {'id': _ofc(t)}
        ofc.OFCClient.do_request("POST", path, body=body).AndReturn(tenant)
        self.mox.ReplayAll()

        ret = self.driver.create_tenant(description, t)
        self.mox.VerifyAll()
        self.assertEqual(ret, _ofc(t))

    def testb_update_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "new desc of %s" % t

        path = "/tenants/%s" % _ofc(t)
        body = {'description': description}
        ofc.OFCClient.do_request("PUT", path, body=body)
        self.mox.ReplayAll()

        self.driver.update_tenant(_ofc(t), description)
        self.mox.VerifyAll()

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s" % _ofc(t)
        ofc.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_tenant(_ofc(t))
        self.mox.VerifyAll()

    def testd_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n

        path = "/tenants/%s/networks" % _ofc(t)
        body = {'id': n, 'description': description}
        network = {'id': _ofc(n)}
        ofc.OFCClient.do_request("POST", path, body=body).AndReturn(network)
        self.mox.ReplayAll()

        ret = self.driver.create_network(_ofc(t), description, n)
        self.mox.VerifyAll()
        self.assertEqual(ret, _ofc(n))

    def teste_update_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n

        path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        body = {'description': description}
        ofc.OFCClient.do_request("PUT", path, body=body)
        self.mox.ReplayAll()

        self.driver.update_network(_ofc(t), _ofc(n), description)
        self.mox.VerifyAll()

    def testf_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        ofc.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_network(_ofc(t), _ofc(n))
        self.mox.VerifyAll()

    def testg_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s/networks/%s/ports" % (_ofc(t), _ofc(n))
        body = {'id': p.id,
                'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        port = {'id': _ofc(p.id)}
        ofc.OFCClient.do_request("POST", path, body=body).AndReturn(port)
        self.mox.ReplayAll()

        ret = self.driver.create_port(_ofc(t), _ofc(n), p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, _ofc(p.id))

    def testh_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s/networks/%s/ports/%s" % (_ofc(t), _ofc(n),
                                                     _ofc(p.id))
        ofc.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(_ofc(t), _ofc(n), _ofc(p.id))
        self.mox.VerifyAll()
