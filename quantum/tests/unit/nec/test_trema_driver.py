# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from quantum import context
from quantum.openstack.common import uuidutils
from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec import drivers
from quantum.tests import base


class TestConfig(object):
    """Configuration for this test"""
    host = '127.0.0.1'
    port = 8888


class TremaDriverTestBase(base.BaseTestCase):

    driver_name = "trema"

    def setUp(self):
        super(TremaDriverTestBase, self).setUp()
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')
        self.addCleanup(self.mox.UnsetStubs)

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
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

        ret = self.driver.create_network(t, description, n)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s' % n)

    def testc_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        ofc_client.OFCClient.do_request("DELETE", net_path)
        self.mox.ReplayAll()

        self.driver.delete_network(net_path)
        self.mox.VerifyAll()


class TremaPortBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_port"

    def testd_create_port(self):
        _t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        body = {'id': p.id,
                'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        ofc_client.OFCClient.do_request("POST",
                                        "/networks/%s/ports" % n, body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s/ports/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        p_path = "/networks/%s/ports/%s" % (n, p.id)
        ofc_client.OFCClient.do_request("DELETE", p_path)
        self.mox.ReplayAll()

        self.driver.delete_port(p_path)
        self.mox.VerifyAll()


class TremaPortMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_portmac"

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        net_path = "/networks/%s" % n
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

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        port_path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port,
                                                              p.id)
        self.assertEqual(ret, port_path)

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(path)
        self.mox.VerifyAll()


class TremaMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_mac"

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        path = "/networks/%s/attachments" % n
        body = {'id': p.id, 'mac': p.mac}
        ofc_client.OFCClient.do_request("POST", path, body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s/attachments/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/networks/%s/attachments/%s" % (n, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(path)
        self.mox.VerifyAll()


class TremaFilterDriverTest(TremaDriverTestBase):

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        t, n, p = (super(TremaFilterDriverTest, self).
                   get_ofc_item_random_params())
        filter_id = uuidutils.generate_uuid()
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

        net_path = "/networks/%s" % n
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

        ret = self.driver.create_filter(net_path, f, p, f.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/filters/%s' % f.id)

    def testb_delete_filter(self):
        t, n, p, f = self.get_ofc_item_random_params()

        f_path = "/filters/%s" % f.id
        ofc_client.OFCClient.do_request("DELETE", f_path)
        self.mox.ReplayAll()

        self.driver.delete_filter(f_path)
        self.mox.VerifyAll()


def generate_random_ids(count=1):
    if count == 1:
        return uuidutils.generate_uuid()
    else:
        return [uuidutils.generate_uuid() for i in xrange(count)]


class TremaIdConvertTest(base.BaseTestCase):
    driver_name = 'trema'

    def setUp(self):
        super(TremaIdConvertTest, self).setUp()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.mox = mox.Mox()
        self.ctx = self.mox.CreateMock(context.Context)
        self.addCleanup(self.mox.UnsetStubs)

    def test_convert_tenant_id(self):
        ofc_t_id = generate_random_ids(1)
        ret = self.driver.convert_ofc_tenant_id(self.ctx, ofc_t_id)
        self.assertEqual(ret, '/tenants/%s' % ofc_t_id)

    def test_convert_tenant_id_noconv(self):
        ofc_t_id = '/tenants/%s' % generate_random_ids(1)
        ret = self.driver.convert_ofc_tenant_id(self.ctx, ofc_t_id)
        self.assertEqual(ret, ofc_t_id)

    def test_convert_network_id(self):
        t_id, ofc_t_id, ofc_n_id = generate_random_ids(3)

        ret = self.driver.convert_ofc_network_id(self.ctx, ofc_n_id, t_id)
        self.assertEqual(ret, ('/networks/%s' % ofc_n_id))

    def test_convert_network_id_noconv(self):
        t_id = 'dummy'
        ofc_t_id, ofc_n_id = generate_random_ids(2)
        ofc_n_id = '/networks/%s' % ofc_n_id
        self.driver.convert_ofc_network_id(self.ctx, ofc_n_id, t_id)

    def test_convert_filter_id(self):
        ofc_f_id = generate_random_ids(1)
        ret = self.driver.convert_ofc_filter_id(self.ctx, ofc_f_id)
        self.assertEqual(ret, '/filters/%s' % ofc_f_id)

    def test_convert_filter_id_noconv(self):
        ofc_f_id = '/filters/%s' % generate_random_ids(1)
        ret = self.driver.convert_ofc_filter_id(self.ctx, ofc_f_id)
        self.assertEqual(ret, ofc_f_id)


class TremaIdConvertTestBase(base.BaseTestCase):
    def setUp(self):
        super(TremaIdConvertTestBase, self).setUp()
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.ctx = self.mox.CreateMock(context.Context)
        self.ctx.session = "session"
        self.mox.StubOutWithMock(ndb, 'get_ofc_id_lookup_both')
        self.addCleanup(self.mox.UnsetStubs)

    def _test_convert_port_id(self, port_path_template):
        t_id, n_id = generate_random_ids(2)
        ofc_n_id, ofc_p_id = generate_random_ids(2)

        ndb.get_ofc_id_lookup_both(
            self.ctx.session, 'ofc_network', n_id).AndReturn(ofc_n_id)
        self.mox.ReplayAll()

        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        exp = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        self.assertEqual(ret, exp)
        self.mox.VerifyAll()

    def _test_convert_port_id_with_new_network_id(self, port_path_template):
        t_id, n_id = generate_random_ids(2)
        ofc_n_id, ofc_p_id = generate_random_ids(2)

        ofc_n_path = '/networks/%s' % ofc_n_id
        ndb.get_ofc_id_lookup_both(
            self.ctx.session, 'ofc_network', n_id).AndReturn(ofc_n_path)
        self.mox.ReplayAll()

        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        exp = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        print 'exp=', exp
        print 'ret=', ret
        self.assertEqual(ret, exp)
        self.mox.VerifyAll()

    def _test_convert_port_id_noconv(self, port_path_template):
        t_id = n_id = 'dummy'
        ofc_n_id, ofc_p_id = generate_random_ids(2)
        ofc_p_id = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        self.assertEqual(ret, ofc_p_id)


class TremaIdConvertPortBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_port"

    def test_convert_port_id(self):
        self._test_convert_port_id('/networks/%(network)s/ports/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/ports/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/ports/%(port)s')


class TremaIdConvertPortMACBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_portmac"

    def test_convert_port_id(self):
        self._test_convert_port_id(
            '/networks/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')


class TremaIdConvertMACBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_mac"

    def test_convert_port_id(self):
        self._test_convert_port_id(
            '/networks/%(network)s/attachments/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/attachments/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/attachments/%(port)s')
