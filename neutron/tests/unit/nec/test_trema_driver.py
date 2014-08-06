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

import random

import mock
from six import moves

from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import ofc_client
from neutron.plugins.nec.db import models as nmodels
from neutron.plugins.nec import drivers
from neutron.tests import base


class TestConfig(object):
    """Configuration for this test."""
    host = '127.0.0.1'
    port = 8888


class TremaDriverTestBase(base.BaseTestCase):

    driver_name = "trema"

    def setUp(self):
        super(TremaDriverTestBase, self).setUp()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.do_request = mock.patch.object(ofc_client.OFCClient,
                                            'do_request').start()

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        mac = ':'.join(['%x' % random.randint(0, 255)
                        for i in moves.xrange(6)])
        portinfo = nmodels.PortInfo(id=port_id, datapath_id="0x123456789",
                                    port_no=1234, vlan_id=321,
                                    mac=mac)
        return tenant_id, network_id, portinfo


class TremaDriverNetworkTestBase(TremaDriverTestBase):

    def test_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        ret = self.driver.create_tenant('dummy_desc', t)
        ofc_t_path = "/tenants/%s" % t
        self.assertEqual(ofc_t_path, ret)
        # There is no API call.
        self.assertEqual(0, self.do_request.call_count)

    def test_update_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/tenants/%s" % t
        self.driver.update_tenant(path, 'dummy_desc')
        # There is no API call.
        self.assertEqual(0, self.do_request.call_count)

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/tenants/%s" % t
        self.driver.delete_tenant(path)
        # There is no API call.
        self.assertEqual(0, self.do_request.call_count)

    def testa_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n
        body = {'id': n, 'description': description}
        ret = self.driver.create_network(t, description, n)
        self.do_request.assert_called_once_with("POST", "/networks", body=body)
        self.assertEqual(ret, '/networks/%s' % n)

    def testc_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()
        net_path = "/networks/%s" % n
        self.driver.delete_network(net_path)
        self.do_request.assert_called_once_with("DELETE", net_path)


class TremaPortBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_port"

    def test_filter_supported(self):
        self.assertTrue(self.driver.filter_supported())

    def testd_create_port(self):
        _t, n, p = self.get_ofc_item_random_params()
        net_path = "/networks/%s" % n
        body = {'id': p.id,
                'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        ret = self.driver.create_port(net_path, p, p.id)
        self.do_request.assert_called_once_with(
            "POST", "/networks/%s/ports" % n, body=body)
        self.assertEqual(ret, '/networks/%s/ports/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        p_path = "/networks/%s/ports/%s" % (n, p.id)
        self.driver.delete_port(p_path)
        self.do_request.assert_called_once_with("DELETE", p_path)


class TremaPortMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_portmac"

    def test_filter_supported(self):
        self.assertTrue(self.driver.filter_supported())

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        net_path = "/networks/%s" % n
        path_1 = "/networks/%s/ports" % n
        body_1 = {'id': dummy_port,
                  'datapath_id': p.datapath_id,
                  'port': str(p.port_no),
                  'vid': str(p.vlan_id)}
        path_2 = "/networks/%s/ports/%s/attachments" % (n, dummy_port)
        body_2 = {'id': p.id, 'mac': p.mac}
        path_3 = "/networks/%s/ports/%s" % (n, dummy_port)
        ret = self.driver.create_port(net_path, p, p.id)

        self.do_request.assert_has_calls([
            mock.call("POST", path_1, body=body_1),
            mock.call("POST", path_2, body=body_2),
            mock.call("DELETE", path_3)
        ])
        port_path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port,
                                                              p.id)
        self.assertEqual(ret, port_path)

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id
        path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port, p.id)
        self.driver.delete_port(path)
        self.do_request.assert_called_once_with("DELETE", path)


class TremaMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_mac"

    def test_filter_supported(self):
        self.assertFalse(self.driver.filter_supported())

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()
        net_path = "/networks/%s" % n
        path = "/networks/%s/attachments" % n
        body = {'id': p.id, 'mac': p.mac}
        ret = self.driver.create_port(net_path, p, p.id)
        self.do_request.assert_called_once_with("POST", path, body=body)
        self.assertEqual(ret, '/networks/%s/attachments/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/networks/%s/attachments/%s" % (n, p.id)
        self.driver.delete_port(path)
        self.do_request.assert_called_once_with("DELETE", path)


class TremaFilterDriverTest(TremaDriverTestBase):
    def _test_create_filter(self, filter_dict=None, filter_post=None,
                            filter_wildcards=None, no_portinfo=False):
        t, n, p = self.get_ofc_item_random_params()
        src_mac = ':'.join(['%x' % random.randint(0, 255)
                            for i in moves.xrange(6)])
        if filter_wildcards is None:
            filter_wildcards = []

        f = {'tenant_id': t,
             'id': uuidutils.generate_uuid(),
             'network_id': n,
             'priority': 123,
             'action': "ACCEPT",
             'in_port': p.id,
             'src_mac': src_mac,
             'dst_mac': "",
             'eth_type': 0,
             'src_cidr': "",
             'dst_cidr': "",
             'src_port': 0,
             'dst_port': 0,
             'protocol': "TCP",
             'admin_state_up': True,
             'status': "ACTIVE"}
        if filter_dict:
            f.update(filter_dict)

        net_path = "/networks/%s" % n

        all_wildcards_ofp = ['dl_vlan', 'dl_vlan_pcp', 'nw_tos',
                             'in_port', 'dl_src', 'dl_dst',
                             'nw_src', 'nw_dst',
                             'dl_type', 'nw_proto',
                             'tp_src', 'tp_dst']
        all_wildcards_non_ofp = ['in_datapath_id', 'slice']

        body = {'id': f['id'],
                'action': 'ALLOW',
                'priority': 123,
                'slice': n,
                'in_datapath_id': '0x123456789',
                'in_port': 1234,
                'nw_proto': '0x6',
                'dl_type': '0x800',
                'dl_src': src_mac}
        if filter_post:
            body.update(filter_post)

        if no_portinfo:
            filter_wildcards += ['in_datapath_id', 'in_port']
            p = None

        for field in filter_wildcards:
            if field in body:
                del body[field]

        ofp_wildcards = ["%s:32" % _f if _f in ['nw_src', 'nw_dst'] else _f
                         for _f in all_wildcards_ofp if _f not in body]
        body['ofp_wildcards'] = set(ofp_wildcards)

        non_ofp_wildcards = [_f for _f in all_wildcards_non_ofp
                             if _f not in body]
        if non_ofp_wildcards:
            body['wildcards'] = set(non_ofp_wildcards)

        ret = self.driver.create_filter(net_path, f, p, f['id'])
        # The content of 'body' is checked below.
        self.do_request.assert_called_once_with("POST", "/filters",
                                                body=mock.ANY)
        self.assertEqual(ret, '/filters/%s' % f['id'])

        # ofp_wildcards and wildcards in body are comma-separated
        # string but the order of elements are not considered,
        # so we check these fields as set.
        actual_body = self.do_request.call_args[1]['body']
        if 'ofp_wildcards' in actual_body:
            ofp_wildcards = actual_body['ofp_wildcards'].split(',')
            actual_body['ofp_wildcards'] = set(ofp_wildcards)
        if 'wildcards' in actual_body:
            actual_body['wildcards'] = set(actual_body['wildcards'].split(','))
        self.assertEqual(body, actual_body)

    def test_create_filter_accept(self):
        self._test_create_filter(filter_dict={'action': 'ACCEPT'})

    def test_create_filter_allow(self):
        self._test_create_filter(filter_dict={'action': 'ALLOW'})

    def test_create_filter_deny(self):
        self._test_create_filter(filter_dict={'action': 'DENY'},
                                 filter_post={'action': 'DENY'})

    def test_create_filter_drop(self):
        self._test_create_filter(filter_dict={'action': 'DROP'},
                                 filter_post={'action': 'DENY'})

    def test_create_filter_no_port(self):
        self._test_create_filter(no_portinfo=True)

    def test_create_filter_src_mac_wildcard(self):
        self._test_create_filter(filter_dict={'src_mac': ''},
                                 filter_wildcards=['dl_src'])

    def test_create_filter_dst_mac(self):
        dst_mac = ':'.join(['%x' % random.randint(0, 255)
                            for i in moves.xrange(6)])
        self._test_create_filter(filter_dict={'dst_mac': dst_mac},
                                 filter_post={'dl_dst': dst_mac})

    def test_create_filter_src_cidr(self):
        src_cidr = '10.2.0.0/24'
        self._test_create_filter(filter_dict={'src_cidr': src_cidr},
                                 filter_post={'nw_src': src_cidr})

    def test_create_filter_dst_cidr(self):
        dst_cidr = '192.168.10.0/24'
        self._test_create_filter(filter_dict={'dst_cidr': dst_cidr},
                                 filter_post={'nw_dst': dst_cidr})

    def test_create_filter_proto_icmp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'icmp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x1'})

    def test_create_filter_proto_tcp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'tcp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x6'})

    def test_create_filter_proto_udp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'udp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x11'})

    def test_create_filter_proto_arp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'arp'},
            filter_post={'dl_type': '0x806'},
            filter_wildcards=['nw_proto'])

    def test_create_filter_proto_misc(self):
        self._test_create_filter(
            filter_dict={'protocol': '0x33', 'eth_type': '0x900'},
            filter_post={'dl_type': '0x900', 'nw_proto': '0x33'})

    def test_create_filter_proto_misc_dl_type_wildcard(self):
        self._test_create_filter(
            filter_dict={'protocol': '0x33', 'ether_type': ''},
            filter_post={'nw_proto': '0x33'},
            filter_wildcards=['dl_type'])

    def test_create_filter_proto_wildcard(self):
        self._test_create_filter(
            filter_dict={'protocol': ''},
            filter_wildcards=['dl_type', 'nw_proto'])

    def test_create_filter_src_dst_port(self):
        self._test_create_filter(filter_dict={'src_port': 8192,
                                              'dst_port': 4096},
                                 filter_post={'tp_src': '0x2000',
                                              'tp_dst': '0x1000'})

    def testb_delete_filter(self):
        t, n, p = self.get_ofc_item_random_params()
        f_path = "/filters/%s" % uuidutils.generate_uuid()
        self.driver.delete_filter(f_path)
        self.do_request.assert_called_once_with("DELETE", f_path)
