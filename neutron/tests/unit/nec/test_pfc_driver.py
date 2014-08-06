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
import string
import uuid

import mock
import netaddr

from neutron.common import constants
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import ofc_client as ofc
from neutron.plugins.nec.db import models as nmodels
from neutron.plugins.nec import drivers
from neutron.plugins.nec.drivers import pfc
from neutron.plugins.nec.extensions import packetfilter as ext_pf
from neutron.tests import base


class TestConfig(object):
    """Configuration for this test."""
    host = '127.0.0.1'
    port = 8888
    use_ssl = False
    key_file = None
    cert_file = None
    insecure_ssl = False


def _ofc(id):
    """OFC ID converter."""
    return "ofc-%s" % id


class PFCDriverTestBase(base.BaseTestCase):

    driver = 'neutron.plugins.nec.drivers.pfc.PFCDriverBase'
    filter_supported = False

    def setUp(self):
        super(PFCDriverTestBase, self).setUp()
        self.driver = drivers.get_driver(self.driver)(TestConfig)
        self.do_request = mock.patch.object(ofc.OFCClient,
                                            'do_request').start()

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        portinfo = nmodels.PortInfo(id=port_id, datapath_id="0x123456789",
                                    port_no=1234, vlan_id=321,
                                    mac="11:22:33:44:55:66")
        return tenant_id, network_id, portinfo

    def _generate_ofc_tenant_id(self, tenant_id):
        fields = tenant_id.split('-')
        # Strip 1st character (UUID version) of 3rd field
        fields[2] = fields[2][1:]
        return ''.join(fields)

    def get_ofc_description(self, desc):
        """OFC description consists of [A-Za-z0-9_]."""
        return desc.replace('-', '_').replace(' ', '_')

    def _create_tenant(self, t, ofc_t, post_id=False, post_desc=False):
        tenant_path = '/tenants/%s' % ofc_t
        path = "/tenants"
        description = "desc of %s" % t
        body = {}
        if post_desc:
            ofc_description = self.get_ofc_description(description)
            body['description'] = ofc_description
        if post_id:
            body['id'] = ofc_t
            self.do_request.return_value = None
        else:
            self.do_request.return_value = {'id': ofc_t}

        ret = self.driver.create_tenant(description, t)
        self.do_request.assert_called_once_with("POST", path, body=body)
        self.assertEqual(ret, tenant_path)

    def testa_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        ofc_t = self._generate_ofc_tenant_id(t)
        self._create_tenant(t, ofc_t, post_id=True)

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s" % _ofc(t)

        self.driver.delete_tenant(path)
        self.do_request.assert_called_once_with("DELETE", path)

    def testd_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n
        ofc_description = self.get_ofc_description(description)

        tenant_path = "/tenants/%s" % _ofc(t)
        post_path = "%s/networks" % tenant_path
        body = {'description': ofc_description}
        network = {'id': _ofc(n)}
        self.do_request.return_value = network

        ret = self.driver.create_network(tenant_path, description, n)
        self.do_request.assert_called_once_with("POST", post_path, body=body)
        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        self.assertEqual(ret, net_path)

    def testf_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))

        self.driver.delete_network(net_path)
        self.do_request.assert_called_once_with("DELETE", net_path)

    def _test_create_port(self, call_filters_arg=None, send_filters_arg=None):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        post_path = "%s/ports" % net_path
        port_path = "/tenants/%s/networks/%s/ports/%s" % (_ofc(t), _ofc(n),
                                                          _ofc(p.id))
        body = {'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        if send_filters_arg is not None:
            body['filters'] = send_filters_arg
        port = {'id': _ofc(p.id)}
        self.do_request.return_value = port

        if call_filters_arg is not None:
            ret = self.driver.create_port(net_path, p, p.id, call_filters_arg)
        else:
            ret = self.driver.create_port(net_path, p, p.id)
        self.do_request.assert_called_once_with("POST", post_path, body=body)
        self.assertEqual(ret, port_path)

    def testg_create_port(self):
        self._test_create_port()

    def test_create_port_with_filters_argument(self):
        # If no filter support, 'filters' argument is passed to OFC.
        # Note that it will be overridden in a test class with filter support.
        self._test_create_port(call_filters_arg=['dummy'],
                               send_filters_arg=None)

    def testh_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        port_path = "/tenants/%s/networks/%s/ports/%s" % (_ofc(t), _ofc(n),
                                                          _ofc(p.id))

        self.driver.delete_port(port_path)
        self.do_request.assert_called_once_with("DELETE", port_path)

    def test_filter_supported(self):
        self.assertEqual(self.filter_supported, self.driver.filter_supported())


class PFCDriverBaseTest(PFCDriverTestBase):

    def test_extract_ofc_network_id(self):
        network_id = '/tenants/tenant-a/networks/network-a'
        self.assertEqual('network-a',
                         self.driver._extract_ofc_network_id(network_id))

    def test_extract_ofc_network_id_failure(self):
        network_id = '/tenants/tenant-a/networks/network-a/dummy'
        self.assertRaises(pfc.InvalidOFCIdFormat,
                          self.driver._extract_ofc_network_id, network_id)

    def test_extract_ofc_port_id(self):
        port_id = '/tenants/tenant-a/networks/network-a/ports/port-a'
        self.assertEqual({'tenant': 'tenant-a',
                          'network': 'network-a',
                          'port': 'port-a'},
                         self.driver._extract_ofc_port_id(port_id))

    def test_extract_ofc_port_id_failure(self):
        port_id = '/tenants/tenant-a/dummy/network-a/ports/port-a'
        self.assertRaises(pfc.InvalidOFCIdFormat,
                          self.driver._extract_ofc_port_id, port_id)


class PFCV3DriverTest(PFCDriverTestBase):
    driver = 'pfc_v3'

    def testa_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        ret = self.driver.create_tenant('dummy_desc', t)
        self.assertEqual(0, self.do_request.call_count)
        ofc_t_path = "/tenants/" + self._generate_ofc_tenant_id(t)
        self.assertEqual(ofc_t_path, ret)

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/tenants/%s" % _ofc(t)
        self.driver.delete_tenant(path)
        self.assertEqual(0, self.do_request.call_count)


class PFCV4DriverTest(PFCDriverTestBase):
    driver = 'pfc_v4'


class PFCV5DriverTest(PFCDriverTestBase):
    driver = 'pfc_v5'

    def test_create_router(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()
        description = 'dummy_router_desc'

        tenant_path = "/tenants/%s" % _ofc(t)
        post_path = "%s/routers" % tenant_path
        router = {'id': _ofc(r)}
        self.do_request.return_value = router

        ret = self.driver.create_router(tenant_path, description, r)
        self.do_request.assert_called_once_with("POST", post_path, body=None)
        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        self.assertEqual(ret, router_path)

    def test_delete_router(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))

        self.driver.delete_router(router_path)
        self.do_request.assert_called_once_with("DELETE", router_path)

    def test_add_router_interface(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()
        n = uuidutils.generate_uuid()
        p = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        infs_path = router_path + "/interfaces"
        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        ip_address = '10.1.1.1/24'
        mac_address = '11:22:33:44:55:66'
        body = {'net_id': _ofc(n),
                'ip_address': ip_address,
                'mac_address': mac_address}
        inf = {'id': _ofc(p)}
        self.do_request.return_value = inf

        ret = self.driver.add_router_interface(router_path, net_path,
                                               ip_address, mac_address)
        self.do_request.assert_called_once_with("POST", infs_path, body=body)

        inf_path = "%s/interfaces/%s" % (router_path, _ofc(p))
        self.assertEqual(ret, inf_path)

    def test_update_router_interface(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()
        p = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        inf_path = "%s/interfaces/%s" % (router_path, _ofc(p))
        ip_address = '10.1.1.1/24'
        mac_address = '11:22:33:44:55:66'

        self.driver.update_router_interface(inf_path, ip_address, mac_address)
        self.driver.update_router_interface(inf_path, ip_address=ip_address)
        self.driver.update_router_interface(inf_path, mac_address=mac_address)

        self.do_request.assert_has_calls([
            mock.call("PUT", inf_path, body={'ip_address': ip_address,
                                             'mac_address': mac_address}),
            mock.call("PUT", inf_path, body={'ip_address': ip_address}),
            mock.call("PUT", inf_path, body={'mac_address': mac_address}),
        ])

    def test_delete_router_interface(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()
        p = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        inf_path = "%s/interfaces/%s" % (router_path, _ofc(p))

        self.driver.delete_router_interface(inf_path)
        self.do_request.assert_called_once_with("DELETE", inf_path)

    def _get_route_id(self, dest, nexthop):
        dest = netaddr.IPNetwork(dest)
        return '-'.join([str(dest.network), nexthop, str(dest.netmask)])

    def test_add_router_route(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        routes_path = router_path + "/routes"
        dest = '10.1.1.0/24'
        nexthop = '192.168.100.10'
        body = {'destination': dest, 'nexthop': nexthop}
        route_id = self._get_route_id(dest, nexthop)
        self.do_request.return_value = {'id': route_id}

        ret = self.driver.add_router_route(router_path, '10.1.1.0/24',
                                           '192.168.100.10')
        self.do_request.assert_called_once_with("POST", routes_path, body=body)
        route_path = routes_path + '/' + route_id
        self.assertEqual(ret, route_path)

    def test_delete_router_route(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        routes_path = router_path + "/routes"

        route_id = self._get_route_id('10.1.1.0/24', '192.168.100.10')
        route_path = routes_path + '/' + route_id

        self.driver.delete_router_route(route_path)
        self.do_request.assert_called_once_with("DELETE", route_path)

    def test_list_router_routes(self):
        t = uuidutils.generate_uuid()
        r = uuidutils.generate_uuid()

        router_path = "/tenants/%s/routers/%s" % (_ofc(t), _ofc(r))
        routes_path = router_path + "/routes"

        routes = [('10.1.1.0/24', '192.168.100.10'),
                  ('10.2.2.0/20', '192.168.100.20')]
        data = {'routes': [{'id': self._get_route_id(route[0], route[1]),
                            'destination': route[0], 'nexthop': route[1]}
                           for route in routes]}
        self.do_request.return_value = data

        ret = self.driver.list_router_routes(router_path)
        self.do_request.assert_called_once_with("GET", routes_path)

        expected = [{'id': (routes_path + "/" +
                            self._get_route_id(route[0], route[1])),
                     'destination': route[0], 'nexthop': route[1]}
                    for route in routes]
        self.assertEqual(len(routes), len(ret))
        self.assertEqual(data['routes'], expected)


class PFCFilterDriverTestMixin:
    def _test_create_filter(self, filter_dict=None, filter_post=None,
                            apply_ports=None):
        t, n, p = self.get_ofc_item_random_params()

        filter_id = uuidutils.generate_uuid()
        f = {'priority': 123, 'action': "ACCEPT"}
        if filter_dict:
            f.update(filter_dict)

        net_path = "/networks/%s" % n
        body = {'action': 'pass', 'priority': 123}
        if filter_post:
            body.update(filter_post)

        self.do_request.return_value = {'id': filter_id}
        if apply_ports is not None:
            ret = self.driver.create_filter(net_path, f, p,
                                            apply_ports=apply_ports)
        else:
            ret = self.driver.create_filter(net_path, f, p)
        self.do_request.assert_called_once_with("POST", "/filters",
                                                body=body)
        self.assertEqual(ret, '/filters/%s' % filter_id)

    def test_create_filter_accept(self):
        self._test_create_filter(filter_dict={'action': 'ACCEPT'})

    def test_create_filter_allow(self):
        self._test_create_filter(filter_dict={'action': 'ALLOW'})

    def test_create_filter_deny(self):
        self._test_create_filter(filter_dict={'action': 'DENY'},
                                 filter_post={'action': 'drop'})

    def test_create_filter_drop(self):
        self._test_create_filter(filter_dict={'action': 'DROP'},
                                 filter_post={'action': 'drop'})

    def test_create_filter_empty_field_not_post(self):
        filter_dict = {'src_mac': '', 'src_cidr': '', 'src_port': 0,
                       'dst_mac': '', 'dst_cidr': '', 'dst_port': 0,
                       'protocol': '', 'eth_type': 0}
        filter_post = {}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_none_field_not_post(self):
        filter_dict = {'src_mac': None, 'src_cidr': None, 'src_port': None,
                       'dst_mac': None, 'dst_cidr': None, 'dst_port': None,
                       'protocol': None, 'eth_type': None}
        filter_post = {}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_all_fields(self):
        filter_dict = {'src_mac': '11:22:33:44:55:66',
                       'dst_mac': '77:88:99:aa:bb:cc',
                       'src_cidr': '192.168.3.0/24',
                       'dst_cidr': '10.11.240.0/20',
                       'src_port': 12345,
                       'dst_port': 23456,
                       'protocol': '0x10',
                       'eth_type': 0x800}
        filter_post = filter_dict.copy()
        filter_post['protocol'] = 16
        filter_post['eth_type'] = '0x800'
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_cidr_ip_addr_32(self):
        filter_dict = {'src_cidr': '192.168.3.1',
                       'dst_cidr': '10.11.240.2'}
        filter_post = {'src_cidr': '192.168.3.1/32',
                       'dst_cidr': '10.11.240.2/32'}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_proto_tcp(self):
        filter_dict = {'protocol': 'TCP'}
        filter_post = {'protocol': constants.PROTO_NUM_TCP}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_proto_udp(self):
        filter_dict = {'protocol': 'UDP'}
        filter_post = {'protocol': constants.PROTO_NUM_UDP}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_proto_icmp(self):
        filter_dict = {'protocol': 'ICMP'}
        filter_post = {'protocol': constants.PROTO_NUM_ICMP}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_proto_arp_not_proto_post(self):
        filter_dict = {'protocol': 'ARP'}
        filter_post = {}
        self._test_create_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_create_filter_apply_ports(self):
        apply_ports = [
            ('p1', '/tenants/tenant-1/networks/network-1/ports/port-1'),
            ('p2', '/tenants/tenant-2/networks/network-2/ports/port-2')]
        filter_post = {'apply_ports': [
            {'tenant': 'tenant-1', 'network': 'network-1', 'port': 'port-1'},
            {'tenant': 'tenant-2', 'network': 'network-2', 'port': 'port-2'}
        ]}
        self._test_create_filter(filter_dict={}, apply_ports=apply_ports,
                                 filter_post=filter_post)

    def _test_update_filter(self, filter_dict=None, filter_post=None):
        filter_id = uuidutils.generate_uuid()
        ofc_filter_id = '/filters/%s' % filter_id
        self.driver.update_filter(ofc_filter_id, filter_dict)
        self.do_request.assert_called_once_with("PUT", ofc_filter_id,
                                                body=filter_post)

    def test_update_filter_empty_fields(self):
        filter_dict = {'src_mac': '', 'src_cidr': '', 'src_port': 0,
                       'dst_mac': '', 'dst_cidr': '', 'dst_port': 0,
                       'protocol': '', 'eth_type': 0}
        filter_post = {'src_mac': '', 'src_cidr': '', 'src_port': '',
                       'dst_mac': '', 'dst_cidr': '', 'dst_port': '',
                       'protocol': '', 'eth_type': ''}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_none_fields(self):
        filter_dict = {'src_mac': None, 'src_cidr': None, 'src_port': None,
                       'dst_mac': None, 'dst_cidr': None, 'dst_port': None,
                       'protocol': None, 'eth_type': None}
        filter_post = {'src_mac': '', 'src_cidr': '', 'src_port': '',
                       'dst_mac': '', 'dst_cidr': '', 'dst_port': '',
                       'protocol': '', 'eth_type': ''}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_all_fields(self):
        filter_dict = {'src_mac': '11:22:33:44:55:66',
                       'dst_mac': '77:88:99:aa:bb:cc',
                       'src_cidr': '192.168.3.0/24',
                       'dst_cidr': '10.11.240.0/20',
                       'src_port': 12345,
                       'dst_port': 23456,
                       'protocol': '0x10',
                       'eth_type': 0x800}
        filter_post = filter_dict.copy()
        filter_post['protocol'] = 16
        filter_post['eth_type'] = '0x800'
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_cidr_ip_addr_32(self):
        filter_dict = {'src_cidr': '192.168.3.1',
                       'dst_cidr': '10.11.240.2'}
        filter_post = {'src_cidr': '192.168.3.1/32',
                       'dst_cidr': '10.11.240.2/32'}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_proto_tcp(self):
        filter_dict = {'protocol': 'TCP'}
        filter_post = {'protocol': constants.PROTO_NUM_TCP}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_proto_udp(self):
        filter_dict = {'protocol': 'UDP'}
        filter_post = {'protocol': constants.PROTO_NUM_UDP}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_proto_icmp(self):
        filter_dict = {'protocol': 'ICMP'}
        filter_post = {'protocol': constants.PROTO_NUM_ICMP}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_update_filter_proto_arp_post_empty(self):
        filter_dict = {'protocol': 'ARP'}
        filter_post = {'protocol': ''}
        self._test_update_filter(filter_dict=filter_dict,
                                 filter_post=filter_post)

    def test_delete_filter(self):
        t, n, p = self.get_ofc_item_random_params()
        f_path = "/filters/%s" % uuidutils.generate_uuid()
        self.driver.delete_filter(f_path)
        self.do_request.assert_called_once_with("DELETE", f_path)

    def _test_validate_filter_duplicate_priority(self, method, found_dup):
        with mock.patch('neutron.manager.NeutronManager'
                        '.get_plugin') as get_plugin:
            plugin = get_plugin.return_value
            if found_dup:
                plugin.get_packet_filters.return_value = ['found']
            else:
                plugin.get_packet_filters.return_value = []
            network_id = str(uuid.uuid4())
            filter_dict = {'network_id': network_id,
                           'priority': 12}
            if found_dup:
                self.assertRaises(ext_pf.PacketFilterDuplicatedPriority,
                                  method, 'context', filter_dict)
            else:
                self.assertIsNone(method('context', filter_dict))
            plugin.get_packet_filters.assert_called_once_with(
                'context',
                filters={'network_id': [network_id],
                         'priority': [12]},
                fields=['id'])

    def test_validate_filter_create_no_duplicate_priority(self):
        self._test_validate_filter_duplicate_priority(
            self.driver.validate_filter_create,
            found_dup=False)

    def test_validate_filter_create_duplicate_priority(self):
        self._test_validate_filter_duplicate_priority(
            self.driver.validate_filter_create,
            found_dup=True)

    def test_validate_filter_update_action_raises_error(self):
        filter_dict = {'action': 'ALLOW'}
        self.assertRaises(ext_pf.PacketFilterUpdateNotSupported,
                          self.driver.validate_filter_update,
                          'context', filter_dict)

    def test_validate_filter_update_priority_raises_error(self):
        filter_dict = {'priority': '13'}
        self.assertRaises(ext_pf.PacketFilterUpdateNotSupported,
                          self.driver.validate_filter_update,
                          'context', filter_dict)

    def _test_validate_filter_ipv6_not_supported(self, field, create=True):
        if create:
            filter_dict = {'network_id': 'net1', 'priority': 12}
            method = self.driver.validate_filter_create
        else:
            filter_dict = {}
            method = self.driver.validate_filter_update
        filter_dict[field] = 'fe80::1'
        self.assertRaises(ext_pf.PacketFilterIpVersionNonSupported,
                          method, 'context', filter_dict)
        filter_dict[field] = '10.56.3.3'
        self.assertIsNone(method('context', filter_dict))

    def test_validate_filter_create_ipv6_not_supported(self):
        with mock.patch('neutron.manager.NeutronManager'
                        '.get_plugin') as get_plugin:
            plugin = get_plugin.return_value
            plugin.get_packet_filters.return_value = []
            self._test_validate_filter_ipv6_not_supported(
                'src_cidr', create=True)
            self._test_validate_filter_ipv6_not_supported(
                'dst_cidr', create=True)

    def test_validate_filter_update_ipv6_not_supported(self):
        self._test_validate_filter_ipv6_not_supported('src_cidr', create=False)
        self._test_validate_filter_ipv6_not_supported('dst_cidr', create=False)

    def _test_validate_filter_priority_range_one(self, method, priority, ok):
        filter_dict = {'priority': priority, 'network_id': 'net1'}
        if ok:
            self.assertIsNone(method('context', filter_dict))
        else:
            self.assertRaises(ext_pf.PacketFilterInvalidPriority,
                              method, 'context', filter_dict)

    def test_validate_filter_create_priority_range(self):
        with mock.patch('neutron.manager.NeutronManager'
                        '.get_plugin') as get_plugin:
            plugin = get_plugin.return_value
            plugin.get_packet_filters.return_value = []

            method = self.driver.validate_filter_create
            self._test_validate_filter_priority_range_one(method, 0, False)
            self._test_validate_filter_priority_range_one(method, 1, True)
            self._test_validate_filter_priority_range_one(method, 32766, True)
            self._test_validate_filter_priority_range_one(method, 32767, False)


class PFCV51DriverTest(PFCFilterDriverTestMixin, PFCV5DriverTest):
    driver = 'pfc_v51'
    filter_supported = True

    def test_create_port_with_filters_argument(self):
        self._test_create_port(
            call_filters_arg=[('neutron-id-1', '/filters/filter-1'),
                              ('neutron-id-2', '/filters/filter-2')],
            send_filters_arg=['filter-1', 'filter-2'])


class PFCDriverStringTest(base.BaseTestCase):

    driver = 'neutron.plugins.nec.drivers.pfc.PFCDriverBase'

    def setUp(self):
        super(PFCDriverStringTest, self).setUp()
        self.driver = drivers.get_driver(self.driver)(TestConfig)

    def test_generate_pfc_id_uuid(self):
        id_str = uuidutils.generate_uuid()
        exp_str = (id_str[:14] + id_str[15:]).replace('-', '')[:31]

        ret_str = self.driver._generate_pfc_id(id_str)
        self.assertEqual(exp_str, ret_str)

    def test_generate_pfc_id_uuid_no_hyphen(self):
        # Keystone tenant_id style uuid
        id_str = uuidutils.generate_uuid()
        id_no_hyphen = id_str.replace('-', '')
        exp_str = (id_str[:14] + id_str[15:]).replace('-', '')[:31]

        ret_str = self.driver._generate_pfc_id(id_no_hyphen)
        self.assertEqual(exp_str, ret_str)

    def test_generate_pfc_id_string(self):
        id_str = uuidutils.generate_uuid() + 'x'
        exp_str = id_str[:31].replace('-', '_')

        ret_str = self.driver._generate_pfc_id(id_str)
        self.assertEqual(exp_str, ret_str)

    def test_generate_pfc_desc(self):
        random_list = [random.choice(string.printable) for x in range(128)]
        random_str = ''.join(random_list)

        accept_letters = string.letters + string.digits
        exp_list = [x if x in accept_letters else '_' for x in random_list]
        exp_str = ''.join(exp_list)[:127]

        ret_str = self.driver._generate_pfc_description(random_str)
        self.assertEqual(exp_str, ret_str)
