# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import sys

import mock
import netaddr

from neutron.common import constants as l3_constants
from neutron.openstack.common import uuidutils
from neutron.tests import base

from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
sys.modules['ncclient'] = mock.MagicMock()
sys.modules['ciscoconfparse'] = mock.MagicMock()
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    csr1kv_routing_driver as csr_driver)
from neutron.plugins.cisco.cfg_agent.service_helpers import routing_svc_helper

_uuid = uuidutils.generate_uuid
FAKE_ID = _uuid()
PORT_ID = _uuid()


class TestCSR1kvRouting(base.BaseTestCase):

    def setUp(self):
        super(TestCSR1kvRouting, self).setUp()

        device_params = {'management_ip_address': 'fake_ip',
                         'protocol_port': 22,
                         'credentials': {"username": "stack",
                                         "password": "cisco"},
                         }
        self.driver = csr_driver.CSR1kvRoutingDriver(
            **device_params)
        self.mock_conn = mock.MagicMock()
        self.driver._csr_conn = self.mock_conn
        self.driver._check_response = mock.MagicMock(return_value=True)

        self.vrf = ('nrouter-' + FAKE_ID)[:csr_driver.CSR1kvRoutingDriver.
                                          DEV_NAME_LEN]
        self.driver._get_vrfs = mock.Mock(return_value=[self.vrf])
        self.ex_gw_ip = '20.0.0.30'
        self.ex_gw_cidr = '20.0.0.30/24'
        self.ex_gw_vlan = 1000
        self.ex_gw_gateway_ip = '20.0.0.1'
        self.ex_gw_port = {'id': _uuid(),
                           'network_id': _uuid(),
                           'fixed_ips': [{'ip_address': self.ex_gw_ip,
                                          'subnet_id': _uuid()}],
                           'subnet': {'cidr': self.ex_gw_cidr,
                                      'gateway_ip': self.ex_gw_gateway_ip},
                           'ip_cidr': self.ex_gw_cidr,
                           'mac_address': 'ca:fe:de:ad:be:ef',
                           'hosting_info': {'segmentation_id': self.ex_gw_vlan,
                                          'hosting_port_name': 't2_p:0'}}
        self.vlan_no = 500
        self.gw_ip_cidr = '10.0.0.1/16'
        self.gw_ip = '10.0.0.1'
        self.hosting_port = 't1_p:0'
        self.port = {'id': PORT_ID,
                     'ip_cidr': self.gw_ip_cidr,
                     'fixed_ips': [{'ip_address': self.gw_ip}],
                     'hosting_info': {'segmentation_id': self.vlan_no,
                                      'hosting_port_name': self.hosting_port}}
        int_ports = [self.port]

        self.router = {
            'id': FAKE_ID,
            l3_constants.INTERFACE_KEY: int_ports,
            'enable_snat': True,
            'routes': [],
            'gw_port': self.ex_gw_port}

        self.ri = routing_svc_helper.RouterInfo(FAKE_ID, self.router)
        self.ri.internal_ports = int_ports

    def test_csr_get_vrf_name(self):
        self.assertEqual(self.driver._csr_get_vrf_name(self.ri), self.vrf)

    def test_create_vrf(self):
        confstr = snippets.CREATE_VRF % self.vrf

        self.driver._create_vrf(self.vrf)

        self.assertTrue(self.driver._csr_conn.edit_config.called)
        self.driver._csr_conn.edit_config.assert_called_with(target='running',
                                                             config=confstr)

    def test_remove_vrf(self):
        confstr = snippets.REMOVE_VRF % self.vrf

        self.driver._remove_vrf(self.vrf)

        self.assertTrue(self.driver._csr_conn.edit_config.called)
        self.driver._csr_conn.edit_config.assert_called_with(target='running',
                                                             config=confstr)

    def test_router_added(self):
        confstr = snippets.CREATE_VRF % self.vrf

        self.driver.router_added(self.ri)

        self.assertTrue(self.driver._csr_conn.edit_config.called)
        self.driver._csr_conn.edit_config.assert_called_with(target='running',
                                                             config=confstr)

    def test_router_removed(self):
        confstr = snippets.REMOVE_VRF % self.vrf

        self.driver._remove_vrf(self.vrf)

        self.assertTrue(self.driver._csr_conn.edit_config.called)
        self.driver._csr_conn.edit_config.assert_called_once_with(
            target='running', config=confstr)

    def test_internal_network_added(self):
        self.driver._create_subinterface = mock.MagicMock()
        interface = 'GigabitEthernet0' + '.' + str(self.vlan_no)

        self.driver.internal_network_added(self.ri, self.port)

        args = (interface, self.vlan_no, self.vrf, self.gw_ip,
                netaddr.IPAddress('255.255.0.0'))
        self.driver._create_subinterface.assert_called_once_with(*args)

    def test_internal_network_removed(self):
        self.driver._remove_subinterface = mock.MagicMock()
        interface = 'GigabitEthernet0' + '.' + str(self.vlan_no)

        self.driver.internal_network_removed(self.ri, self.port)

        self.driver._remove_subinterface.assert_called_once_with(interface)

    def test_routes_updated(self):
        dest_net = '20.0.0.0/16'
        next_hop = '10.0.0.255'
        route = {'destination': dest_net,
                 'nexthop': next_hop}

        dest = netaddr.IPAddress('20.0.0.0')
        destmask = netaddr.IPNetwork(dest_net).netmask
        self.driver._add_static_route = mock.MagicMock()
        self.driver._remove_static_route = mock.MagicMock()

        self.driver.routes_updated(self.ri, 'replace', route)
        self.driver._add_static_route.assert_called_once_with(
            dest, destmask, next_hop, self.vrf)

        self.driver.routes_updated(self.ri, 'delete', route)
        self.driver._remove_static_route.assert_called_once_with(
            dest, destmask, next_hop, self.vrf)

    def test_floatingip(self):
        floating_ip = '15.1.2.3'
        fixed_ip = '10.0.0.3'

        self.driver._add_floating_ip = mock.MagicMock()
        self.driver._remove_floating_ip = mock.MagicMock()
        self.driver._add_interface_nat = mock.MagicMock()
        self.driver._remove_dyn_nat_translations = mock.MagicMock()
        self.driver._remove_interface_nat = mock.MagicMock()

        self.driver.floating_ip_added(self.ri, self.ex_gw_port,
                                      floating_ip, fixed_ip)
        self.driver._add_floating_ip.assert_called_once_with(
            floating_ip, fixed_ip, self.vrf)

        self.driver.floating_ip_removed(self.ri, self.ex_gw_port,
                                        floating_ip, fixed_ip)

        self.driver._remove_interface_nat.assert_called_once_with(
            'GigabitEthernet1.1000', 'outside')
        self.driver._remove_dyn_nat_translations.assert_called_once_with()
        self.driver._remove_floating_ip.assert_called_once_with(
            floating_ip, fixed_ip, self.vrf)
        self.driver._add_interface_nat.assert_called_once_with(
            'GigabitEthernet1.1000', 'outside')

    def test_external_gateway_added(self):
        self.driver._create_subinterface = mock.MagicMock()
        self.driver._add_default_static_route = mock.MagicMock()

        ext_interface = 'GigabitEthernet1' + '.' + str(1000)
        args = (ext_interface, self.ex_gw_vlan, self.vrf, self.ex_gw_ip,
                netaddr.IPAddress('255.255.255.0'))

        self.driver.external_gateway_added(self.ri, self.ex_gw_port)

        self.driver._create_subinterface.assert_called_once_with(*args)
        self.driver._add_default_static_route.assert_called_once_with(
            self.ex_gw_gateway_ip, self.vrf)

    def test_enable_internal_network_NAT(self):
        self.driver._nat_rules_for_internet_access = mock.MagicMock()
        int_interface = ('GigabitEthernet0' + '.' + str(self.vlan_no))
        ext_interface = 'GigabitEthernet1' + '.' + str(1000)
        args = (('acl_' + str(self.vlan_no)),
                netaddr.IPNetwork(self.gw_ip_cidr).network,
                netaddr.IPNetwork(self.gw_ip_cidr).hostmask,
                int_interface,
                ext_interface,
                self.vrf)

        self.driver.enable_internal_network_NAT(self.ri, self.port,
                                                self.ex_gw_port)

        self.driver._nat_rules_for_internet_access.assert_called_once_with(
            *args)

    def test_enable_internal_network_NAT_with_confstring(self):
        self.driver._csr_conn.reset_mock()
        self.driver._check_acl = mock.Mock(return_value=False)
        int_interface = ('GigabitEthernet0' + '.' + str(self.vlan_no))
        ext_interface = 'GigabitEthernet1' + '.' + str(1000)
        acl_no = ('acl_' + str(self.vlan_no))
        int_network = netaddr.IPNetwork(self.gw_ip_cidr).network
        int_net_mask = netaddr.IPNetwork(self.gw_ip_cidr).hostmask

        self.driver.enable_internal_network_NAT(self.ri, self.port,
                                                self.ex_gw_port)

        self.assert_edit_running_config(
            snippets.CREATE_ACL, (acl_no, int_network, int_net_mask))
        self.assert_edit_running_config(
            snippets.SET_DYN_SRC_TRL_INTFC, (acl_no, ext_interface, self.vrf))
        self.assert_edit_running_config(
            snippets.SET_NAT, (int_interface, 'inside'))
        self.assert_edit_running_config(
            snippets.SET_NAT, (ext_interface, 'outside'))

    def test_disable_internal_network_NAT(self):
        self.driver._remove_interface_nat = mock.MagicMock()
        self.driver._remove_dyn_nat_translations = mock.MagicMock()
        self.driver._remove_dyn_nat_rule = mock.MagicMock()
        int_interface = ('GigabitEthernet0' + '.' + str(self.vlan_no))
        ext_interface = 'GigabitEthernet1' + '.' + str(1000)
        self.driver.disable_internal_network_NAT(self.ri, self.port,
                                                 self.ex_gw_port)
        args = (('acl_' + str(self.vlan_no)), ext_interface, self.vrf)

        self.driver._remove_interface_nat.assert_called_once_with(
            int_interface, 'inside')
        self.driver._remove_dyn_nat_translations.assert_called_once_with()
        self.driver._remove_dyn_nat_rule.assert_called_once_with(*args)

    def assert_edit_running_config(self, snippet_name, args):
        if args:
            confstr = snippet_name % args
        else:
            confstr = snippet_name
        self.driver._csr_conn.edit_config.assert_any_call(
            target='running', config=confstr)

    def test_disable_internal_network_NAT_with_confstring(self):
        self.driver._cfg_exists = mock.Mock(return_value=True)
        int_interface = ('GigabitEthernet0' + '.' + str(self.vlan_no))
        ext_interface = 'GigabitEthernet1' + '.' + str(1000)
        acl_no = 'acl_' + str(self.vlan_no)
        self.driver.disable_internal_network_NAT(self.ri, self.port,
                                                 self.ex_gw_port)

        self.assert_edit_running_config(
            snippets.REMOVE_NAT, (int_interface, 'inside'))
        self.assert_edit_running_config(snippets.CLEAR_DYN_NAT_TRANS, None)
        self.assert_edit_running_config(
            snippets.REMOVE_DYN_SRC_TRL_INTFC, (acl_no, ext_interface,
                                                self.vrf))
        self.assert_edit_running_config(snippets.REMOVE_ACL, acl_no)
