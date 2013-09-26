# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
# All Rights Reserved.
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
# @author: Rossella Sblendido, Midokura Europe SARL
# @author: Ryu Ishimoto, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK

import mock
import os
import re
import sys

import neutron.common.test_lib as test_lib
import neutron.tests.unit.midonet.mock_lib as mock_lib
import neutron.tests.unit.test_db_plugin as test_plugin
import neutron.tests.unit.test_extension_security_group as sg
import neutron.tests.unit.test_l3_plugin as test_l3_plugin
import webob.exc

MIDOKURA_PKG_PATH = "neutron.plugins.midonet.plugin"
MIDONET_PLUGIN_NAME = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)

ETHERTYPE_ARP = 0x0806
ETHERTYPE_IP4 = 0x0800
ETHERTYPE_IP6 = 0x86dd

mac_addr_regex = re.compile("(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
inbound_chain_regex = re.compile("OS_PORT_.*_INBOUND")
outbound_chain_regex = re.compile("OS_PORT_.*_OUTBOUND")
egress_chain_regex = re.compile("OS_SG_.*_EGRESS")
ingress_chain_regex = re.compile("OS_SG_.*_INGRESS")

# Need to mock the midonetclient module since the plugin will try to load it.
sys.modules["midonetclient"] = mock.Mock()


class MidonetPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=MIDONET_PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        self.mock_api = mock.patch(
            'neutron.plugins.midonet.midonet_lib.MidoClient')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(
            etc_path, 'midonet.ini.test')]

        self.instance = self.mock_api.start()
        mock_cfg = mock_lib.MidonetLibMockConfig(self.instance.return_value)
        mock_cfg.setup()
        mock_client = mock_lib.MidoClientMockConfig(self.instance.return_value)
        mock_client.setup()
        super(MidonetPluginV2TestCase, self).setUp(plugin=plugin,
                                                   ext_mgr=ext_mgr)

    def tearDown(self):
        super(MidonetPluginV2TestCase, self).tearDown()
        self.mock_api.stop()


class TestMidonetNetworksV2(test_plugin.TestNetworksV2,
                            MidonetPluginV2TestCase):

    pass


class TestMidonetL3NatTestCase(test_l3_plugin.L3NatDBIntTestCase,
                               MidonetPluginV2TestCase):
    def setUp(self,
              plugin=MIDONET_PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestMidonetL3NatTestCase, self).setUp(plugin=plugin,
                                                    ext_mgr=None,
                                                    service_plugins=None)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(MIDONET_PLUGIN_NAME)

    def test_floatingip_assoc_no_port(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = super(TestMidonetL3NatTestCase, self)._create_floatingip(
                self.fmt, public_sub['subnet']['network_id'])
            # Cleanup
            floatingip = self.deserialize(self.fmt, res)
            self._delete('floatingips', floatingip['floatingip']['id'])
        self.assertFalse(self.instance.return_value.add_static_nat.called)

    def test_floatingip_assoc_with_port(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    # We need to hook up the private subnet to the external
                    # network in order to associate the fip.
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    # Create the fip.
                    res = super(TestMidonetL3NatTestCase,
                                self)._create_floatingip(
                                    self.fmt,
                                    public_sub['subnet']['network_id'],
                                    port_id=private_port['port']['id'])

                    # Cleanup the resources used for the test
                    floatingip = self.deserialize(self.fmt, res)
                    self._delete('floatingips', floatingip['floatingip']['id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
        self.assertTrue(self.instance.return_value.add_static_nat.called)

    def test_external_network_port_creation(self):
        with self.subnet(cidr='200.200.200.0/24') as pub_sub:
            self._set_net_external(pub_sub['subnet']['network_id'])
            ip_addr = "200.200.200.200"
            port_res = self._create_port(self.fmt,
                                         pub_sub['subnet']['network_id'],
                                         webob.exc.HTTPCreated.code,
                                         tenant_id='fake_tenant_id',
                                         device_id='fake_device',
                                         device_owner='fake_owner',
                                         fixed_ips=[{'subnet_id':
                                                     pub_sub['subnet']['id'],
                                                     'ip_address': ip_addr}],
                                         set_context=False)
            port = self.deserialize(self.fmt, port_res)
            self._delete('ports', port['port']['id'])
            verify_delete_call = self.instance.return_value.delete_route
            self.assertTrue(verify_delete_call.called_once)
        verify_add_call = self.instance.return_value.add_router_route
        self.assertTrue(verify_add_call.called_with(dst_network_addr=ip_addr))


class TestMidonetSecurityGroupsTestCase(sg.SecurityGroupDBTestCase):

    _plugin_name = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)

    def setUp(self):
        self.mock_api = mock.patch(
            'neutron.plugins.midonet.midonet_lib.MidoClient')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(
            etc_path, 'midonet.ini.test')]

        self.instance = self.mock_api.start()
        mock_cfg = mock_lib.MidonetLibMockConfig(self.instance.return_value)
        mock_cfg.setup()
        super(TestMidonetSecurityGroupsTestCase, self).setUp(self._plugin_name)


class TestMidonetSecurityGroup(sg.TestSecurityGroups,
                               TestMidonetSecurityGroupsTestCase):
    pass


class TestMidonetSubnetsV2(test_plugin.TestSubnetsV2,
                           MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.
    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        pass

    def test_create_subnet_with_v6_allocation_pool(self):
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_create_subnet_dhcp_disabled(self):
        super(TestMidonetSubnetsV2, self)._test_create_subnet(
            enable_dhcp=False)
        self.assertFalse(self.instance.return_value.create_dhcp.called)


class TestMidonetPortsV2(test_plugin.TestPortsV2,
                         MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.
    def test_requested_subnet_id_v4_and_v6(self):
        pass

    def test_create_port_json(self):
        super(TestMidonetPortsV2, self).test_create_port_json()

        # Verify that creating the port resulted in the creation of
        # the correct rule chains for the ports and security groups.
        # If this fails, the reason is likely either in the plugin
        # code that makes the API calls to create the chains
        # (_initialize_port_chains in plugin.py) or in the code that
        # mocks the API calls (mock_lib.py).

        # The order of the chains isn't important, and the UUIDs vary from run
        # to run, so just loop through them to find the ones whose names match
        # the patterns we're looking for.
        chains = self.instance().get_chains(query=None)
        for chain in chains:
            if inbound_chain_regex.match(chain.get_name()):
                self._verify_inbound_chain(chain)
            elif outbound_chain_regex.match(chain.get_name()):
                self._verify_outbound_chain(chain)
            elif egress_chain_regex.match(chain.get_name()):
                self._verify_egress_chain(chain)
            elif ingress_chain_regex.match(chain.get_name()):
                self._verify_ingress_chain(chain)
            else:
                self.Fail("Unexpected chain: " + chain.get_name())

            for rule in chain.get_rules():
                self.assertEqual(chain.get_id(), rule.get_chain_id())

    def _verify_inbound_chain(self, chain):
        rules = chain.get_rules()

        # IP spoofing prevention.
        self.assertEqual(ETHERTYPE_IP4, rules[0].get_dl_type())
        self.assertEqual("drop", rules[0].get_flow_action())
        self.assertTrue(rules[0].get_inv_nw_src())
        self.assertEqual("10.0.0.2", rules[0].get_nw_src_address())
        self.assertEqual(32, rules[0].get_nw_src_length())

        # MAC spoofing prevention.
        self.assertTrue(mac_addr_regex.match(rules[1].get_dl_src()))
        self.assertEqual("drop", rules[1].get_flow_action())
        self.assertTrue(rules[1].get_inv_dl_src())

        # Accept return flow traffic.
        self.assertEqual("accept", rules[2].get_flow_action())
        self.assertTrue(rules[2].is_match_return_flow())

        # Jump to SG egress chain.
        self.assertEqual("jump", rules[3].get_flow_action())
        self.assertTrue(
            egress_chain_regex.match(rules[3].get_jump_chain_name()))

        # Drop non-ARP traffic that doesn't match any other rules.
        self.assertEqual("drop", rules[4].get_flow_action())
        self.assertEqual(ETHERTYPE_ARP, rules[4].get_dl_type())
        self.assertTrue(rules[4].get_inv_dl_type())

    def _verify_outbound_chain(self, chain):
        rules = chain.get_rules()

        # Accept return flow traffic.
        self.assertEqual("accept", rules[0].get_flow_action())
        self.assertTrue(rules[0].is_match_return_flow())

        # Jump to SG ingress chain.
        self.assertEqual("jump", rules[1].get_flow_action())
        self.assertTrue(
            ingress_chain_regex.match(rules[1].get_jump_chain_name()))

        # Drop non-ARP traffic.
        self.assertEqual("drop", rules[2].get_flow_action())
        self.assertEqual(ETHERTYPE_ARP, rules[2].get_dl_type())
        self.assertTrue(rules[2].get_inv_dl_type())

    def _verify_egress_chain(self, chain):
        rules = chain.get_rules()

        # Allow all IPv6 traffic.
        self.assertEqual("accept", rules[0].get_flow_action())
        self.assertEqual(ETHERTYPE_IP6, rules[0].get_dl_type())
        self.assertTrue(rules[0].is_match_forward_flow())

        # Allow all IPv4 traffic.
        self.assertEqual("accept", rules[1].get_flow_action())
        self.assertEqual(ETHERTYPE_IP4, rules[1].get_dl_type())
        self.assertTrue(rules[1].is_match_forward_flow())

    def _verify_ingress_chain(self, chain):
        rules = chain.get_rules()

        # Accept all IPv6 traffic from a particular port group.
        self.assertEqual("accept", rules[0].get_flow_action())
        self.assertEqual(ETHERTYPE_IP6, rules[0].get_dl_type())
        self.assertIsNotNone(rules[0].get_port_group_src())
        self.assertFalse(rules[0].is_match_forward_flow())

        self.assertEqual("accept", rules[1].get_flow_action())
        self.assertEqual(ETHERTYPE_IP4, rules[1].get_dl_type())
        self.assertIsNotNone(rules[1].get_port_group_src())
        self.assertFalse(rules[1].is_match_forward_flow())

