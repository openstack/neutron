# Copyright (c) 2016 IBM Corp.
#
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

import os
import sys

import mock
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_service import service

from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common import topics
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.macvtap.agent import macvtap_neutron_agent
from neutron.plugins.ml2.drivers.macvtap import macvtap_common
from neutron.tests import base


INTERFACE_MAPPINGS = {'physnet1': 'eth1'}
NETWORK_ID = 'net-id123'
NETWORK_SEGMENT_VLAN = amb.NetworkSegment('vlan', 'physnet1', 1)
NETWORK_SEGMENT_FLAT = amb.NetworkSegment('flat', 'physnet1', None)


class TestMacvtapRPCCallbacks(base.BaseTestCase):
    def setUp(self):
        super(TestMacvtapRPCCallbacks, self).setUp()

        agent = mock.Mock()
        agent.mgr = mock.Mock()
        agent.mgr.interface_mappings = INTERFACE_MAPPINGS
        self.rpc = macvtap_neutron_agent.MacvtapRPCCallBack(mock.Mock(), agent,
                                                            mock.Mock())

    def test_network_delete_vlan(self):
        self.rpc.network_map = {NETWORK_ID: NETWORK_SEGMENT_VLAN}
        with mock.patch.object(ip_lib.IpLinkCommand, 'delete') as mock_del,\
                mock.patch.object(macvtap_common, 'get_vlan_device_name',
                                  return_value='vlan1'),\
                mock.patch.object(ip_lib.IPDevice, 'exists',
                                  return_value=True):
            self.rpc.network_delete("anycontext", network_id=NETWORK_ID)
            self.assertTrue(mock_del.called)

    def test_network_delete_flat(self):
        self.rpc.network_map = {NETWORK_ID: NETWORK_SEGMENT_FLAT}
        with mock.patch.object(ip_lib.IpLinkCommand, 'delete') as mock_del:
            self.rpc.network_delete(
                "anycontext", network_id=NETWORK_SEGMENT_FLAT.segmentation_id)
            self.assertFalse(mock_del.called)

    def test_port_update(self):
        port = {'id': 'port-id123', 'mac_address': 'mac1'}
        self.rpc.port_update(context=None, port=port)
        self.assertEqual(set(['mac1']), self.rpc.updated_devices)


class TestMacvtapManager(base.BaseTestCase):
    def setUp(self):
        super(TestMacvtapManager, self).setUp()
        with mock.patch.object(ip_lib, 'device_exists', return_value=True):
            self.mgr = macvtap_neutron_agent.MacvtapManager(INTERFACE_MAPPINGS)

    def test_validate_interface_mappings_dev_exists(self):
        good_mapping = {'physnet1': 'eth1', 'physnet2': 'eth2'}
        self.mgr.interface_mappings = good_mapping
        with mock.patch.object(ip_lib, 'device_exists', return_value=True)\
            as mock_de:
            self.mgr.validate_interface_mappings()
            mock_de.assert_any_call('eth1')
            mock_de.assert_any_call('eth2')
            self.assertEqual(2, mock_de.call_count)

    def test_validate_interface_mappings_dev_not_exists(self):
        bad_mapping = {'physnet1': 'foo'}
        self.mgr.interface_mappings = bad_mapping
        with mock.patch.object(ip_lib, 'device_exists', return_value=False)\
            as mock_de, mock.patch.object(sys, 'exit') as mock_exit:
            self.mgr.validate_interface_mappings()
            mock_de.assert_called_with('foo')
            mock_exit.assert_called_once_with(1)

    def _test_ensure_port_admin_state(self, admin_state):
        dev = 'macvtap1'
        mac = 'mac1'

        self.mgr.mac_device_name_mappings = {mac: dev}
        with mock.patch.object(ip_lib, 'IPDevice') as mock_ip_dev:
            self.mgr.ensure_port_admin_state(mac, admin_state)
            self.assertEqual(admin_state, mock_ip_dev(dev).link.set_up.called)
            self.assertNotEqual(admin_state,
                                mock_ip_dev(dev).link.set_down.called)

    def test_ensure_port_admin_state_up(self):
        self._test_ensure_port_admin_state(True)

    def test_ensure_port_admin_state_down(self):
        self._test_ensure_port_admin_state(False)

    def test_get_all_devices(self):
        listing = ['foo', 'macvtap0', 'macvtap1', 'bar']
        # set some mac mappings to make sure they are cleaned up
        self.mgr.mac_device_name_mappings = {'foo': 'bar'}
        with mock.patch.object(os, 'listdir', return_value=listing)\
            as mock_ld,\
            mock.patch.object(ip_lib, 'get_device_mac') as mock_gdn:
            mock_gdn.side_effect = ['mac0', 'mac1']

            result = self.mgr.get_all_devices()
            mock_ld.assert_called_once_with(macvtap_neutron_agent.MACVTAP_FS)
            self.assertEqual(set(['mac0', 'mac1']), result)
            self.assertEqual({'mac0': 'macvtap0', 'mac1': 'macvtap1'},
                             self.mgr.mac_device_name_mappings)

    def test_get_agent_configurations(self):
        expected = {'interface_mappings': INTERFACE_MAPPINGS}
        self.assertEqual(expected, self.mgr.get_agent_configurations())

    def test_get_agent_id_ok(self):
        mock_devices = [ip_lib.IPDevice('macvtap1')]
        with mock.patch.object(ip_lib.IPWrapper, 'get_devices',
                               return_value=mock_devices),\
            mock.patch.object(ip_lib, 'get_device_mac',
                              return_value='foo:bar'):
            self.assertEqual('macvtapfoobar', self.mgr.get_agent_id())

    def test_get_agent_id_fail(self):
        mock_devices = []
        with mock.patch.object(ip_lib.IPWrapper, 'get_devices',
                               return_value=mock_devices),\
            mock.patch.object(sys, 'exit') as mock_exit:
            self.mgr.get_agent_id()
            mock_exit.assert_called_once_with(1)

    def test_get_extension_driver_type(self):
        self.assertEqual('macvtap', self.mgr.get_extension_driver_type())

    def test_get_rpc_callbacks(self):
        context = mock.Mock()
        agent = mock.Mock()
        sg_agent = mock.Mock()
        obj = self.mgr.get_rpc_callbacks(context, agent, sg_agent)
        self.assertIsInstance(obj, macvtap_neutron_agent.MacvtapRPCCallBack)

    def test_get_rpc_consumers(self):
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.assertEqual(consumers, self.mgr.get_rpc_consumers())

    def test_plug_interface(self):
        self.mgr.mac_device_name_mappings['mac1'] = 'macvtap0'
        with mock.patch.object(ip_lib.IpLinkCommand, 'set_allmulticast_on')\
            as mock_sao:
            self.mgr.plug_interface('network_id', 'network_segment', 'mac1',
                                    'device_owner')
            self.assertTrue(mock_sao.called)


class TestMacvtapMain(base.BaseTestCase):
    def test_parse_interface_mappings_good(self):
        cfg.CONF.set_override('physical_interface_mappings', 'good_mapping',
                              'macvtap')
        with mock.patch.object(helpers, 'parse_mappings',
                               return_value=INTERFACE_MAPPINGS):
            mappings = macvtap_neutron_agent.parse_interface_mappings()
            self.assertEqual(INTERFACE_MAPPINGS, mappings)

    def test_parse_interface_mappings_bad(self):
        cfg.CONF.set_override('physical_interface_mappings', 'bad_mapping',
                              'macvtap')
        with mock.patch.object(helpers, 'parse_mappings',
                               side_effect=ValueError('bad mapping')),\
            mock.patch.object(sys, 'exit') as mock_exit:
            macvtap_neutron_agent.parse_interface_mappings()
            mock_exit.assert_called_with(1)

    def test_parse_interface_mappings_no_mapping(self):
        with mock.patch.object(sys, 'exit') as mock_exit:
            macvtap_neutron_agent.parse_interface_mappings()
            mock_exit.assert_called_with(1)

    def test_validate_firewall_driver_noop_long(self):
        cfg.CONF.set_override('firewall_driver',
                              'neutron.agent.firewall.NoopFirewallDriver',
                              'SECURITYGROUP')
        macvtap_neutron_agent.validate_firewall_driver()

    def test_validate_firewall_driver_noop(self):
        cfg.CONF.set_override('firewall_driver',
                              'noop',
                              'SECURITYGROUP')
        macvtap_neutron_agent.validate_firewall_driver()

    def test_validate_firewall_driver_other(self):
        cfg.CONF.set_override('firewall_driver',
                              'foo',
                              'SECURITYGROUP')
        with mock.patch.object(sys, 'exit')as mock_exit:
            macvtap_neutron_agent.validate_firewall_driver()
            mock_exit.assert_called_with(1)

    def test_main(self):
        cfg.CONF.set_override('quitting_rpc_timeout', 1, 'AGENT')
        cfg.CONF.set_override('polling_interval', 2, 'AGENT')

        mock_manager_return = mock.Mock(spec=amb.CommonAgentManagerBase)
        mock_launch_return = mock.Mock()

        with mock.patch.object(common_config, 'init'),\
            mock.patch.object(common_config, 'setup_logging'),\
            mock.patch.object(service, 'launch',
                              return_value=mock_launch_return) as mock_launch,\
            mock.patch.object(macvtap_neutron_agent,
                              'parse_interface_mappings',
                              return_value=INTERFACE_MAPPINGS) as mock_pim,\
            mock.patch.object(macvtap_neutron_agent,
                              'validate_firewall_driver') as mock_vfd,\
            mock.patch('neutron.plugins.ml2.drivers.agent._common_agent.'
                       'CommonAgentLoop') as mock_loop,\
            mock.patch('neutron.plugins.ml2.drivers.macvtap.agent.'
                       'macvtap_neutron_agent.MacvtapManager',
                       return_value=mock_manager_return) as mock_manager:
            macvtap_neutron_agent.main()
            self.assertTrue(mock_vfd.called)
            self.assertTrue(mock_pim.called)
            mock_manager.assert_called_with(INTERFACE_MAPPINGS)
            mock_loop.assert_called_with(mock_manager_return, 2, 1,
                                         'Macvtap agent',
                                         'neutron-macvtap-agent')
            self.assertTrue(mock_launch.called)
            self.assertTrue(mock_launch_return.wait.called)
