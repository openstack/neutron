# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
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

import mock
import unittest2 as unittest

from quantum.openstack.common import cfg
from quantum.plugins.openvswitch.agent import ovs_quantum_agent
from quantum.plugins.openvswitch.common import config


class TestParseBridgeMappings(unittest.TestCase):

    def parse(self, bridge_mapping_list):
        return ovs_quantum_agent.parse_bridge_mappings(bridge_mapping_list)

    def test_parse_bridge_mappings_fails_for_missing_separator(self):
        with self.assertRaises(ValueError):
            self.parse(['net'])

    def test_parse_bridge_mappings_fails_for_missing_value(self):
        with self.assertRaises(ValueError):
            self.parse(['net:'])

    def test_parse_bridge_mappings_succeeds_for_one_mapping(self):
        self.assertEqual(self.parse(['net:br']), {'net': 'br'})

    def test_parse_bridge_mappings_succeeds_for_n_mappings(self):
        self.assertEqual(self.parse(['net:br', 'net1:br1']),
                         {'net': 'br', 'net1': 'br1'})

    def test_parse_bridge_mappings_succeeds_for_no_mappings(self):
        self.assertEqual(self.parse(['']), {})


class CreateAgentConfigMap(unittest.TestCase):

    def test_create_agent_config_map_succeeds(self):
        self.assertTrue(ovs_quantum_agent.create_agent_config_map(cfg.CONF))

    def test_create_agent_config_map_fails_for_invalid_tunnel_config(self):
        self.addCleanup(cfg.CONF.reset)
        # An ip address is required for tunneling but there is no default
        cfg.CONF.set_override('enable_tunneling', True, group='OVS')
        with self.assertRaises(ValueError):
            ovs_quantum_agent.create_agent_config_map(cfg.CONF)


class TestOvsQuantumAgent(unittest.TestCase):

    def setUp(self):
        self.addCleanup(cfg.CONF.reset)
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        kwargs = ovs_quantum_agent.create_agent_config_map(cfg.CONF)
        with mock.patch('quantum.plugins.openvswitch.agent.ovs_quantum_agent.'
                        'OVSQuantumAgent.setup_integration_br',
                        return_value=mock.Mock()):
            with mock.patch('quantum.agent.linux.utils.get_interface_mac',
                            return_value='000000000001'):
                self.agent = ovs_quantum_agent.OVSQuantumAgent(**kwargs)
        self.agent.plugin_rpc = mock.Mock()
        self.agent.context = mock.Mock()
        self.agent.agent_id = mock.Mock()

    def mock_port_bound(self, ofport=None):
        port = mock.Mock()
        port.ofport = ofport
        net_uuid = 'my-net-uuid'
        with mock.patch.object(self.agent.int_br,
                               'delete_flows') as delete_flows_func:
            self.agent.port_bound(port, net_uuid, 'local', None, None)
        self.assertEqual(delete_flows_func.called, ofport != -1)

    def test_port_bound_deletes_flows_for_valid_ofport(self):
        self.mock_port_bound(ofport=1)

    def test_port_bound_ignores_flows_for_invalid_ofport(self):
        self.mock_port_bound(ofport=-1)

    def test_port_dead(self):
        with mock.patch.object(self.agent.int_br,
                               'add_flow') as add_flow_func:
            self.agent.port_dead(mock.Mock())
        self.assertTrue(add_flow_func.called)

    def mock_update_ports(self, vif_port_set=None, registered_ports=None):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_set',
                               return_value=vif_port_set):
            return self.agent.update_ports(registered_ports)

    def test_update_ports_returns_none_for_unchanged_ports(self):
        self.assertIsNone(self.mock_update_ports())

    def test_update_ports_returns_port_changes(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]), removed=set([2]))
        actual = self.mock_update_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_treat_devices_added_returns_true_for_missing_device(self):
        with mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                               side_effect=Exception()):
            self.assertTrue(self.agent.treat_devices_added([{}]))

    def mock_treat_devices_added(self, details, port, func_name):
        """

        :param details: the details to return for the device
        :param port: the port that get_vif_port_by_id should return
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                               return_value=details):
            with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                                   return_value=port):
                with mock.patch.object(self.agent, func_name) as func:
                    self.assertFalse(self.agent.treat_devices_added([{}]))
        return func.called

    def test_treat_devices_added_ignores_invalid_ofport(self):
        port = mock.Mock()
        port.ofport = -1
        self.assertFalse(self.mock_treat_devices_added(mock.MagicMock(), port,
                                                       'port_dead'))

    def test_treat_devices_added_marks_unknown_port_as_dead(self):
        port = mock.Mock()
        port.ofport = 1
        self.assertTrue(self.mock_treat_devices_added(mock.MagicMock(), port,
                                                      'port_dead'))

    def test_treat_devices_added_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        self.assertTrue(self.mock_treat_devices_added(details,
                                                      mock.Mock(),
                                                      'treat_vif_port'))

    def test_treat_devices_removed_returns_true_for_missing_device(self):
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               side_effect=Exception()):
            self.assertTrue(self.agent.treat_devices_removed([{}]))

    def mock_treat_devices_removed(self, port_exists):
        details = dict(exists=port_exists)
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               return_value=details):
            with mock.patch.object(self.agent, 'port_unbound') as func:
                self.assertFalse(self.agent.treat_devices_removed([{}]))
        self.assertEqual(func.called, not port_exists)

    def test_treat_devices_removed_unbinds_port(self):
        self.mock_treat_devices_removed(False)

    def test_treat_devices_removed_ignores_missing_port(self):
        self.mock_treat_devices_removed(False)
