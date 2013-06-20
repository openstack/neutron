# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
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

import contextlib

import mock
from oslo.config import cfg
import testtools

from quantum.plugins.openvswitch.agent import ovs_quantum_agent
from quantum.tests import base


NOTIFIER = ('quantum.plugins.openvswitch.'
            'ovs_quantum_plugin.AgentNotifierApi')


class CreateAgentConfigMap(base.BaseTestCase):

    def test_create_agent_config_map_succeeds(self):
        self.assertTrue(ovs_quantum_agent.create_agent_config_map(cfg.CONF))

    def test_create_agent_config_map_fails_for_invalid_tunnel_config(self):
        self.addCleanup(cfg.CONF.reset)
        # An ip address is required for tunneling but there is no default
        cfg.CONF.set_override('enable_tunneling', True, group='OVS')
        with testtools.ExpectedException(ValueError):
            ovs_quantum_agent.create_agent_config_map(cfg.CONF)


class TestOvsQuantumAgent(base.BaseTestCase):

    def setUp(self):
        super(TestOvsQuantumAgent, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(mock.patch.stopall)
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        kwargs = ovs_quantum_agent.create_agent_config_map(cfg.CONF)
        with mock.patch('quantum.plugins.openvswitch.agent.ovs_quantum_agent.'
                        'OVSQuantumAgent.setup_integration_br',
                        return_value=mock.Mock()):
            with mock.patch(
                'quantum.plugins.openvswitch.agent.ovs_quantum_agent.'
                'OVSQuantumAgent.setup_ancillary_bridges',
                return_value=[]):
                with mock.patch('quantum.agent.linux.utils.get_interface_mac',
                                return_value='000000000001'):
                    self.agent = ovs_quantum_agent.OVSQuantumAgent(**kwargs)
        self.agent.sg_agent = mock.Mock()

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
            with mock.patch.object(self.agent, 'port_unbound') as port_unbound:
                self.assertFalse(self.agent.treat_devices_removed([{}]))
        self.assertEqual(port_unbound.called, not port_exists)

    def test_treat_devices_removed_unbinds_port(self):
        self.mock_treat_devices_removed(False)

    def test_treat_devices_removed_ignores_missing_port(self):
        self.mock_treat_devices_removed(False)

    def test_port_update(self):
        port = {'id': 1,
                'network_id': 1,
                'admin_state_up': True}
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value='2'):
            with mock.patch.object(self.agent.plugin_rpc,
                                   'update_device_up') as device_up:
                with mock.patch.object(self.agent, 'port_bound') as port_bound:
                    self.agent.port_update(mock.Mock(), port=port)
                    self.assertTrue(port_bound.called)
                    self.assertTrue(device_up.called)
            with mock.patch.object(self.agent.plugin_rpc,
                                   'update_device_down') as device_down:
                with mock.patch.object(self.agent, 'port_dead') as port_dead:
                    port['admin_state_up'] = False
                    self.agent.port_update(mock.Mock(), port=port)
                    self.assertTrue(port_dead.called)
                    self.assertTrue(device_down.called)

    def test_process_network_ports(self):
        reply = {'current': set(['tap0']),
                 'removed': set(['eth0']),
                 'added': set(['eth1'])}
        with mock.patch.object(self.agent, 'treat_devices_added',
                               return_value=False) as device_added:
            with mock.patch.object(self.agent, 'treat_devices_removed',
                                   return_value=False) as device_removed:
                self.assertFalse(self.agent.process_network_ports(reply))
                self.assertTrue(device_added.called)
                self.assertTrue(device_removed.called)


class AncillaryBridgesTest(base.BaseTestCase):

    def setUp(self):
        super(AncillaryBridgesTest, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(mock.patch.stopall)
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        self.kwargs = ovs_quantum_agent.create_agent_config_map(cfg.CONF)

    def _test_ancillary_bridges(self, bridges, ancillary):
        device_ids = ancillary[:]

        def pullup_side_effect(self, *args):
            result = device_ids.pop(0)
            return result

        with contextlib.nested(
            mock.patch('quantum.plugins.openvswitch.agent.ovs_quantum_agent.'
                       'OVSQuantumAgent.setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('quantum.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('quantum.agent.linux.ovs_lib.get_bridges',
                       return_value=bridges),
            mock.patch(
                'quantum.agent.linux.ovs_lib.get_bridge_external_bridge_id',
                side_effect=pullup_side_effect)):
            self.agent = ovs_quantum_agent.OVSQuantumAgent(**self.kwargs)
            self.assertEqual(len(ancillary), len(self.agent.ancillary_brs))
            if ancillary:
                bridges = [br.br_name for br in self.agent.ancillary_brs]
                for br in ancillary:
                    self.assertIn(br, bridges)

    def test_ancillary_bridges_single(self):
        bridges = ['br-int', 'br-ex']
        self._test_ancillary_bridges(bridges, ['br-ex'])

    def test_ancillary_bridges_none(self):
        bridges = ['br-int']
        self._test_ancillary_bridges(bridges, [])

    def test_ancillary_bridges_multiple(self):
        bridges = ['br-int', 'br-ex1', 'br-ex2']
        self._test_ancillary_bridges(bridges, ['br-ex1', 'br-ex2'])
