# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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

"""
Unit tests for Windows Hyper-V virtual switch quantum driver
"""

import mock
from oslo.config import cfg

from quantum.plugins.hyperv.agent import hyperv_quantum_agent
from quantum.tests import base


class TestHyperVQuantumAgent(base.BaseTestCase):

    def setUp(self):
        super(TestHyperVQuantumAgent, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        self.agent = hyperv_quantum_agent.HyperVQuantumAgent()
        self.agent.plugin_rpc = mock.Mock()
        self.agent.context = mock.Mock()
        self.agent.agent_id = mock.Mock()
        self.agent._utils = mock.Mock()

    def test_port_bound(self):
        port = mock.Mock()
        net_uuid = 'my-net-uuid'
        with mock.patch.object(
                self.agent._utils, 'connect_vnic_to_vswitch'):
            with mock.patch.object(
                    self.agent._utils, 'set_vswitch_port_vlan_id'):
                    self.agent._port_bound(port, net_uuid, 'vlan', None, None)

    def test_port_unbound(self):
        map = {
            'network_type': 'vlan',
            'vswitch_name': 'fake-vswitch',
            'ports': [],
            'vlan_id': 1}
        net_uuid = 'my-net-uuid'
        network_vswitch_map = (net_uuid, map)
        with mock.patch.object(self.agent,
                               '_get_network_vswitch_map_by_port_id',
                               return_value=network_vswitch_map):
            with mock.patch.object(
                    self.agent._utils,
                    'disconnect_switch_port'):
                self.agent._port_unbound(net_uuid)

    def test_treat_devices_added_returns_true_for_missing_device(self):
        attrs = {'get_device_details.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        self.assertTrue(self.agent._treat_devices_added([{}]))

    def mock_treat_devices_added(self, details, func_name):
        """
        :param details: the details to return for the device
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        attrs = {'get_device_details.return_value': details}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with mock.patch.object(self.agent, func_name) as func:
            self.assertFalse(self.agent._treat_devices_added([{}]))
        return func.called

    def test_treat_devices_added_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        self.assertTrue(self.mock_treat_devices_added(details,
                                                      '_treat_vif_port'))

    def test_treat_devices_removed_returns_true_for_missing_device(self):
        attrs = {'update_device_down.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        self.assertTrue(self.agent._treat_devices_removed([{}]))

    def mock_treat_devices_removed(self, port_exists):
        details = dict(exists=port_exists)
        attrs = {'update_device_down.return_value': details}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with mock.patch.object(self.agent, '_port_unbound') as func:
            self.assertFalse(self.agent._treat_devices_removed([{}]))
        self.assertEqual(func.called, not port_exists)

    def test_treat_devices_removed_unbinds_port(self):
        self.mock_treat_devices_removed(False)

    def test_treat_devices_removed_ignores_missing_port(self):
        self.mock_treat_devices_removed(False)
