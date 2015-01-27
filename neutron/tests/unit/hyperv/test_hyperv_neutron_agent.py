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
Unit tests for Windows Hyper-V virtual switch neutron driver
"""

import mock
from oslo_config import cfg

from neutron.plugins.hyperv.agent import hyperv_neutron_agent
from neutron.plugins.hyperv.agent import utilsfactory
from neutron.tests import base

cfg.CONF.import_opt('enable_metrics_collection',
                    'neutron.plugins.hyperv.agent.hyperv_neutron_agent',
                    'AGENT')


class TestHyperVNeutronAgent(base.BaseTestCase):

    _FAKE_PORT_ID = 'fake_port_id'

    def setUp(self):
        super(TestHyperVNeutronAgent, self).setUp()

        utilsfactory._get_windows_version = mock.MagicMock(
            return_value='6.2.0')

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        mock.patch('neutron.openstack.common.loopingcall.'
                   'FixedIntervalLoopingCall',
                   new=MockFixedIntervalLoopingCall).start()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.agent = hyperv_neutron_agent.HyperVNeutronAgent()
        self.agent.plugin_rpc = mock.Mock()
        self.agent.sec_groups_agent = mock.MagicMock()
        self.agent.sg_plugin_rpc = mock.Mock()
        self.agent.context = mock.Mock()
        self.agent.agent_id = mock.Mock()

        fake_agent_state = {
            'binary': 'neutron-hyperv-agent',
            'host': 'fake_host_name',
            'topic': 'N/A',
            'configurations': {'vswitch_mappings': ['*:MyVirtualSwitch']},
            'agent_type': 'HyperV agent',
            'start_flag': True}
        self.agent_state = fake_agent_state

    def test_use_enhanced_rpc(self):
        self.agent.sec_groups_agent = hyperv_neutron_agent.HyperVSecurityAgent(
            self.agent.context, self.agent.sg_plugin_rpc)
        self.assertFalse(self.agent.sec_groups_agent.use_enhanced_rpc)

    def test_port_bound_enable_metrics(self):
        cfg.CONF.set_override('enable_metrics_collection', True, 'AGENT')
        self._test_port_bound(True)

    def test_port_bound_no_metrics(self):
        cfg.CONF.set_override('enable_metrics_collection', False, 'AGENT')
        self._test_port_bound(False)

    def _test_port_bound(self, enable_metrics):
        port = mock.MagicMock()
        mock_enable_metrics = mock.MagicMock()
        net_uuid = 'my-net-uuid'

        with mock.patch.multiple(
                self.agent._utils,
                connect_vnic_to_vswitch=mock.MagicMock(),
                set_vswitch_port_vlan_id=mock.MagicMock(),
                enable_port_metrics_collection=mock_enable_metrics):

            self.agent._port_bound(port, net_uuid, 'vlan', None, None)

            self.assertEqual(enable_metrics, mock_enable_metrics.called)

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

    def test_port_enable_control_metrics_ok(self):
        cfg.CONF.set_override('enable_metrics_collection', True, 'AGENT')
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = (
            cfg.CONF.AGENT.metrics_max_retries)

        with mock.patch.multiple(self.agent._utils,
                                 can_enable_control_metrics=mock.MagicMock(),
                                 enable_control_metrics=mock.MagicMock()):

            self.agent._utils.can_enable_control_metrics.return_value = True
            self.agent._port_enable_control_metrics()
            self.agent._utils.enable_control_metrics.assert_called_with(
                self._FAKE_PORT_ID)

        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_port_enable_control_metrics_maxed(self):
        cfg.CONF.set_override('enable_metrics_collection', True, 'AGENT')
        cfg.CONF.set_override('metrics_max_retries', 3, 'AGENT')
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = (
            cfg.CONF.AGENT.metrics_max_retries)

        with mock.patch.multiple(self.agent._utils,
                                 can_enable_control_metrics=mock.MagicMock(),
                                 enable_control_metrics=mock.MagicMock()):

            self.agent._utils.can_enable_control_metrics.return_value = False
            for i in range(cfg.CONF.AGENT.metrics_max_retries + 1):
                self.assertIn(self._FAKE_PORT_ID,
                              self.agent._port_metric_retries)
                self.agent._port_enable_control_metrics()

        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_treat_devices_added_returns_true_for_missing_device(self):
        attrs = {'get_devices_details_list.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        self.assertTrue(self.agent._treat_devices_added([{}]))

    def mock_treat_devices_added(self, details, func_name):
        """Mock treat devices added.

        :param details: the details to return for the device
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        attrs = {'get_devices_details_list.return_value': [details]}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with mock.patch.object(self.agent, func_name) as func:
            self.assertFalse(self.agent._treat_devices_added([{}]))
        return func.called

    def test_treat_devices_added_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        with mock.patch.object(self.agent.plugin_rpc,
                               "update_device_up") as func:
            self.assertTrue(self.mock_treat_devices_added(details,
                                                          '_treat_vif_port'))
            self.assertTrue(func.called)

    def test_treat_devices_added_missing_port_id(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: False
        with mock.patch.object(self.agent.plugin_rpc,
                               "update_device_up") as func:
            self.assertFalse(self.mock_treat_devices_added(details,
                                                           '_treat_vif_port'))
            self.assertFalse(func.called)

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

    def test_report_state(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)
            self.assertNotIn("start_flag", self.agent.agent_state)

    def test_main(self):
        with mock.patch.object(hyperv_neutron_agent,
                               'HyperVNeutronAgent') as plugin:
            with mock.patch.object(hyperv_neutron_agent,
                                   'common_config') as common_config:
                hyperv_neutron_agent.main()

                self.assertTrue(common_config.init.called)
                self.assertTrue(common_config.setup_logging.called)
                plugin.assert_has_calls([mock.call().daemon_loop()])
