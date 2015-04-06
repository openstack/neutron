# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import mock
from oslo_config import cfg

from neutron.plugins.sriovnicagent.common import config  # noqa
from neutron.plugins.sriovnicagent import sriov_nic_agent
from neutron.tests import base

DEVICE_MAC = '11:22:33:44:55:66'


class TestSriovAgent(base.BaseTestCase):
    def setUp(self):
        super(TestSriovAgent, self).setUp()
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('enable_security_group',
                             False,
                             group='SECURITYGROUP')

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        mock.patch('neutron.openstack.common.loopingcall.'
                   'FixedIntervalLoopingCall',
                   new=MockFixedIntervalLoopingCall)

        self.agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0)

    def test_treat_devices_removed_with_existed_device(self):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0)
        devices = [DEVICE_MAC]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd:
            fn_udd.return_value = {'device': DEVICE_MAC,
                                   'exists': True}
            with mock.patch.object(sriov_nic_agent.LOG,
                                   'info') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(2, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)

    def test_treat_devices_removed_with_not_existed_device(self):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0)
        devices = [DEVICE_MAC]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd:
            fn_udd.return_value = {'device': DEVICE_MAC,
                                   'exists': False}
            with mock.patch.object(sriov_nic_agent.LOG,
                                   'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(1, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)

    def test_treat_devices_removed_failed(self):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0)
        devices = [DEVICE_MAC]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd:
            fn_udd.side_effect = Exception()
            with mock.patch.object(sriov_nic_agent.LOG,
                                   'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(1, log.call_count)
                self.assertTrue(resync)
                self.assertTrue(fn_udd.called)

    def mock_scan_devices(self, expected, mock_current,
                          registered_devices, updated_devices):
        self.agent.eswitch_mgr = mock.Mock()
        self.agent.eswitch_mgr.get_assigned_devices.return_value = mock_current

        results = self.agent.scan_devices(registered_devices, updated_devices)
        self.assertEqual(expected, results)

    def test_scan_devices_returns_empty_sets(self):
        registered = set()
        updated = set()
        mock_current = set()
        expected = {'current': set(),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        self.mock_scan_devices(expected, mock_current, registered, updated)

    def test_scan_devices_no_changes(self):
        registered = set(['1', '2'])
        updated = set()
        mock_current = set(['1', '2'])
        expected = {'current': set(['1', '2']),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        self.mock_scan_devices(expected, mock_current, registered, updated)

    def test_scan_devices_new_and_removed(self):
        registered = set(['1', '2'])
        updated = set()
        mock_current = set(['2', '3'])
        expected = {'current': set(['2', '3']),
                    'updated': set(),
                    'added': set(['3']),
                    'removed': set(['1'])}
        self.mock_scan_devices(expected, mock_current, registered, updated)

    def test_scan_devices_new_updates(self):
        registered = set(['1'])
        updated = set(['2'])
        mock_current = set(['1', '2'])
        expected = {'current': set(['1', '2']),
                    'updated': set(['2']),
                    'added': set(['2']),
                    'removed': set()}
        self.mock_scan_devices(expected, mock_current, registered, updated)

    def test_scan_devices_updated_missing(self):
        registered = set(['1'])
        updated = set(['2'])
        mock_current = set(['1'])
        expected = {'current': set(['1']),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        self.mock_scan_devices(expected, mock_current, registered, updated)

    def test_process_network_devices(self):
        agent = self.agent
        device_info = {'current': set(),
                       'added': set(['mac3', 'mac4']),
                       'updated': set(['mac2', 'mac3']),
                       'removed': set(['mac1'])}
        agent.sg_agent.prepare_devices_filter = mock.Mock()
        agent.sg_agent.refresh_firewall = mock.Mock()
        agent.treat_devices_added_updated = mock.Mock(return_value=False)
        agent.treat_devices_removed = mock.Mock(return_value=False)

        agent.process_network_devices(device_info)

        agent.sg_agent.prepare_devices_filter.assert_called_with(
                set(['mac3', 'mac4']))
        self.assertTrue(agent.sg_agent.refresh_firewall.called)
        agent.treat_devices_added_updated.assert_called_with(set(['mac2',
                                                                  'mac3',
                                                                  'mac4']))
        agent.treat_devices_removed.assert_called_with(set(['mac1']))

    def test_treat_devices_added_updated_admin_state_up_true(self):
        agent = self.agent
        mock_details = {'device': 'aa:bb:cc:dd:ee:ff',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': '1:2:3.0'},
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.set_device_state = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(
                                    set(['aa:bb:cc:dd:ee:ff']))

        self.assertFalse(resync_needed)
        agent.eswitch_mgr.device_exists.assert_called_with('aa:bb:cc:dd:ee:ff',
                                                          '1:2:3.0')
        agent.eswitch_mgr.set_device_state.assert_called_with(
                                        'aa:bb:cc:dd:ee:ff',
                                        '1:2:3.0',
                                        True)
        self.assertTrue(agent.plugin_rpc.update_device_up.called)

    def test_treat_devices_added_updated_admin_state_up_false(self):
        agent = self.agent
        mock_details = {'device': 'aa:bb:cc:dd:ee:ff',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': '1:2:3.0'},
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.remove_port_binding = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(
                            set(['aa:bb:cc:dd:ee:ff']))

        self.assertFalse(resync_needed)
        self.assertFalse(agent.plugin_rpc.update_device_up.called)
