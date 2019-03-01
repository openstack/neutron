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
from neutron_lib.api.definitions import portbindings
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.l2 import l2_agent_extensions_manager as l2_ext_manager
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as c_const
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import config  # noqa
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import exceptions
from neutron.plugins.ml2.drivers.mech_sriov.agent import sriov_nic_agent
from neutron.tests import base

DEVICE_MAC = '11:22:33:44:55:66'
PCI_SLOT = "0000:06:00.1"


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

        mock.patch('oslo_service.loopingcall.'
                   'FixedIntervalLoopingCall',
                   new=MockFixedIntervalLoopingCall)

        self.agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0, {}, {})

    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.eswitch_manager"
               ".ESwitchManager.get_assigned_devices_info", return_value=set())
    @mock.patch.object(agent_rpc.PluginReportStateAPI, 'report_state')
    def test_cached_device_count_report_state(self, report_state, get_dev):
        self.agent._report_state()
        agent_conf = self.agent.agent_state['configurations']
        # ensure devices aren't calculated until first scan_devices call
        self.assertNotIn('devices', agent_conf)
        self.agent.scan_devices(set(), set())
        self.assertEqual(0, agent_conf['devices'])
        # ensure report_state doesn't call get_dev
        get_dev.reset_mock()
        get_dev.return_value = set(['dev1', 'dev2'])
        self.agent._report_state()
        self.assertEqual(0, agent_conf['devices'])
        # after a device scan, conf should bump to 2
        self.agent.scan_devices(set(), set())
        self.assertEqual(2, agent_conf['devices'])

    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                "PciDeviceIPWrapper.get_assigned_macs",
                return_value=[(DEVICE_MAC, PCI_SLOT)])
    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                "eswitch_manager.PciOsWrapper.is_assigned_vf",
                return_value=True)
    def test_treat_devices_removed_with_existed_device(self, *args):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0, {}, {})
        devices = [(DEVICE_MAC, PCI_SLOT)]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd:
            fn_udd.return_value = {'device': DEVICE_MAC,
                                   'exists': True}
            resync = agent.treat_devices_removed(devices)
            self.assertFalse(resync)
            self.assertTrue(fn_udd.called)

    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                "PciDeviceIPWrapper.get_assigned_macs",
                return_value=[(DEVICE_MAC, PCI_SLOT)])
    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                "eswitch_manager.PciOsWrapper.is_assigned_vf",
                return_value=True)
    def test_treat_devices_removed_with_not_existed_device(self, *args):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0, {}, {})
        devices = [(DEVICE_MAC, PCI_SLOT)]
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

    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.pci_lib."
                "PciDeviceIPWrapper.get_assigned_macs",
                return_value=[(DEVICE_MAC, PCI_SLOT)])
    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent."
                "eswitch_manager.PciOsWrapper.is_assigned_vf",
                return_value=True)
    def test_treat_devices_removed_failed(self, *args):
        agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0, {}, {})
        devices = [(DEVICE_MAC, PCI_SLOT)]
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
        self.agent.eswitch_mgr.get_assigned_devices_info.return_value = (
            mock_current)

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

    def test_scan_devices_updated_and_removed(self):
        registered = set(['1', '2'])
        # '1' is in removed and updated tuple
        updated = set(['1'])
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

    def test_treat_devices_added_updated_sends_host(self):
        agent = self.agent
        host = 'host1'
        cfg.CONF.set_override('host', host)
        agent.plugin_rpc = mock.Mock()
        MAC = 'aa:bb:cc:dd:ee:ff'
        device_details = {'device': MAC,
                          'port_id': 'port123',
                          'network_id': 'net123',
                          'admin_state_up': True,
                          'propagate_uplink_status': True,
                          'network_type': 'vlan',
                          'segmentation_id': 100,
                          'profile': {'pci_slot': '1:2:3.0'},
                          'physical_network': 'physnet1',
                          'port_security_enabled': False}
        agent.plugin_rpc.get_devices_details_list.return_value = (
                [device_details])
        agent.treat_devices_added_updated([[MAC]])
        agent.plugin_rpc.get_devices_details_list.assert_called_once_with(
            mock.ANY, set([MAC]), mock.ANY, host)

    def test_treat_devices_added_updated_and_removed(self):
        agent = self.agent
        MAC1 = 'aa:bb:cc:dd:ee:ff'
        SLOT1 = '1:2:3.0'
        MAC2 = 'aa:bb:cc:dd:ee:fe'
        SLOT2 = '1:3:3.0'
        mac_pci_slot_device1 = (MAC1, SLOT1)
        mac_pci_slot_device2 = (MAC2, SLOT2)
        mock_device1_details = {'device': MAC1,
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'propagate_uplink_status': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': SLOT1},
                        'physical_network': 'physnet1',
                        'port_security_enabled': False}
        mock_device2_details = {'device': MAC2,
                        'port_id': 'port124',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'propagate_uplink_status': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': SLOT2},
                        'physical_network': 'physnet1',
                        'port_security_enabled': False}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = (
                [mock_device1_details])
        agent.treat_devices_added_updated(set([MAC1]))
        self.assertEqual({'net123': [{'port_id': 'port123',
                         'device': mac_pci_slot_device1}]},
                         agent.network_ports)
        agent.plugin_rpc.get_devices_details_list.return_value = (
                [mock_device2_details])
        # add the second device and check the network_ports dict
        agent.treat_devices_added_updated(set([MAC2]))
        self.assertEqual(
                {'net123': [{'port_id': 'port123',
                'device': mac_pci_slot_device1}, {'port_id': 'port124',
                'device': mac_pci_slot_device2}]},
                agent.network_ports)
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down"):
            agent.treat_devices_removed([mac_pci_slot_device2])
        # remove the second device and check the network_ports dict
        self.assertEqual({'net123': [{'port_id': 'port123',
                         'device': mac_pci_slot_device1}]},
                         agent.network_ports)

    def test_treat_devices_added_updated_admin_state_up_true(self):
        agent = self.agent
        mock_details = {'device': 'aa:bb:cc:dd:ee:ff',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'propagate_uplink_status': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': '1:2:3.0'},
                        'physical_network': 'physnet1',
                        'port_security_enabled': False}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.set_device_state = mock.Mock()
        agent.set_device_spoofcheck = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(
                                    set(['aa:bb:cc:dd:ee:ff']))

        self.assertFalse(resync_needed)
        agent.eswitch_mgr.device_exists.assert_called_with('aa:bb:cc:dd:ee:ff',
                                                          '1:2:3.0')
        agent.eswitch_mgr.set_device_state.assert_called_with(
                                        'aa:bb:cc:dd:ee:ff',
                                        '1:2:3.0',
                                        True, False)
        agent.eswitch_mgr.set_device_spoofcheck.assert_called_with(
                                        'aa:bb:cc:dd:ee:ff',
                                        '1:2:3.0',
                                        False)
        agent.plugin_rpc.update_device_list.assert_called_once_with(
                mock.ANY,
                set(['aa:bb:cc:dd:ee:ff']),
                set(),
                mock.ANY,
                mock.ANY)

    def test_treat_devices_added_updated_multiple_admin_state_up_true(self):
        agent = self.agent
        mock_details = [{'device': 'aa:bb:cc:dd:ee:ff',
                         'port_id': 'port123',
                         'network_id': 'net123',
                         'admin_state_up': True,
                         'propagate_uplink_status': False,
                         'network_type': 'vlan',
                         'segmentation_id': 100,
                         'profile': {'pci_slot': '1:2:3.0'},
                         'physical_network': 'physnet1',
                         'port_security_enabled': False},
                        {'device': '11:22:33:44:55:66',
                         'port_id': 'port321',
                         'network_id': 'net123',
                         'admin_state_up': True,
                         'propagate_uplink_status': False,
                         'network_type': 'vlan',
                         'segmentation_id': 100,
                         'profile': {'pci_slot': '1:2:3.0'},
                         'physical_network': 'physnet1',
                         'port_security_enabled': False}]
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = mock_details
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.set_device_state = mock.Mock()
        agent.set_device_spoofcheck = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(
                                    set(['aa:bb:cc:dd:ee:ff',
                                         '11:22:33:44:55:66']))
        self.assertFalse(resync_needed)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0'),
                 mock.call('11:22:33:44:55:66', '1:2:3.0')]
        agent.eswitch_mgr.device_exists.assert_has_calls(calls, any_order=True)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0', True, False),
                 mock.call('11:22:33:44:55:66', '1:2:3.0', True, False)]
        agent.eswitch_mgr.set_device_state.assert_has_calls(calls,
                                                            any_order=True)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0', False),
                 mock.call('11:22:33:44:55:66', '1:2:3.0', False)]
        agent.eswitch_mgr.set_device_spoofcheck.assert_has_calls(calls,
                                                                any_order=True)
        agent.plugin_rpc.update_device_list.assert_called_once_with(
                mock.ANY,
                set(['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']),
                set(),
                mock.ANY,
                mock.ANY)

    def test_treat_devices_added_updated_multiple_admin_states(self):
        agent = self.agent
        mock_details = [{'device': 'aa:bb:cc:dd:ee:ff',
                         'port_id': 'port123',
                         'network_id': 'net123',
                         'admin_state_up': True,
                         'propagate_uplink_status': False,
                         'network_type': 'vlan',
                         'segmentation_id': 100,
                         'profile': {'pci_slot': '1:2:3.0'},
                         'physical_network': 'physnet1',
                         'port_security_enabled': False},
                        {'device': '11:22:33:44:55:66',
                         'port_id': 'port321',
                         'network_id': 'net123',
                         'admin_state_up': False,
                         'propagate_uplink_status': False,
                         'network_type': 'vlan',
                         'segmentation_id': 100,
                         'profile': {'pci_slot': '1:2:3.0'},
                         'physical_network': 'physnet1',
                         'port_security_enabled': False}]
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = mock_details
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.set_device_state = mock.Mock()
        agent.set_device_spoofcheck = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(
                                    set(['aa:bb:cc:dd:ee:ff',
                                         '11:22:33:44:55:66']))
        self.assertFalse(resync_needed)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0'),
                 mock.call('11:22:33:44:55:66', '1:2:3.0')]
        agent.eswitch_mgr.device_exists.assert_has_calls(calls, any_order=True)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0', True, False),
                 mock.call('11:22:33:44:55:66', '1:2:3.0', False, False)]
        agent.eswitch_mgr.set_device_state.assert_has_calls(calls,
                                                            any_order=True)
        calls = [mock.call('aa:bb:cc:dd:ee:ff', '1:2:3.0', False),
                 mock.call('11:22:33:44:55:66', '1:2:3.0', False)]
        agent.eswitch_mgr.set_device_spoofcheck.assert_has_calls(calls,
                                                                any_order=True)
        agent.plugin_rpc.update_device_list.assert_called_once_with(
                mock.ANY,
                set(['aa:bb:cc:dd:ee:ff']),
                set(['11:22:33:44:55:66']),
                mock.ANY,
                mock.ANY)

    def test_treat_device_ip_link_state_not_supported(self):
        agent = self.agent
        agent.plugin_rpc = mock.Mock()
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.eswitch_mgr.set_device_state.side_effect = (
            exceptions.IpCommandOperationNotSupportedError(
                dev_name='aa:bb:cc:dd:ee:ff'))

        self.assertTrue(agent.treat_device('aa:bb:cc:dd:ee:ff', '1:2:3:0',
                                           admin_state_up=True))

    def test_treat_device_set_device_state_exception(self):
        agent = self.agent
        agent.plugin_rpc = mock.Mock()
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        agent.eswitch_mgr.set_device_state.side_effect = (
            exceptions.SriovNicError())

        self.assertFalse(agent.treat_device('aa:bb:cc:dd:ee:ff', '1:2:3:0',
                                           admin_state_up=True))

    def test_treat_device_no_device_found(self):
        agent = self.agent
        agent.plugin_rpc = mock.Mock()
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = False

        self.assertFalse(agent.treat_device('aa:bb:cc:dd:ee:ff', '1:2:3:0',
                                            admin_state_up=True))

    def test_treat_devices_added_updated_admin_state_up_false(self):
        agent = self.agent
        mock_details = {'device': 'aa:bb:cc:dd:ee:ff',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': False,
                        'propagate_uplink_status': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': '1:2:3.0'},
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.remove_port_binding = mock.Mock()
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = True
        resync_needed = agent.treat_devices_added_updated(
                            set(['aa:bb:cc:dd:ee:ff']))
        self.assertFalse(resync_needed)
        agent.plugin_rpc.update_device_list.assert_called_once_with(
                mock.ANY,
                set(),
                set(['aa:bb:cc:dd:ee:ff']),
                mock.ANY,
                mock.ANY)

    def test_treat_devices_added_updated_no_device_found(self):
        agent = self.agent
        mock_details = {'device': 'aa:bb:cc:dd:ee:ff',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'profile': {'pci_slot': '1:2:3.0'},
                        'propagate_uplink_status': False,
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.remove_port_binding = mock.Mock()
        agent.eswitch_mgr = mock.Mock()
        agent.eswitch_mgr.device_exists.return_value = False
        resync_needed = agent.treat_devices_added_updated(
                            set(['aa:bb:cc:dd:ee:ff']))
        self.assertTrue(resync_needed)
        self.assertFalse(agent.plugin_rpc.update_device_up.called)

    def test_update_and_clean_network_ports(self):
        network_id1 = 'network_id1'
        network_id2 = 'network_id2'

        port_id1 = 'port_id1'
        port_id2 = 'port_id2'
        mac_slot_1 = ('mac1', 'slot1')
        mac_slot_2 = ('mac2', 'slot2')

        self.agent.network_ports[network_id1] = [{'port_id': port_id1,
            'device': mac_slot_1}, {'port_id': port_id2, 'device': mac_slot_2}]

        self.agent._update_network_ports(network_id2, port_id1, mac_slot_1)

        self.assertEqual({network_id1: [{'port_id': port_id2,
                         'device': mac_slot_2}], network_id2: [
                         {'port_id': port_id1, 'device': mac_slot_1}]},
                         self.agent.network_ports)

        cleaned_port_id = self.agent._clean_network_ports(mac_slot_1)
        self.assertEqual(cleaned_port_id, port_id1)

        self.assertEqual({network_id1: [{'port_id': port_id2,
                                         'device': mac_slot_2}]},
                        self.agent.network_ports)

        cleaned_port_id = self.agent._clean_network_ports(mac_slot_2)
        self.assertEqual({}, self.agent.network_ports)

    def test_configurations_has_rp_bandwidth(self):
        rp_bandwidth = {'ens7': {'egress': 10000, 'ingress': 10000}}
        agent = sriov_nic_agent.SriovNicSwitchAgent(
            {}, {}, 0, rp_bandwidth, {})
        self.assertIn(c_const.RP_BANDWIDTHS,
                      agent.agent_state['configurations'])

        rp_bandwidths = agent.agent_state['configurations'][
            c_const.RP_BANDWIDTHS]
        self.assertEqual(rp_bandwidth['ens7'], rp_bandwidths['ens7'])

    def test_configurations_has_rp_default_inventory(self):
        rp_inventory_values = {
            'allocation_ratio': 1.0,
            'min_unit': 1,
            'step_size': 1,
            'reserved': 0
        }
        agent = sriov_nic_agent.SriovNicSwitchAgent(
            {}, {}, 0, {}, rp_inventory_values)
        self.assertIn(c_const.RP_INVENTORY_DEFAULTS,
                      agent.agent_state['configurations'])

        rp_inv_defaults = agent.agent_state['configurations'][
            c_const.RP_INVENTORY_DEFAULTS]
        self.assertListEqual(
            sorted(list(rp_inventory_values)),
            sorted(list(rp_inv_defaults.keys())))
        for inv_key, inv_value in rp_inventory_values.items():
            self.assertEqual(inv_value,
                             rp_inv_defaults[inv_key])

    def test_process_activated_bindings(self):
        # Create several devices which are pairs of (<mac_addr>, <pci_slot>)
        dev_a = ('fa:16:3e:f8:ae:af', "0000:01:00.0")
        dev_b = ('fa:16:3e:f8:ae:b0', "0000:02:00.0")
        dev_c = ('fa:16:3e:f8:ae:b1', "0000:03:00.0")
        # Create device_info
        fake_device_info = {
            'current': set([dev_a, dev_b]),
            'added': set([dev_c]),
            'removed': set(),
            'updated': set()}
        fake_activated_bindings = set([dev_a])
        self.agent.process_activated_bindings(fake_device_info,
                                              fake_activated_bindings)
        self.assertLessEqual(fake_activated_bindings,
                             fake_device_info['added'])


class FakeAgent(object):
    def __init__(self):
        self.updated_devices = set()
        self.activated_bindings = set()
        self.conf = mock.Mock()
        self.conf.host = 'host1'


class TestSriovNicSwitchRpcCallbacks(base.BaseTestCase):

    def setUp(self):
        super(TestSriovNicSwitchRpcCallbacks, self).setUp()
        self.context = object()
        self.agent = FakeAgent()
        sg_agent = object()
        self.sriov_rpc_callback = sriov_nic_agent.SriovNicSwitchRpcCallbacks(
            self.context, self.agent, sg_agent)

    def _create_fake_port(self):
        return {'id': uuidutils.generate_uuid(),
                portbindings.PROFILE: {'pci_slot': PCI_SLOT},
                'mac_address': DEVICE_MAC}

    def _create_fake_bindings(self, fake_port, fake_host):
        return {'port_id': fake_port['id'],
                'host': fake_host}

    def test_port_update_with_pci_slot(self):
        port = self._create_fake_port()
        kwargs = {'context': self.context, 'port': port}
        self.sriov_rpc_callback.port_update(**kwargs)
        self.assertEqual(set([(DEVICE_MAC, PCI_SLOT)]),
                         self.agent.updated_devices)

    def test_port_update_with_vnic_physical_direct(self):
        port = self._create_fake_port()
        port[portbindings.VNIC_TYPE] = portbindings.VNIC_DIRECT_PHYSICAL
        kwargs = {'context': self.context, 'port': port}
        self.sriov_rpc_callback.port_update(**kwargs)
        self.assertEqual(set(), self.agent.updated_devices)

    def test_port_update_without_pci_slot(self):
        port = self._create_fake_port()
        port[portbindings.PROFILE] = None
        kwargs = {'context': self.context, 'port': port}
        self.sriov_rpc_callback.port_update(**kwargs)
        self.assertEqual(set(), self.agent.updated_devices)

    def test_network_update(self):
        TEST_NETWORK_ID1 = "n1"
        TEST_NETWORK_ID2 = "n2"
        TEST_PORT_ID1 = 'p1'
        TEST_PORT_ID2 = 'p2'
        network1 = {'id': TEST_NETWORK_ID1}
        port1 = {'id': TEST_PORT_ID1, 'network_id': TEST_NETWORK_ID1}
        port2 = {'id': TEST_PORT_ID2, 'network_id': TEST_NETWORK_ID2}
        self.agent.network_ports = {
                TEST_NETWORK_ID1: [{'port_id': port1['id'],
                                   'device': ('mac1', 'slot1')}],
                TEST_NETWORK_ID2: [{'port_id': port2['id'],
                                   'device': ('mac2', 'slot2')}]}
        kwargs = {'context': self.context, 'network': network1}
        self.sriov_rpc_callback.network_update(**kwargs)
        self.assertEqual(set([('mac1', 'slot1')]), self.agent.updated_devices)

    def test_binding_activate(self):
        fake_port = self._create_fake_port()
        self.agent.get_device_details_from_port_id = mock.Mock()
        self.agent.get_device_details_from_port_id.return_value = {
            'mac_address': fake_port['mac_address'],
            'profile': fake_port[portbindings.PROFILE]
        }
        kwargs = self._create_fake_bindings(fake_port, self.agent.conf.host)
        kwargs['context'] = self.context
        self.sriov_rpc_callback.binding_activate(**kwargs)
        # Assert agent.activated_binding set contains the new binding
        self.assertIn((fake_port['mac_address'],
                       fake_port[portbindings.PROFILE]['pci_slot']),
                      self.agent.activated_bindings)

    def test_binding_activate_no_host(self):
        fake_port = self._create_fake_port()
        kwargs = self._create_fake_bindings(fake_port, 'other-host')
        kwargs['context'] = self.context
        self.sriov_rpc_callback.binding_activate(**kwargs)
        # Assert no bindings were added
        self.assertEqual(set(), self.agent.activated_bindings)

    def test_binding_deactivate(self):
        # binding_deactivate() basically does nothing
        # call it with both the agent's host and other host to cover
        # all code paths
        fake_port = self._create_fake_port()
        kwargs = self._create_fake_bindings(fake_port, self.agent.conf.host)
        kwargs['context'] = self.context
        self.sriov_rpc_callback.binding_deactivate(**kwargs)
        kwargs['host'] = 'other-host'
        self.sriov_rpc_callback.binding_deactivate(**kwargs)


class TestSRIOVAgentExtensionConfig(base.BaseTestCase):
    def setUp(self):
        super(TestSRIOVAgentExtensionConfig, self).setUp()
        l2_ext_manager.register_opts(cfg.CONF)
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, group='AGENT')
        cfg.CONF.set_override('extensions', ['qos'], group='agent')

    @mock.patch("neutron.plugins.ml2.drivers.mech_sriov.agent.eswitch_manager"
               ".ESwitchManager.get_assigned_devices_info", return_value=[])
    def test_report_loaded_extension(self, *args):
        with mock.patch.object(agent_rpc.PluginReportStateAPI,
                               'report_state') as mock_report_state:
            agent = sriov_nic_agent.SriovNicSwitchAgent({}, {}, 0, {}, {})
            agent._report_state()
            mock_report_state.assert_called_with(
                agent.context, agent.agent_state)
            self.assertEqual(
                ['qos'], agent.agent_state['configurations']['extensions'])


class TestSriovNicAgentConfigParser(base.BaseTestCase):

    def test__validate_rp_in_dev_mappings(self):
        with mock.patch.object(
                cfg.CONF.SRIOV_NIC, 'physical_device_mappings',
                new=[]), \
             mock.patch.object(
                cfg.CONF.SRIOV_NIC, 'resource_provider_bandwidths',
                new=['no_such_dev_in_dev_mappings:1:1']):
            parser = sriov_nic_agent.SriovNicAgentConfigParser()
            self.assertRaises(ValueError, parser.parse)
