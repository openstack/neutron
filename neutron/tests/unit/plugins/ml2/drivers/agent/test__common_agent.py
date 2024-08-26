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

from unittest import mock

from neutron_lib.agent import constants as agent_consts
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from oslo_config import cfg
import testtools

from neutron.agent.linux import bridge_lib
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.tests import base

LOCAL_IP = '192.168.0.33'
LOCAL_IPV6 = '2001:db8:1::33'
VXLAN_GROUPV6 = 'ff05::/120'
PORT_1 = 'abcdef01-12ddssdfds-fdsfsd'
DEVICE_1 = 'tapabcdef01-12'
NETWORK_ID = '57653b20-ed5b-4ed0-a31d-06f84e3fd909'
BRIDGE_MAPPING_VALUE = 'br-eth2'
BRIDGE_MAPPINGS = {'physnet0': BRIDGE_MAPPING_VALUE}
INTERFACE_MAPPINGS = {'physnet1': 'eth1'}
FAKE_DEFAULT_DEV = mock.Mock()
FAKE_DEFAULT_DEV.name = 'eth1'
PORT_DATA = {
    "port_id": PORT_1,
    "device": DEVICE_1
}


class TestCommonAgentLoop(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.get_bridge_names_p = mock.patch.object(bridge_lib,
                                                    'get_bridge_names')
        self.get_bridge_names = self.get_bridge_names_p.start()
        self.get_bridge_names.return_value = ["br-int", "brq1"]

        manager = mock.Mock()
        manager.get_all_devices.return_value = []
        manager.get_agent_configurations.return_value = {}
        manager.get_rpc_consumers.return_value = []
        with mock.patch.object(ca.CommonAgentLoop, '_validate_manager_class'),\
            mock.patch.object(ca.CommonAgentLoop,
                              '_validate_rpc_endpoints'):
            self.agent = ca.CommonAgentLoop(manager, 0, 10, 'fake_agent',
                                            'foo-binary')
            with mock.patch.object(self.agent, "daemon_loop"):
                self.agent.start()

    def test_treat_devices_removed_notify(self):
        handler = mock.Mock()
        registry.subscribe(handler, resources.PORT_DEVICE, events.AFTER_DELETE)
        devices = [DEVICE_1]
        self.agent.treat_devices_removed(devices)
        handler.assert_called_once_with(mock.ANY, mock.ANY, self.agent,
                                        payload=mock.ANY)

    def test_treat_devices_added_updated_notify(self):
        handler = mock.Mock()
        registry.subscribe(handler, resources.PORT_DEVICE, events.AFTER_UPDATE)
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': 'horse'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.mgr = mock.Mock()
        agent.mgr.plug_interface.return_value = True
        agent.treat_devices_added_updated({'dev123'})
        handler.assert_called_once_with(mock.ANY, mock.ANY, self.agent,
                                        payload=mock.ANY)

        payload = handler.mock_calls[0][2]['payload']
        self.assertDictEqual(mock_details, payload.latest_state)
        self.assertEqual(mock_details['device'], payload.resource_id)

    def test_treat_devices_removed_with_existed_device(self):
        agent = self.agent
        agent.mgr.ensure_port_admin_state = mock.Mock()
        devices = [DEVICE_1]
        agent.network_ports[NETWORK_ID].append(PORT_DATA)
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf,\
                mock.patch.object(agent.ext_manager,
                                  "delete_port") as ext_mgr_delete_port:
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': True}
            with mock.patch.object(ca.LOG, 'info') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(2, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)
                self.assertTrue(ext_mgr_delete_port.called)
                self.assertNotIn(PORT_DATA, agent.network_ports[NETWORK_ID])

    def test_treat_devices_removed_with_not_existed_device(self):
        agent = self.agent
        devices = [DEVICE_1]
        agent.network_ports[NETWORK_ID].append(PORT_DATA)
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf,\
                mock.patch.object(agent.ext_manager,
                                  "delete_port") as ext_mgr_delete_port:
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': False}
            with mock.patch.object(ca.LOG, 'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(1, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)
                self.assertTrue(ext_mgr_delete_port.called)
                self.assertNotIn(PORT_DATA, agent.network_ports[NETWORK_ID])

    def test_treat_devices_removed_failed(self):
        agent = self.agent
        devices = [DEVICE_1]
        agent.network_ports[NETWORK_ID].append(PORT_DATA)
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf,\
                mock.patch.object(agent.ext_manager,
                                  "delete_port") as ext_mgr_delete_port:
            fn_udd.side_effect = Exception()
            resync = agent.treat_devices_removed(devices)
            self.assertTrue(resync)
            self.assertTrue(fn_udd.called)
            self.assertTrue(fn_rdf.called)
            self.assertTrue(ext_mgr_delete_port.called)
            self.assertNotIn(PORT_DATA, agent.network_ports[NETWORK_ID])

    def test_treat_devices_removed_failed_extension(self):
        agent = self.agent
        devices = [DEVICE_1]
        agent.network_ports[NETWORK_ID].append(PORT_DATA)
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf,\
                mock.patch.object(agent.ext_manager,
                                  "delete_port") as ext_mgr_delete_port:
            ext_mgr_delete_port.side_effect = Exception()
            resync = agent.treat_devices_removed(devices)
            self.assertTrue(resync)
            self.assertTrue(fn_udd.called)
            self.assertTrue(fn_rdf.called)
            self.assertTrue(ext_mgr_delete_port.called)
            self.assertNotIn(PORT_DATA, agent.network_ports[NETWORK_ID])

    def test_treat_devices_removed_delete_arp_spoofing(self):
        agent = self.agent
        agent._ensure_port_admin_state = mock.Mock()
        devices = [DEVICE_1]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter"):
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': True}
            with mock.patch.object(agent.mgr,
                                   'delete_arp_spoofing_protection') as de_arp:
                agent.treat_devices_removed(devices)
                de_arp.assert_called_with(devices)

    def test__get_devices_locally_modified(self):
        new_ts = {1: 1000, 2: 2000, 3: 3000}
        old_ts = {1: 10, 2: 2000, 4: 900}
        # 3 and 4 are not returned because 3 is a new device and 4 is a
        # removed device
        self.assertEqual(
            {1},
            self.agent._get_devices_locally_modified(new_ts, old_ts))

    def _test_scan_devices(self, previous, updated,
                           fake_current, expected, sync,
                           fake_ts_current=None):
        self.agent.mgr = mock.Mock()
        self.agent.mgr.get_all_devices.return_value = fake_current
        self.agent.mgr.get_devices_modified_timestamps.return_value = (
            fake_ts_current or {})

        self.agent.rpc_callbacks.get_and_clear_updated_devices.return_value =\
            updated
        results = self.agent.scan_devices(previous, sync)
        self.assertEqual(expected, results)

    def test_scan_devices_no_changes(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}
        fake_current = {1, 2}
        updated = set()
        expected = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_timestamp_triggers_updated_None_to_something(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {2: None}}
        fake_current = {1, 2}
        updated = set()
        expected = {'current': {1, 2},
                    'updated': {2},
                    'added': set(),
                    'removed': set(),
                    'timestamps': {2: 1000}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False, fake_ts_current={2: 1000})

    def test_scan_devices_timestamp_triggers_updated(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {2: 600}}
        fake_current = {1, 2}
        updated = set()
        expected = {'current': {1, 2},
                    'updated': {2},
                    'added': set(),
                    'removed': set(),
                    'timestamps': {2: 1000}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False, fake_ts_current={2: 1000})

    def test_scan_devices_added_removed(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}
        fake_current = {2, 3}
        updated = set()
        expected = {'current': {2, 3},
                    'updated': set(),
                    'added': {3},
                    'removed': {1},
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_removed_retried_on_sync(self):
        previous = {'current': {2, 3},
                    'updated': set(),
                    'added': set(),
                    'removed': {1},
                    'timestamps': {}}
        fake_current = {2, 3}
        updated = set()
        expected = {'current': {2, 3},
                    'updated': set(),
                    'added': {2, 3},
                    'removed': {1},
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_vanished_removed_on_sync(self):
        previous = {'current': {2, 3},
                    'updated': set(),
                    'added': set(),
                    'removed': {1},
                    'timestamps': {}}
        # Device 2 disappeared.
        fake_current = {3}
        updated = set()
        # Device 1 should be retried.
        expected = {'current': {3},
                    'updated': set(),
                    'added': {3},
                    'removed': {1, 2},
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_updated(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}
        fake_current = {1, 2}
        updated = {1}
        expected = {'current': {1, 2},
                    'updated': {1},
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_non_existing(self):
        previous = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}
        fake_current = {1, 2}
        updated = {3}
        expected = {'current': {1, 2},
                    'updated': set(),
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_deleted_concurrently(self):
        previous = {
            'current': {1, 2},
            'updated': set(),
            'added': set(),
            'removed': set(),
            'timestamps': {}
        }
        # Device 2 disappeared.
        fake_current = {1}
        # Device 2 got an concurrent update via network_update
        updated = {2}
        expected = {
            'current': {1},
            'updated': set(),
            'added': set(),
            'removed': {2},
            'timestamps': {}
        }
        self._test_scan_devices(
            previous, updated, fake_current, expected, sync=False
        )

    def test_scan_devices_updated_on_sync(self):
        previous = {'current': {1, 2},
                    'updated': {1},
                    'added': set(),
                    'removed': set(),
                    'timestamps': {}}
        fake_current = {1, 2}
        updated = {2}
        expected = {'current': {1, 2},
                    'updated': {1, 2},
                    'added': {1, 2},
                    'removed': set(),
                    'timestamps': {}}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_with_delete_arp_protection(self):
        previous = None
        fake_current = {1, 2}
        updated = set()
        expected = {'current': {1, 2},
                    'updated': set(),
                    'added': {1, 2},
                    'removed': set(),
                    'timestamps': {}}
        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)
        self.agent.mgr.delete_unreferenced_arp_protection.assert_called_with(
            fake_current)

    def test_process_network_devices(self):
        agent = self.agent
        device_info = {'current': set(),
                       'added': {'tap3', 'tap4'},
                       'updated': {'tap2', 'tap3'},
                       'removed': {'tap1'}}
        agent.sg_agent.setup_port_filters = mock.Mock()
        agent.treat_devices_added_updated = mock.Mock(return_value=False)
        agent.treat_devices_removed = mock.Mock(return_value=False)

        agent.process_network_devices(device_info)

        agent.sg_agent.setup_port_filters.assert_called_with(
                device_info['added'],
                device_info['updated'])
        agent.treat_devices_added_updated.assert_called_with({'tap2',
                                                              'tap3',
                                                              'tap4'})
        agent.treat_devices_removed.assert_called_with({'tap1'})

    def test_treat_devices_added_updated_no_local_interface(self):
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        agent.ext_manager = mock.Mock()
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.mgr = mock.Mock()
        agent.mgr.plug_interface.return_value = False
        agent.mgr.ensure_port_admin_state = mock.Mock()
        agent.treat_devices_added_updated({'tap1'})
        self.assertFalse(agent.mgr.ensure_port_admin_state.called)

    def test_treat_devices_added_updated_admin_state_up_true(self):
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        mock_port_data = {
            'port_id': mock_details['port_id'],
            'device': mock_details['device']
        }
        agent.ext_manager = mock.Mock()
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.mgr = mock.Mock()
        agent.mgr.plug_interface.return_value = True
        agent.mgr.ensure_port_admin_state = mock.Mock()
        mock_segment = amb.NetworkSegment(mock_details['network_type'],
                                          mock_details['physical_network'],
                                          mock_details['segmentation_id'])

        with mock.patch('neutron.plugins.ml2.drivers.agent.'
                        '_agent_manager_base.NetworkSegment',
                        return_value=mock_segment):
            resync_needed = agent.treat_devices_added_updated({'tap1'})

            self.assertFalse(resync_needed)
            agent.rpc_callbacks.add_network.assert_called_with('net123',
                                                               mock_segment)
            agent.mgr.plug_interface.assert_called_with(
                'net123', mock_segment, 'dev123',
                constants.DEVICE_OWNER_NETWORK_PREFIX)
            self.assertTrue(agent.plugin_rpc.update_device_up.called)
            self.assertTrue(agent.ext_manager.handle_port.called)
            self.assertIn(mock_port_data, agent.network_ports[
                mock_details['network_id']]
                          )

    def test_treat_devices_added_updated_setup_arp_protection(self):
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.mgr = mock.Mock()
        agent.mgr.plug_interface.return_value = True
        with mock.patch.object(agent.mgr,
                               'setup_arp_spoofing_protection') as set_arp:
            agent.treat_devices_added_updated({'tap1'})
            set_arp.assert_called_with(mock_details['device'], mock_details)

    def test__process_device_if_exists_missing_intf(self):
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        self.agent.mgr = mock.Mock()
        self.agent.mgr.get_all_devices.return_value = []
        self.agent.mgr.plug_interface.side_effect = RuntimeError()
        self.agent._process_device_if_exists(mock_details)

    def test__process_device_if_exists_error(self):
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        self.agent.mgr = mock.Mock()
        self.agent.mgr.get_all_devices.return_value = ['dev123']
        self.agent.mgr.plug_interface.side_effect = RuntimeError()
        with testtools.ExpectedException(RuntimeError):
            # device exists so it should raise
            self.agent._process_device_if_exists(mock_details)

    def test__process_device_if_exists_no_active_binding_in_host(self):
        mock_details = {'device': 'dev123',
                        constants.NO_ACTIVE_BINDING: True}
        self.agent.mgr = mock.Mock()
        self.agent._process_device_if_exists(mock_details)
        self.agent.mgr.setup_arp_spoofing_protection.assert_not_called()

    def test_set_rpc_timeout(self):
        self.agent.stop()
        for rpc_client in (self.agent.plugin_rpc.client,
                           self.agent.sg_plugin_rpc.client,
                           self.agent.state_rpc.client):
            self.assertEqual(cfg.CONF.AGENT.quitting_rpc_timeout,
                             rpc_client.timeout)

    def test_set_rpc_timeout_no_value(self):
        self.agent.quitting_rpc_timeout = None
        with mock.patch.object(self.agent, 'set_rpc_timeout') as mock_set_rpc:
            self.agent.stop()
            self.assertFalse(mock_set_rpc.called)

    def test_report_state_revived(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            report_st.return_value = agent_consts.AGENT_REVIVED
            self.agent._report_state()
            self.assertTrue(self.agent.fullsync)

    def test_update_network_ports(self):
        port_1_data = PORT_DATA
        NETWORK_2_ID = 'fake_second_network'
        port_2_data = {
            'port_id': 'fake_port_2',
            'device': 'fake_port_2_device_name'
        }
        self.agent.network_ports[NETWORK_ID].append(
            port_1_data
        )
        self.agent.network_ports[NETWORK_ID].append(
            port_2_data
        )
        # check update port:
        self.agent._update_network_ports(
            NETWORK_2_ID, port_2_data['port_id'], port_2_data['device']
        )
        self.assertNotIn(port_2_data, self.agent.network_ports[NETWORK_ID])
        self.assertIn(port_2_data, self.agent.network_ports[NETWORK_2_ID])

    def test_clean_network_ports(self):
        port_1_data = PORT_DATA
        port_2_data = {
            'port_id': 'fake_port_2',
            'device': 'fake_port_2_device_name'
        }
        self.agent.network_ports[NETWORK_ID].append(
            port_1_data
        )
        self.agent.network_ports[NETWORK_ID].append(
            port_2_data
        )
        # check removing port from network when other ports are still there:
        cleaned_port_id = self.agent._clean_network_ports(DEVICE_1)
        self.assertIn(NETWORK_ID, self.agent.network_ports.keys())
        self.assertNotIn(port_1_data, self.agent.network_ports[NETWORK_ID])
        self.assertIn(port_2_data, self.agent.network_ports[NETWORK_ID])
        self.assertEqual(PORT_1, cleaned_port_id)
        # and now remove last port from network:
        cleaned_port_id = self.agent._clean_network_ports(
            port_2_data['device']
        )
        self.assertNotIn(NETWORK_ID, self.agent.network_ports.keys())
        self.assertEqual(port_2_data['port_id'], cleaned_port_id)

    def test_stop(self):
        mock_connection = mock.Mock()
        self.agent.connection = mock_connection
        with mock.patch.object(self.agent, 'set_rpc_timeout'):
            self.agent.stop()
            mock_connection.close.assert_called_once()
