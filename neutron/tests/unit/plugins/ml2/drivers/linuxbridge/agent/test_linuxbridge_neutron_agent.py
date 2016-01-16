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

import collections
import sys

import mock
from oslo_config import cfg

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.linuxbridge.agent import arp_protect
from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lconst
from neutron.plugins.ml2.drivers.linuxbridge.agent \
    import linuxbridge_neutron_agent
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


class FakeIpLinkCommand(object):
    def set_up(self):
        pass


class FakeIpDevice(object):
    def __init__(self):
        self.link = FakeIpLinkCommand()


def get_linuxbridge_manager(bridge_mappings, interface_mappings):
    with mock.patch.object(ip_lib.IPWrapper, 'get_device_by_ip',
                           return_value=FAKE_DEFAULT_DEV),\
            mock.patch.object(ip_lib, 'device_exists', return_value=True),\
            mock.patch.object(linuxbridge_neutron_agent.LinuxBridgeManager,
                              'check_vxlan_support'):
        cfg.CONF.set_override('local_ip', LOCAL_IP, 'VXLAN')
        return linuxbridge_neutron_agent.LinuxBridgeManager(
            bridge_mappings, interface_mappings)


class TestLinuxBridge(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        self.linux_bridge = get_linuxbridge_manager(
            BRIDGE_MAPPINGS, INTERFACE_MAPPINGS)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             p_const.TYPE_VLAN,
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', p_const.TYPE_FLAT, 'physnet1', None)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', p_const.TYPE_VLAN, 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)

    def test_ensure_physical_in_bridge_vxlan(self):
        self.linux_bridge.vxlan_mode = lconst.VXLAN_UCAST
        with mock.patch.object(self.linux_bridge,
                               'ensure_vxlan_bridge') as vxlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'vxlan', 'physnet1', 7)
        self.assertTrue(vxlan_bridge_func.called)


class TestLinuxBridgeAgent(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridgeAgent, self).setUp()
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        cfg.CONF.set_override('prevent_arp_spoofing', False, 'AGENT')
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        cfg.CONF.set_override('local_ip', LOCAL_IP, 'VXLAN')
        self.get_devices_p = mock.patch.object(ip_lib.IPWrapper, 'get_devices')
        self.get_devices = self.get_devices_p.start()
        self.get_devices.return_value = [ip_lib.IPDevice('eth77')]
        self.get_mac_p = mock.patch('neutron.agent.linux.utils.'
                                    'get_interface_mac')
        self.get_mac = self.get_mac_p.start()
        self.get_mac.return_value = '00:00:00:00:00:01'
        self.get_bridge_names_p = mock.patch.object(bridge_lib,
                                                    'get_bridge_names')
        self.get_bridge_names = self.get_bridge_names_p.start()
        self.get_bridge_names.return_value = ["br-int", "brq1"]
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_device_by_ip',
                               return_value=FAKE_DEFAULT_DEV):
            self.agent = linuxbridge_neutron_agent.LinuxBridgeNeutronAgentRPC(
                {}, {}, 0, cfg.CONF.AGENT.quitting_rpc_timeout)
            with mock.patch.object(self.agent, "daemon_loop"),\
                    mock.patch.object(
                        linuxbridge_neutron_agent.LinuxBridgeManager,
                        'check_vxlan_support'):
                self.agent.start()

    def test_treat_devices_removed_with_existed_device(self):
        agent = self.agent
        agent._ensure_port_admin_state = mock.Mock()
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
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'info') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(2, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)
                self.assertTrue(ext_mgr_delete_port.called)
                self.assertTrue(
                    PORT_DATA not in agent.network_ports[NETWORK_ID]
                )

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
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(1, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)
                self.assertTrue(ext_mgr_delete_port.called)
                self.assertTrue(
                    PORT_DATA not in agent.network_ports[NETWORK_ID]
                )

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
            self.assertTrue(
                PORT_DATA not in agent.network_ports[NETWORK_ID]
            )

    def test_treat_devices_removed_with_prevent_arp_spoofing_true(self):
        agent = self.agent
        agent.prevent_arp_spoofing = True
        agent._ensure_port_admin_state = mock.Mock()
        devices = [DEVICE_1]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter"):
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': True}
            with mock.patch.object(arp_protect,
                                   'delete_arp_spoofing_protection') as de_arp:
                agent.treat_devices_removed(devices)
                de_arp.assert_called_with(devices)

    def _test_scan_devices(self, previous, updated,
                           fake_current, expected, sync):
        self.agent.br_mgr = mock.Mock()
        self.agent.br_mgr.get_tap_devices.return_value = fake_current

        self.agent.updated_devices = updated
        results = self.agent.scan_devices(previous, sync)
        self.assertEqual(expected, results)

    def test_scan_devices_no_changes(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set()
        expected = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_added_removed(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([2, 3])
        updated = set()
        expected = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set([3]),
                    'removed': set([1])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_removed_retried_on_sync(self):
        previous = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set(),
                    'removed': set([1])}
        fake_current = set([2, 3])
        updated = set()
        expected = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set([2, 3]),
                    'removed': set([1])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_vanished_removed_on_sync(self):
        previous = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set(),
                    'removed': set([1])}
        # Device 2 disappeared.
        fake_current = set([3])
        updated = set()
        # Device 1 should be retried.
        expected = {'current': set([3]),
                    'updated': set(),
                    'added': set([3]),
                    'removed': set([1, 2])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_updated(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([1])
        expected = {'current': set([1, 2]),
                    'updated': set([1]),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_non_existing(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([3])
        expected = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_deleted_concurrently(self):
        previous = {
            'current': set([1, 2]),
            'updated': set(),
            'added': set(),
            'removed': set()
        }
        # Device 2 disappeared.
        fake_current = set([1])
        # Device 2 got an concurrent update via network_update
        updated = set([2])
        expected = {
            'current': set([1]),
            'updated': set(),
            'added': set(),
            'removed': set([2])
        }
        self._test_scan_devices(
            previous, updated, fake_current, expected, sync=False
        )

    def test_scan_devices_updated_on_sync(self):
        previous = {'current': set([1, 2]),
                    'updated': set([1]),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([2])
        expected = {'current': set([1, 2]),
                    'updated': set([1, 2]),
                    'added': set([1, 2]),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_with_prevent_arp_spoofing_true(self):
        self.agent.prevent_arp_spoofing = True
        previous = None
        fake_current = set([1, 2])
        updated = set()
        expected = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set([1, 2]),
                    'removed': set()}
        with mock.patch.object(arp_protect,
                               'delete_unreferenced_arp_protection') as de_arp:
            self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)
            de_arp.assert_called_with(fake_current)

    def test_process_network_devices(self):
        agent = self.agent
        device_info = {'current': set(),
                       'added': set(['tap3', 'tap4']),
                       'updated': set(['tap2', 'tap3']),
                       'removed': set(['tap1'])}
        agent.sg_agent.setup_port_filters = mock.Mock()
        agent.treat_devices_added_updated = mock.Mock(return_value=False)
        agent.treat_devices_removed = mock.Mock(return_value=False)

        agent.process_network_devices(device_info)

        agent.sg_agent.setup_port_filters.assert_called_with(
                device_info['added'],
                device_info['updated'])
        agent.treat_devices_added_updated.assert_called_with(set(['tap2',
                                                                  'tap3',
                                                                  'tap4']))
        agent.treat_devices_removed.assert_called_with(set(['tap1']))

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
        agent.br_mgr = mock.Mock()
        agent.br_mgr.add_interface.return_value = True
        agent._ensure_port_admin_state = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(set(['tap1']))

        self.assertFalse(resync_needed)
        agent.br_mgr.add_interface.assert_called_with(
                                      'net123', 'vlan', 'physnet1',
                                      100, 'port123',
                                      constants.DEVICE_OWNER_NETWORK_PREFIX)
        self.assertTrue(agent.plugin_rpc.update_device_up.called)
        self.assertTrue(agent.ext_manager.handle_port.called)
        self.assertTrue(
            mock_port_data in agent.network_ports[mock_details['network_id']]
        )

    def test_treat_devices_added_updated_prevent_arp_spoofing_true(self):
        agent = self.agent
        agent.prevent_arp_spoofing = True
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1',
                        'device_owner': constants.DEVICE_OWNER_NETWORK_PREFIX}
        tap_name = constants.TAP_DEVICE_PREFIX + mock_details['port_id']
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.br_mgr = mock.Mock()
        agent.br_mgr.add_interface.return_value = True
        agent.br_mgr.get_tap_device_name.return_value = tap_name
        agent._ensure_port_admin_state = mock.Mock()
        with mock.patch.object(arp_protect,
                               'setup_arp_spoofing_protection') as set_arp:
            agent.treat_devices_added_updated(set(['tap1']))
            set_arp.assert_called_with(tap_name, mock_details)

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
            report_st.return_value = constants.AGENT_REVIVED
            self.agent._report_state()
            self.assertTrue(self.agent.fullsync)

    def _test_ensure_port_admin_state(self, admin_state):
        port_id = 'fake_id'
        with mock.patch.object(ip_lib, 'IPDevice') as dev_mock:
            self.agent._ensure_port_admin_state(port_id, admin_state)

        tap_name = self.agent.br_mgr.get_tap_device_name(port_id)
        self.assertEqual(admin_state,
                         dev_mock(tap_name).link.set_up.called)
        self.assertNotEqual(admin_state,
                            dev_mock(tap_name).link.set_down.called)

    def test_ensure_port_admin_state_up(self):
        self._test_ensure_port_admin_state(True)

    def test_ensure_port_admin_state_down(self):
        self._test_ensure_port_admin_state(False)

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
        #check update port:
        self.agent._update_network_ports(
            NETWORK_2_ID, port_2_data['port_id'], port_2_data['device']
        )
        self.assertTrue(
            port_2_data not in self.agent.network_ports[NETWORK_ID]
        )
        self.assertTrue(
            port_2_data in self.agent.network_ports[NETWORK_2_ID]
        )

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
        #check removing port from network when other ports are still there:
        cleaned_port_id = self.agent._clean_network_ports(DEVICE_1)
        self.assertTrue(
            NETWORK_ID in self.agent.network_ports.keys()
        )
        self.assertTrue(
            port_1_data not in self.agent.network_ports[NETWORK_ID]
        )
        self.assertTrue(
            port_2_data in self.agent.network_ports[NETWORK_ID]
        )
        self.assertEqual(PORT_1, cleaned_port_id)
        #and now remove last port from network:
        cleaned_port_id = self.agent._clean_network_ports(
            port_2_data['device']
        )
        self.assertTrue(
            NETWORK_ID not in self.agent.network_ports.keys()
        )
        self.assertEqual(port_2_data['port_id'], cleaned_port_id)


class TestLinuxBridgeManager(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeManager, self).setUp()
        self.lbm = get_linuxbridge_manager(
            BRIDGE_MAPPINGS, INTERFACE_MAPPINGS)

    def test_local_ip_validation_with_valid_ip(self):
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_device_by_ip',
                               return_value=FAKE_DEFAULT_DEV):
            result = self.lbm.get_local_ip_device(LOCAL_IP)
            self.assertEqual(FAKE_DEFAULT_DEV, result)

    def test_local_ip_validation_with_invalid_ip(self):
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_device_by_ip',
                               return_value=None),\
                mock.patch.object(sys, 'exit') as exit,\
                mock.patch.object(linuxbridge_neutron_agent.LOG,
                                  'error') as log:
            self.lbm.get_local_ip_device(LOCAL_IP)
            self.assertEqual(1, log.call_count)
            exit.assert_called_once_with(1)

    def _test_vxlan_group_validation(self, bad_local_ip, bad_vxlan_group):
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_device_by_ip',
                               return_value=FAKE_DEFAULT_DEV),\
                mock.patch.object(sys, 'exit') as exit,\
                mock.patch.object(linuxbridge_neutron_agent.LOG,
                                  'error') as log:
            self.lbm.local_ip = bad_local_ip
            cfg.CONF.set_override('vxlan_group', bad_vxlan_group, 'VXLAN')
            self.lbm.validate_vxlan_group_with_local_ip()
            self.assertEqual(1, log.call_count)
            exit.assert_called_once_with(1)

    def test_vxlan_group_validation_with_mismatched_local_ip(self):
        self._test_vxlan_group_validation(LOCAL_IP, VXLAN_GROUPV6)

    def test_vxlan_group_validation_with_unicast_group(self):
        self._test_vxlan_group_validation(LOCAL_IP, '240.0.0.0')

    def test_vxlan_group_validation_with_invalid_cidr(self):
        self._test_vxlan_group_validation(LOCAL_IP, '224.0.0.1/')

    def test_vxlan_group_validation_with_v6_unicast_group(self):
        self._test_vxlan_group_validation(LOCAL_IPV6, '2001:db8::')

    def test_get_existing_bridge_name(self):
        phy_net = 'physnet0'
        self.assertEqual('br-eth2',
                         self.lbm.get_existing_bridge_name(phy_net))

        phy_net = ''
        self.assertIsNone(self.lbm.get_existing_bridge_name(phy_net))

    def test_get_bridge_name(self):
        nw_id = "123456789101112"
        self.assertEqual("brq" + nw_id[0:11],
                         self.lbm.get_bridge_name(nw_id))
        nw_id = ""
        self.assertEqual("brq", self.lbm.get_bridge_name(nw_id))

    def test_get_subinterface_name(self):
        self.assertEqual("eth0.0",
                         self.lbm.get_subinterface_name("eth0", "0"))
        self.assertEqual("eth0.", self.lbm.get_subinterface_name("eth0", ""))

    def test_get_tap_device_name(self):
        if_id = "123456789101112"
        self.assertEqual(constants.TAP_DEVICE_PREFIX + if_id[0:11],
                         self.lbm.get_tap_device_name(if_id))
        if_id = ""
        self.assertEqual(constants.TAP_DEVICE_PREFIX,
                         self.lbm.get_tap_device_name(if_id))

    def test_get_vxlan_device_name(self):
        vn_id = p_const.MAX_VXLAN_VNI
        self.assertEqual("vxlan-" + str(vn_id),
                         self.lbm.get_vxlan_device_name(vn_id))
        self.assertIsNone(self.lbm.get_vxlan_device_name(vn_id + 1))

    def test_get_vxlan_group(self):
        cfg.CONF.set_override('vxlan_group', '239.1.2.3/24', 'VXLAN')
        vn_id = p_const.MAX_VXLAN_VNI
        self.assertEqual('239.1.2.255', self.lbm.get_vxlan_group(vn_id))
        vn_id = 256
        self.assertEqual('239.1.2.0', self.lbm.get_vxlan_group(vn_id))
        vn_id = 257
        self.assertEqual('239.1.2.1', self.lbm.get_vxlan_group(vn_id))

    def test_get_vxlan_group_with_ipv6(self):
        cfg.CONF.set_override('local_ip', LOCAL_IPV6, 'VXLAN')
        self.lbm.local_ip = LOCAL_IPV6
        cfg.CONF.set_override('vxlan_group', VXLAN_GROUPV6, 'VXLAN')
        vn_id = p_const.MAX_VXLAN_VNI
        self.assertEqual('ff05::ff', self.lbm.get_vxlan_group(vn_id))
        vn_id = 256
        self.assertEqual('ff05::', self.lbm.get_vxlan_group(vn_id))
        vn_id = 257
        self.assertEqual('ff05::1', self.lbm.get_vxlan_group(vn_id))

    def test_get_deletable_bridges(self):
        br_list = ["br-int", "brq1", "brq2", "brq-user"]
        expected = set(br_list[1:3])
        lbm = get_linuxbridge_manager(
            bridge_mappings={"physnet0": "brq-user"}, interface_mappings={})
        with mock.patch.object(
                bridge_lib, 'get_bridge_names', return_value=br_list):
            self.assertEqual(expected, lbm.get_deletable_bridges())

    def test_get_tap_devices_count(self):
        with mock.patch.object(
                bridge_lib.BridgeDevice, 'get_interfaces') as get_ifs_fn:
            get_ifs_fn.return_value = ['tap2101', 'eth0.100', 'vxlan-1000']
            self.assertEqual(self.lbm.get_tap_devices_count('br0'), 1)

    def test_get_interface_details(self):
        with mock.patch.object(ip_lib.IpAddrCommand, 'list') as list_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'get_gateway') as getgw_fn:
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            ret = self.lbm.get_interface_details("eth0")

            self.assertTrue(list_fn.called)
            self.assertTrue(getgw_fn.called)
            self.assertEqual(ret, (ipdict, gwdict))

    def test_ensure_flat_bridge(self):
        with mock.patch.object(ip_lib.IpAddrCommand, 'list') as list_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'get_gateway') as getgw_fn:
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            with mock.patch.object(self.lbm, 'ensure_bridge') as ens:
                self.assertEqual(
                    self.lbm.ensure_flat_bridge("123", None, "eth0"),
                    "eth0"
                )
                self.assertTrue(list_fn.called)
                self.assertTrue(getgw_fn.called)
                ens.assert_called_once_with("brq123", "eth0",
                                            ipdict, gwdict)

    def test_ensure_flat_bridge_with_existed_brq(self):
        with mock.patch.object(self.lbm, 'ensure_bridge') as ens:
            ens.return_value = "br-eth2"
            self.assertEqual("br-eth2",
                             self.lbm.ensure_flat_bridge("123",
                                                         "br-eth2",
                                                         None))
            ens.assert_called_with("br-eth2")

    def test_ensure_vlan_bridge(self):
        with mock.patch.object(self.lbm, 'ensure_vlan') as ens_vl_fn,\
                mock.patch.object(self.lbm, 'ensure_bridge') as ens,\
                mock.patch.object(self.lbm,
                                  'get_interface_details') as get_int_det_fn:
            ens_vl_fn.return_value = "eth0.1"
            get_int_det_fn.return_value = (None, None)
            self.assertEqual(self.lbm.ensure_vlan_bridge("123",
                                                         None,
                                                         "eth0",
                                                         "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", None, None)

            get_int_det_fn.return_value = ("ips", "gateway")
            self.assertEqual(self.lbm.ensure_vlan_bridge("123",
                                                         None,
                                                         "eth0",
                                                         "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", "ips", "gateway")

    def test_ensure_vlan_bridge_with_existed_brq(self):
        with mock.patch.object(self.lbm, 'ensure_vlan') as ens_vl_fn,\
                mock.patch.object(self.lbm, 'ensure_bridge') as ens:
            ens_vl_fn.return_value = None
            ens.return_value = "br-eth2"
            self.assertEqual("br-eth2",
                             self.lbm.ensure_vlan_bridge("123",
                                                         "br-eth2",
                                                         None,
                                                         None))
            ens.assert_called_with("br-eth2")

    def test_ensure_local_bridge(self):
        with mock.patch.object(self.lbm, 'ensure_bridge') as ens_fn:
            self.lbm.ensure_local_bridge("54321", None)
            ens_fn.assert_called_once_with("brq54321")

    def test_ensure_local_bridge_with_existed_brq(self):
        with mock.patch.object(self.lbm, 'ensure_bridge') as ens_fn:
            ens_fn.return_value = "br-eth2"
            self.lbm.ensure_local_bridge("54321", 'br-eth2')
            ens_fn.assert_called_once_with("br-eth2")

    def test_ensure_vlan(self):
        with mock.patch.object(ip_lib, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
            de_fn.return_value = False
            with mock.patch.object(utils, 'execute') as exec_fn:
                exec_fn.return_value = False
                self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
                # FIXME(kevinbenton): validate the params to the exec_fn calls
                self.assertEqual(exec_fn.call_count, 2)
                exec_fn.return_value = True
                self.assertIsNone(self.lbm.ensure_vlan("eth0", "1"))
                self.assertEqual(exec_fn.call_count, 3)

    def test_ensure_vxlan(self):
        seg_id = "12345678"
        self.lbm.local_int = 'eth0'
        self.lbm.vxlan_mode = lconst.VXLAN_MCAST
        with mock.patch.object(ip_lib, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vxlan(seg_id), "vxlan-" + seg_id)
            de_fn.return_value = False
            with mock.patch.object(self.lbm.ip,
                                   'add_vxlan') as add_vxlan_fn:
                add_vxlan_fn.return_value = FakeIpDevice()
                self.assertEqual(self.lbm.ensure_vxlan(seg_id),
                                 "vxlan-" + seg_id)
                add_vxlan_fn.assert_called_with("vxlan-" + seg_id, seg_id,
                                                group="224.0.0.1",
                                                dev=self.lbm.local_int)
                cfg.CONF.set_override('l2_population', 'True', 'VXLAN')
                self.assertEqual(self.lbm.ensure_vxlan(seg_id),
                                 "vxlan-" + seg_id)
                add_vxlan_fn.assert_called_with("vxlan-" + seg_id, seg_id,
                                                group="224.0.0.1",
                                                dev=self.lbm.local_int,
                                                proxy=True)

    def test_update_interface_ip_details(self):
        gwdict = dict(gateway='1.1.1.1',
                      metric=50)
        ipdict = dict(cidr='1.1.1.1/24',
                      broadcast='1.1.1.255',
                      scope='global',
                      ip_version=4,
                      dynamic=False)
        with mock.patch.object(ip_lib.IpAddrCommand, 'add') as add_fn,\
                mock.patch.object(ip_lib.IpAddrCommand, 'delete') as del_fn:
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 [ipdict], None)
            self.assertTrue(add_fn.called)
            self.assertTrue(del_fn.called)

        with mock.patch.object(ip_lib.IpRouteCommand,
                               'add_gateway') as addgw_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'delete_gateway') as delgw_fn:
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 None, gwdict)
            self.assertTrue(addgw_fn.called)
            self.assertTrue(delgw_fn.called)

    def test_bridge_exists_and_ensure_up(self):
        ip_lib_mock = mock.Mock()
        with mock.patch.object(ip_lib, 'IPDevice', return_value=ip_lib_mock):
            # device exists
            self.assertTrue(self.lbm._bridge_exists_and_ensure_up("br0"))
            self.assertTrue(ip_lib_mock.link.set_up.called)
            # device doesn't exists
            ip_lib_mock.link.set_up.side_effect = RuntimeError
            self.assertFalse(self.lbm._bridge_exists_and_ensure_up("br0"))

    def test_ensure_bridge(self):
        bridge_device = mock.Mock()
        bridge_device_old = mock.Mock()
        with mock.patch.object(self.lbm,
                               '_bridge_exists_and_ensure_up') as de_fn,\
                mock.patch.object(bridge_lib, "BridgeDevice",
                                  return_value=bridge_device) as br_fn,\
                mock.patch.object(self.lbm,
                                  'update_interface_ip_details') as upd_fn,\
                mock.patch.object(bridge_lib, 'is_bridged_interface'),\
                mock.patch.object(bridge_lib.BridgeDevice,
                                  'get_interface_bridge') as get_if_br_fn:
            de_fn.return_value = False
            br_fn.addbr.return_value = bridge_device
            bridge_device.setfd.return_value = False
            bridge_device.disable_stp.return_value = False
            bridge_device.disable_ipv6.return_value = False
            bridge_device.link.set_up.return_value = False
            self.assertEqual(self.lbm.ensure_bridge("br0", None), "br0")

            bridge_device.owns_interface.return_value = False
            self.lbm.ensure_bridge("br0", "eth0")
            upd_fn.assert_called_with("br0", "eth0", None, None)
            bridge_device.owns_interface.assert_called_with("eth0")

            self.lbm.ensure_bridge("br0", "eth0", "ips", "gateway")
            upd_fn.assert_called_with("br0", "eth0", "ips", "gateway")
            bridge_device.owns_interface.assert_called_with("eth0")

            de_fn.return_value = True
            bridge_device.delif.side_effect = Exception()
            self.lbm.ensure_bridge("br0", "eth0")
            bridge_device.owns_interface.assert_called_with("eth0")

            de_fn.return_value = True
            bridge_device.owns_interface.return_value = False
            get_if_br_fn.return_value = bridge_device_old
            bridge_device.addif.reset_mock()
            self.lbm.ensure_bridge("br0", "eth0")
            bridge_device_old.delif.assert_called_once_with('eth0')
            bridge_device.addif.assert_called_once_with('eth0')

    def test_ensure_physical_in_bridge(self):
        self.assertFalse(
            self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VLAN,
                                               "phys", "1")
        )
        with mock.patch.object(self.lbm, "ensure_flat_bridge") as flbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_FLAT,
                                                   "physnet1", None)
            )
            self.assertTrue(flbr_fn.called)
        with mock.patch.object(self.lbm, "ensure_vlan_bridge") as vlbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

        with mock.patch.object(self.lbm, "ensure_vxlan_bridge") as vlbr_fn:
            self.lbm.vxlan_mode = lconst.VXLAN_MCAST
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VXLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

    def test_ensure_physical_in_bridge_with_existed_brq(self):
        with mock.patch.object(linuxbridge_neutron_agent.LOG, 'error') as log:
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_FLAT,
                                                   "physnet9", "1")
                self.assertEqual(1, log.call_count)

    def test_add_tap_interface_owner_other(self):
        with mock.patch.object(ip_lib, "device_exists"):
            with mock.patch.object(self.lbm, "ensure_local_bridge"):
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           p_const.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1", "foo"))

    def _test_add_tap_interface(self, dev_owner_prefix):
        with mock.patch.object(ip_lib, "device_exists") as de_fn:
            de_fn.return_value = False
            self.assertFalse(
                self.lbm.add_tap_interface("123", p_const.TYPE_VLAN,
                                           "physnet1", "1", "tap1",
                                           dev_owner_prefix))

            de_fn.return_value = True
            bridge_device = mock.Mock()
            with mock.patch.object(self.lbm, "ensure_local_bridge") as en_fn,\
                    mock.patch.object(bridge_lib, "BridgeDevice",
                                      return_value=bridge_device), \
                    mock.patch.object(bridge_lib.BridgeDevice,
                                      "get_interface_bridge") as get_br:
                bridge_device.addif.retun_value = False
                get_br.return_value = True
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           p_const.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1",
                                                           dev_owner_prefix))
                en_fn.assert_called_with("123", "brq123")

                self.lbm.bridge_mappings = {"physnet1": "brq999"}
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           p_const.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1",
                                                           dev_owner_prefix))
                en_fn.assert_called_with("123", "brq999")

                get_br.return_value = False
                bridge_device.addif.retun_value = True
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            p_const.TYPE_LOCAL,
                                                            "physnet1", None,
                                                            "tap1",
                                                            dev_owner_prefix))
            with mock.patch.object(self.lbm,
                                   "ensure_physical_in_bridge") as ens_fn,\
                    mock.patch.object(self.lbm,
                                      "ensure_tap_mtu") as en_mtu_fn,\
                    mock.patch.object(bridge_lib.BridgeDevice,
                                      "get_interface_bridge") as get_br:
                ens_fn.return_value = False
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            p_const.TYPE_VLAN,
                                                            "physnet1", "1",
                                                            "tap1",
                                                            dev_owner_prefix))

                ens_fn.return_value = "eth0.1"
                get_br.return_value = "brq123"
                self.lbm.add_tap_interface("123", p_const.TYPE_VLAN,
                                           "physnet1", "1", "tap1",
                                           dev_owner_prefix)
                en_mtu_fn.assert_called_once_with("tap1", "eth0.1")
                bridge_device.addif.assert_called_once_with("tap1")

    def test_add_tap_interface_owner_network(self):
        self._test_add_tap_interface(constants.DEVICE_OWNER_NETWORK_PREFIX)

    def test_add_tap_interface_owner_neutron(self):
        self._test_add_tap_interface(constants.DEVICE_OWNER_NEUTRON_PREFIX)

    def test_add_interface(self):
        with mock.patch.object(self.lbm, "add_tap_interface") as add_tap:
            self.lbm.add_interface("123", p_const.TYPE_VLAN, "physnet-1",
                                   "1", "234",
                                   constants.DEVICE_OWNER_NETWORK_PREFIX)
            add_tap.assert_called_with("123", p_const.TYPE_VLAN, "physnet-1",
                                       "1", "tap234",
                                       constants.DEVICE_OWNER_NETWORK_PREFIX)

    def test_delete_bridge(self):
        with mock.patch.object(ip_lib.IPDevice, "exists") as de_fn,\
                mock.patch.object(ip_lib, "IpLinkCommand") as link_cmd,\
                mock.patch.object(bridge_lib.BridgeDevice,
                                  "get_interfaces") as getif_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_interface") as delif_fn:
            de_fn.return_value = False
            self.lbm.delete_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1", "vxlan-1002"]
            if_det_fn.return_value = ("ips", "gateway")
            link_cmd.set_down.return_value = False
            self.lbm.delete_bridge("br0")
            updif_fn.assert_called_with("eth1", "br0", "ips", "gateway")
            delif_fn.assert_called_with("vxlan-1002")

    def test_delete_bridge_with_ip(self):
        bridge_device = mock.Mock()
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_interface") as del_interface,\
                mock.patch.object(bridge_lib, "BridgeDevice",
                                  return_value=bridge_device):
            de_fn.return_value = True
            bridge_device.get_interfaces.return_value = ["eth0", "eth1.1"]
            if_det_fn.return_value = ("ips", "gateway")
            bridge_device.link.set_down.return_value = False
            self.lbm.delete_bridge("br0")
            updif_fn.assert_called_with("eth1.1", "br0", "ips", "gateway")
            self.assertFalse(del_interface.called)

    def test_delete_bridge_no_ip(self):
        bridge_device = mock.Mock()
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_interface") as del_interface,\
                mock.patch.object(bridge_lib, "BridgeDevice",
                                  return_value=bridge_device):
            de_fn.return_value = True
            bridge_device.get_interfaces.return_value = ["eth0", "eth1.1"]
            bridge_device.link.set_down.return_value = False
            if_det_fn.return_value = ([], None)
            self.lbm.delete_bridge("br0")
            del_interface.assert_called_with("eth1.1")
            self.assertFalse(updif_fn.called)

    def test_delete_bridge_no_int_mappings(self):
        lbm = get_linuxbridge_manager(
            bridge_mappings={}, interface_mappings={})

        with mock.patch.object(ip_lib.IPDevice, "exists") as de_fn,\
                mock.patch.object(ip_lib, "IpLinkCommand") as link_cmd,\
                mock.patch.object(bridge_lib.BridgeDevice,
                                  "get_interfaces") as getif_fn,\
                mock.patch.object(lbm, "remove_interface"),\
                mock.patch.object(lbm, "delete_interface") as del_interface:
            de_fn.return_value = False
            lbm.delete_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["vxlan-1002"]
            link_cmd.set_down.return_value = False
            lbm.delete_bridge("br0")
            del_interface.assert_called_with("vxlan-1002")

    def test_delete_bridge_with_physical_vlan(self):
        self.lbm.interface_mappings.update({"physnet2": "eth1.4000"})
        bridge_device = mock.Mock()
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm, "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm, "delete_interface") as del_int,\
                mock.patch.object(bridge_lib, "BridgeDevice",
                                  return_value=bridge_device):
            de_fn.return_value = True
            bridge_device.get_interfaces.return_value = ["eth1.1", "eth1.4000"]
            if_det_fn.return_value = ([], None)
            bridge_device.link.set_down.return_value = False
            self.lbm.delete_bridge("br0")
            del_int.assert_called_once_with("eth1.1")

    def test_remove_interface(self):
        with mock.patch.object(ip_lib.IPDevice, "exists") as de_fn,\
                mock.patch.object(bridge_lib,
                                  'is_bridged_interface') as isdev_fn,\
                mock.patch.object(bridge_lib.BridgeDevice,
                                  "delif") as delif_fn:
            de_fn.return_value = False
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))
            self.assertFalse(isdev_fn.called)

            de_fn.return_value = True
            isdev_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

            isdev_fn.return_value = True
            delif_fn.return_value = True
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))

            delif_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

    def test_delete_interface(self):
        with mock.patch.object(ip_lib.IPDevice, "exists") as de_fn,\
                mock.patch.object(ip_lib.IpLinkCommand, "set_down") as down_fn,\
                mock.patch.object(ip_lib.IpLinkCommand, "delete") as delete_fn:
            de_fn.return_value = False
            self.lbm.delete_interface("eth1.1")
            self.assertFalse(down_fn.called)
            self.assertFalse(delete_fn.called)

            de_fn.return_value = True
            self.lbm.delete_interface("eth1.1")
            self.assertTrue(down_fn.called)
            self.assertTrue(delete_fn.called)

    def _check_vxlan_support(self, expected, vxlan_ucast_supported,
                             vxlan_mcast_supported):
        with mock.patch.object(self.lbm,
                               'vxlan_ucast_supported',
                               return_value=vxlan_ucast_supported),\
                mock.patch.object(self.lbm,
                                  'vxlan_mcast_supported',
                                  return_value=vxlan_mcast_supported):
            if expected == lconst.VXLAN_NONE:
                self.assertRaises(exceptions.VxlanNetworkUnsupported,
                                  self.lbm.check_vxlan_support)
                self.assertEqual(expected, self.lbm.vxlan_mode)
            else:
                self.lbm.check_vxlan_support()
                self.assertEqual(expected, self.lbm.vxlan_mode)

    def test_check_vxlan_support(self):
        self._check_vxlan_support(expected=lconst.VXLAN_UCAST,
                                  vxlan_ucast_supported=True,
                                  vxlan_mcast_supported=True)
        self._check_vxlan_support(expected=lconst.VXLAN_MCAST,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=True)

        self._check_vxlan_support(expected=lconst.VXLAN_NONE,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=False)
        self._check_vxlan_support(expected=lconst.VXLAN_NONE,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=False)

    def _check_vxlan_ucast_supported(
            self, expected, l2_population, iproute_arg_supported, fdb_append):
        cfg.CONF.set_override('l2_population', l2_population, 'VXLAN')
        with mock.patch.object(ip_lib, 'device_exists', return_value=False),\
                mock.patch.object(ip_lib, 'vxlan_in_use', return_value=False),\
                mock.patch.object(self.lbm,
                                  'delete_interface',
                                  return_value=None),\
                mock.patch.object(self.lbm,
                                  'ensure_vxlan',
                                  return_value=None),\
                mock.patch.object(
                    utils,
                    'execute',
                    side_effect=None if fdb_append else RuntimeError()),\
                mock.patch.object(ip_lib,
                                  'iproute_arg_supported',
                                  return_value=iproute_arg_supported):
            self.assertEqual(expected, self.lbm.vxlan_ucast_supported())

    def test_vxlan_ucast_supported(self):
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=False, iproute_arg_supported=True, fdb_append=True)
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=True, iproute_arg_supported=False, fdb_append=True)
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=True, iproute_arg_supported=True, fdb_append=False)
        self._check_vxlan_ucast_supported(
            expected=True,
            l2_population=True, iproute_arg_supported=True, fdb_append=True)

    def _check_vxlan_mcast_supported(
            self, expected, vxlan_group, iproute_arg_supported):
        cfg.CONF.set_override('vxlan_group', vxlan_group, 'VXLAN')
        with mock.patch.object(
                ip_lib, 'iproute_arg_supported',
                return_value=iproute_arg_supported):
            self.assertEqual(expected, self.lbm.vxlan_mcast_supported())

    def test_vxlan_mcast_supported(self):
        self._check_vxlan_mcast_supported(
            expected=False,
            vxlan_group='',
            iproute_arg_supported=True)
        self._check_vxlan_mcast_supported(
            expected=False,
            vxlan_group='224.0.0.1',
            iproute_arg_supported=False)
        self._check_vxlan_mcast_supported(
            expected=True,
            vxlan_group='224.0.0.1',
            iproute_arg_supported=True)


class TestLinuxBridgeRpcCallbacks(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeRpcCallbacks, self).setUp()

        class FakeLBAgent(object):
            def __init__(self):
                self.agent_id = 1
                self.br_mgr = get_linuxbridge_manager(
                    BRIDGE_MAPPINGS, INTERFACE_MAPPINGS)

                self.br_mgr.vxlan_mode = lconst.VXLAN_UCAST
                segment = mock.Mock()
                segment.network_type = 'vxlan'
                segment.segmentation_id = 1
                self.br_mgr.network_map['net_id'] = segment
                self.updated_devices = set()
                self.network_ports = collections.defaultdict(list)

        self.lb_rpc = linuxbridge_neutron_agent.LinuxBridgeRpcCallbacks(
            object(),
            FakeLBAgent(),
            object()
        )

    def test_network_delete(self):
        mock_net = mock.Mock()
        mock_net.physical_network = None

        self.lb_rpc.agent.br_mgr.network_map = {NETWORK_ID: mock_net}

        with mock.patch.object(self.lb_rpc.agent.br_mgr,
                               "get_bridge_name") as get_br_fn,\
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "delete_bridge") as del_fn:
            get_br_fn.return_value = "br0"
            self.lb_rpc.network_delete("anycontext", network_id=NETWORK_ID)
            get_br_fn.assert_called_with(NETWORK_ID)
            del_fn.assert_called_with("br0")

    def test_port_update(self):
        port = {'id': PORT_1}
        self.lb_rpc.port_update(context=None, port=port)
        self.assertEqual(set([DEVICE_1]), self.lb_rpc.agent.updated_devices)

    def test_network_update(self):
        updated_network = {'id': NETWORK_ID}
        self.lb_rpc.agent.network_ports = {
            NETWORK_ID: [PORT_DATA]
        }
        self.lb_rpc.network_update(context=None, network=updated_network)
        self.assertEqual(set([DEVICE_1]), self.lb_rpc.agent.updated_devices)

    def test_network_delete_with_existed_brq(self):
        mock_net = mock.Mock()
        mock_net.physical_network = 'physnet0'

        self.lb_rpc.agent.br_mgr.network_map = {'123': mock_net}

        with mock.patch.object(linuxbridge_neutron_agent.LOG, 'info') as log,\
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "delete_bridge") as del_fn:
                self.lb_rpc.network_delete("anycontext", network_id="123")
                self.assertEqual(0, del_fn.call_count)
                self.assertEqual(1, log.call_count)

    def test_fdb_add(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {'agent_ip': [constants.FLOODING_ENTRY,
                                      ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn, \
                mock.patch.object(ip_lib.IpNeighCommand, 'add',
                                  return_value='') as add_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)

            expected = [
                mock.call(['bridge', 'fdb', 'show', 'dev', 'vxlan-1'],
                          run_as_root=True),
                mock.call(['bridge', 'fdb', 'add',
                           constants.FLOODING_ENTRY[0],
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'replace', 'port_mac', 'dev',
                           'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
            ]
            execute_fn.assert_has_calls(expected)
            add_fn.assert_called_with('port_ip', 'port_mac')

    def test_fdb_ignore(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {LOCAL_IP: [constants.FLOODING_ENTRY,
                                    ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)
            self.lb_rpc.fdb_remove(None, fdb_entries)

            self.assertFalse(execute_fn.called)

        fdb_entries = {'other_net_id':
                       {'ports':
                        {'192.168.0.67': [constants.FLOODING_ENTRY,
                                          ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)
            self.lb_rpc.fdb_remove(None, fdb_entries)

            self.assertFalse(execute_fn.called)

    def test_fdb_remove(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {'agent_ip': [constants.FLOODING_ENTRY,
                                      ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn, \
                mock.patch.object(ip_lib.IpNeighCommand, 'delete',
                                  return_value='') as del_fn:
            self.lb_rpc.fdb_remove(None, fdb_entries)

            expected = [
                mock.call(['bridge', 'fdb', 'del',
                           constants.FLOODING_ENTRY[0],
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'del', 'port_mac',
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
            ]
            execute_fn.assert_has_calls(expected)
            del_fn.assert_called_with('port_ip', 'port_mac')

    def test_fdb_update_chg_ip(self):
        fdb_entries = {'chg_ip':
                       {'net_id':
                        {'agent_ip':
                         {'before': [['port_mac', 'port_ip_1']],
                          'after': [['port_mac', 'port_ip_2']]}}}}

        with mock.patch.object(ip_lib.IpNeighCommand, 'add',
                               return_value='') as add_fn, \
                mock.patch.object(ip_lib.IpNeighCommand, 'delete',
                                  return_value='') as del_fn:
            self.lb_rpc.fdb_update(None, fdb_entries)

            del_fn.assert_called_with('port_ip_1', 'port_mac')
            add_fn.assert_called_with('port_ip_2', 'port_mac')

    def test_fdb_update_chg_ip_empty_lists(self):
        fdb_entries = {'chg_ip': {'net_id': {'agent_ip': {}}}}
        self.lb_rpc.fdb_update(None, fdb_entries)
