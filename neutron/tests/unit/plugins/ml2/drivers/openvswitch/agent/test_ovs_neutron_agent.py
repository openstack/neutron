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

import sys
import time

import mock
from neutron_lib.agent import constants as agent_consts
from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
import testtools

from neutron._i18n import _
from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.agent.linux import async_process
from neutron.agent.linux import ip_lib
from neutron.common import rpc as n_rpc
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent \
    as ovs_agent
from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import test_vlanmanager


NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
PULLAPI = 'neutron.api.rpc.handlers.resources_rpc.ResourcesPullRpcApi'
OVS_LINUX_KERN_VERS_WITHOUT_VXLAN = "3.12.0"

FAKE_MAC = '00:11:22:33:44:55'
FAKE_IP1 = '10.0.0.1'
FAKE_IP2 = '10.0.0.2'
FAKE_IP6 = '2001:db8:42:42::10'

TEST_PORT_ID1 = 'port-id-1'
TEST_PORT_ID2 = 'port-id-2'
TEST_PORT_ID3 = 'port-id-3'

TEST_NETWORK_ID1 = 'net-id-1'
TEST_NETWORK_ID2 = 'net-id-2'

DEVICE_OWNER_COMPUTE = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class FakeVif(object):
    ofport = 99
    port_name = 'name'
    vif_mac = 'aa:bb:cc:11:22:33'


class MockFixedIntervalLoopingCall(object):
    def __init__(self, f):
        self.f = f

    def start(self, interval=0):
        self.f()


class ValidateTunnelTypes(ovs_test_base.OVSAgentConfigTestBase):

    def setUp(self):
        super(ValidateTunnelTypes, self).setUp()
        self.mock_validate_local_ip = mock.patch.object(
            self.mod_agent, 'validate_local_ip').start()

    def test_validate_tunnel_types_succeeds(self):
        cfg.CONF.set_override('local_ip', '10.10.10.10', group='OVS')
        cfg.CONF.set_override('tunnel_types', [n_const.TYPE_GRE],
                              group='AGENT')
        self.mod_agent.validate_tunnel_config(cfg.CONF.AGENT.tunnel_types,
                                              cfg.CONF.OVS.local_ip)
        self.mock_validate_local_ip.assert_called_once_with('10.10.10.10')

    def test_validate_tunnel_types_fails_for_invalid_tunnel_type(self):
        cfg.CONF.set_override('local_ip', '10.10.10.10', group='OVS')
        cfg.CONF.set_override('tunnel_types', ['foobar'], group='AGENT')
        with testtools.ExpectedException(SystemExit):
            self.mod_agent.validate_tunnel_config(cfg.CONF.AGENT.tunnel_types,
                                                  cfg.CONF.OVS.local_ip)


class TestOvsNeutronAgent(object):

    def setUp(self):
        super(TestOvsNeutronAgent, self).setUp()
        self.useFixture(test_vlanmanager.LocalVlanManagerFixture())
        mock.patch(PULLAPI).start()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        systemd_patch = mock.patch('oslo_service.systemd.notify_once')
        self.systemd_notify = systemd_patch.start()

        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        cfg.CONF.set_default('local_ip', '127.0.0.1', 'OVS')
        mock.patch(
            'neutron.agent.ovsdb.native.helpers.enable_connection_uri').start()
        mock.patch(
            'neutron.agent.common.ovs_lib.OVSBridge.get_ports_attributes',
            return_value=[]).start()

        mock.patch('neutron.agent.common.ovs_lib.BaseOVS.config',
                   new_callable=mock.PropertyMock,
                   return_value={}).start()
        mock.patch('neutron.agent.ovsdb.impl_idl._connection').start()
        self.agent = self._make_agent()
        self.agent.sg_agent = mock.Mock()

    def _make_agent(self):
        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'),\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'setup_ancillary_bridges',
                                  return_value=[]),\
                mock.patch('neutron.agent.linux.ip_lib.get_device_mac',
                           return_value='00:00:00:00:00:01'),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.BaseOVS.get_bridges'),\
                mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                           new=MockFixedIntervalLoopingCall),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.OVSBridge.' 'get_vif_ports',
                    return_value=[]):
            ext_manager = mock.Mock()
            agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                   ext_manager, cfg.CONF)
            agent.tun_br = self.br_tun_cls(br_name='br-tun')
            return agent

    def _mock_port_bound(self, ofport=None, new_local_vlan=None,
                         old_local_vlan=None, db_get_val=None):
        port = mock.Mock()
        port.ofport = ofport
        net_uuid = 'my-net-uuid'
        fixed_ips = [{'subnet_id': 'my-subnet-uuid',
                      'ip_address': '1.1.1.1'}]
        if old_local_vlan is not None:
            self.agent.vlan_manager.add(
                net_uuid, old_local_vlan, None, None, None)
        with mock.patch.object(self.agent, 'int_br', autospec=True) as int_br:
            int_br.db_get_val.return_value = db_get_val
            int_br.set_db_attribute.return_value = True
            needs_binding = self.agent.port_bound(
                port, net_uuid, 'local', None, None,
                fixed_ips, DEVICE_OWNER_COMPUTE, False)
        if db_get_val is None:
            self.assertEqual(0, int_br.set_db_attribute.call_count)
            self.assertFalse(needs_binding)
        else:
            vlan_mapping = {'net_uuid': net_uuid,
                            'network_type': 'local',
                            'physical_network': 'None'}
            int_br.set_db_attribute.assert_called_once_with(
                "Port", mock.ANY, "other_config", vlan_mapping)
            self.assertTrue(needs_binding)

    def test_datapath_type_system(self):
        # verify kernel datapath is default
        expected = constants.OVS_DATAPATH_SYSTEM
        self.assertEqual(expected, self.agent.int_br.datapath_type)

    def test_datapath_type_netdev(self):

        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'), \
            mock.patch.object(self.mod_agent.OVSNeutronAgent,
                           'setup_ancillary_bridges',
                           return_value=[]), \
            mock.patch('neutron.agent.linux.ip_lib.get_device_mac',
                    return_value='00:00:00:00:00:01'), \
            mock.patch(
                'neutron.agent.common.ovs_lib.BaseOVS.get_bridges'), \
            mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall), \
            mock.patch(
                'neutron.agent.common.ovs_lib.OVSBridge.' 'get_vif_ports',
                return_value=[]), \
            mock.patch('neutron.agent.common.ovs_lib.BaseOVS.config',
                       new_callable=mock.PropertyMock,
                       return_value={'datapath_types': ['netdev']}):
            # validate setting non default datapath
            expected = constants.OVS_DATAPATH_NETDEV
            cfg.CONF.set_override('datapath_type',
                                  expected,
                                  group='OVS')
            ext_manager = mock.Mock()
            self.agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                        ext_manager, cfg.CONF)
            self.assertEqual(expected, self.agent.int_br.datapath_type)

    def test_agent_type_ovs(self):
        # verify agent_type is default
        expected = n_const.AGENT_TYPE_OVS
        self.assertEqual(expected,
                         self.agent.agent_state['agent_type'])

    def test_agent_available_local_vlans(self):
        expected = [n_const.MIN_VLAN_TAG,
                    n_const.MIN_VLAN_TAG + 1,
                    n_const.MAX_VLAN_TAG - 1,
                    n_const.MAX_VLAN_TAG]
        exception = [n_const.MIN_VLAN_TAG - 1,
                     n_const.MAX_VLAN_TAG + 1,
                     n_const.MAX_VLAN_TAG + 2]
        available_vlan = self.agent.available_local_vlans
        for tag in expected:
            self.assertIn(tag, available_vlan)
        for tag in exception:
            self.assertNotIn(tag, available_vlan)

    def test_agent_type_alt(self):
        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'),\
            mock.patch.object(self.mod_agent.OVSNeutronAgent,
                              'setup_ancillary_bridges',
                              return_value=[]), \
            mock.patch('neutron.agent.linux.ip_lib.get_device_mac',
                       return_value='00:00:00:00:00:01'), \
            mock.patch(
                'neutron.agent.common.ovs_lib.BaseOVS.get_bridges'), \
            mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall), \
            mock.patch(
                'neutron.agent.common.ovs_lib.OVSBridge.' 'get_vif_ports',
                return_value=[]):
            # validate setting non default agent_type
            expected = 'alt agent type'
            cfg.CONF.set_override('agent_type',
                                  expected,
                                  group='AGENT')
            ext_manager = mock.Mock()
            self.agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                        ext_manager, cfg.CONF)
            self.assertEqual(expected,
                             self.agent.agent_state['agent_type'])

    def _test_restore_local_vlan_maps(self, tag, segmentation_id='1'):
        port = mock.Mock()
        port.port_name = 'fake_port'
        net_uuid = 'fake_network_id'
        local_vlan_map = {'net_uuid': net_uuid,
                          'network_type': 'vlan',
                          'physical_network': 'fake_network'}
        if segmentation_id is not None:
            local_vlan_map['segmentation_id'] = segmentation_id

        # this is for the call inside get_vif_ports()
        get_interfaces = [{'name': port.port_name,
                           'ofport': '1',
                           'external_ids': {
                               'iface-id': '1',
                               'attached-mac': 'mac1'}},
                          {'name': 'invalid',
                           'ofport': ovs_lib.INVALID_OFPORT,
                           'external_ids': {
                               'iface-id': '2',
                               'attached-mac': 'mac2'}},
                          {'name': 'unassigned',
                           'ofport': ovs_lib.UNASSIGNED_OFPORT,
                           'external_ids': {
                               'iface-id': '3',
                               'attached-mac': 'mac3'}}]
        # this is for the call inside _restore_local_vlan_map()
        get_ports = [{'name': port.port_name,
                      'other_config': local_vlan_map,
                      'tag': tag}]

        with mock.patch.object(self.agent.int_br,
                               'get_ports_attributes',
                               side_effect=[get_interfaces, get_ports]) as gpa:
            self.agent._restore_local_vlan_map()
            expected_hints = {}
            if tag:
                expected_hints[net_uuid] = tag
            self.assertEqual(expected_hints, self.agent._local_vlan_hints)
            # make sure invalid and unassigned ports were skipped
            gpa.assert_has_calls([
                mock.call('Interface', columns=mock.ANY, if_exists=True),
                mock.call('Port', columns=mock.ANY, ports=['fake_port'])
            ])

    def test_restore_local_vlan_map_with_device_has_tag(self):
        self._test_restore_local_vlan_maps(2)

    def test_restore_local_vlan_map_with_device_no_tag(self):
        self._test_restore_local_vlan_maps([])

    def test_restore_local_vlan_map_no_segmentation_id(self):
        self._test_restore_local_vlan_maps(2, segmentation_id=None)

    def test_restore_local_vlan_map_segmentation_id_compat(self):
        self._test_restore_local_vlan_maps(2, segmentation_id='None')

    def test_check_agent_configurations_for_dvr_raises(self):
        self.agent.enable_distributed_routing = True
        self.agent.enable_tunneling = True
        self.agent.l2_pop = False
        self.assertRaises(ValueError,
                          self.agent._check_agent_configurations)

    def test_check_agent_configurations_for_dvr(self):
        self.agent.enable_distributed_routing = True
        self.agent.enable_tunneling = True
        self.agent.l2_pop = True
        self.assertIsNone(self.agent._check_agent_configurations())

    def test_check_agent_configurations_for_dvr_with_vlan(self):
        self.agent.enable_distributed_routing = True
        self.agent.enable_tunneling = False
        self.agent.l2_pop = False
        self.assertIsNone(self.agent._check_agent_configurations())

    def test_port_bound_deletes_flows_for_valid_ofport(self):
        self._mock_port_bound(ofport=1, new_local_vlan=1, db_get_val={})

    def test_port_bound_ignores_flows_for_invalid_ofport(self):
        self._mock_port_bound(ofport=-1, new_local_vlan=1, db_get_val={})

    def test_port_bound_does_not_rewire_if_already_bound(self):
        self._mock_port_bound(
            ofport=-1, new_local_vlan=1, old_local_vlan=1, db_get_val={})

    def test_port_bound_not_found(self):
        self._mock_port_bound(ofport=1, new_local_vlan=1, db_get_val=None)

    def _test_port_dead(self, cur_tag=None):
        port = mock.Mock()
        port.ofport = 1
        with mock.patch.object(self.agent, 'int_br') as int_br:
            int_br.db_get_val.return_value = cur_tag
            self.agent.port_dead(port)
        if cur_tag is None or cur_tag == constants.DEAD_VLAN_TAG:
            self.assertFalse(int_br.set_db_attribute.called)
            self.assertFalse(int_br.drop_port.called)
        else:
            int_br.assert_has_calls([
                mock.call.set_db_attribute("Port", mock.ANY, "tag",
                                           constants.DEAD_VLAN_TAG,
                                           log_errors=True),
                mock.call.drop_port(in_port=port.ofport),
            ])

    def test_port_dead(self):
        self._test_port_dead()

    def test_port_dead_with_port_already_dead(self):
        self._test_port_dead(constants.DEAD_VLAN_TAG)

    def test_port_dead_with_valid_tag(self):
        self._test_port_dead(cur_tag=1)

    def mock_scan_ports(self, vif_port_set=None, registered_ports=None,
                        updated_ports=None, port_tags_dict=None, sync=False):
        if port_tags_dict is None:  # Because empty dicts evaluate as False.
            port_tags_dict = {}
        with mock.patch.object(self.agent.int_br,
                               'get_vif_port_set',
                               return_value=vif_port_set),\
                mock.patch.object(self.agent.int_br,
                                  'get_port_tag_dict',
                                  return_value=port_tags_dict):
            return self.agent.scan_ports(registered_ports, sync, updated_ports)

    def test_scan_ports_returns_current_only_for_unchanged_ports(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 3])
        expected = {'current': vif_port_set,
                    'added': set(),
                    'removed': set()}
        actual = self.mock_scan_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_returns_port_changes(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]), removed=set([2]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_returns_port_changes_with_sync(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=vif_port_set,
                        removed=set([2]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      sync=True)
        self.assertEqual(expected, actual)

    def _test_scan_ports_with_updated_ports(self, updated_ports):
        vif_port_set = set([1, 3, 4])
        registered_ports = set([1, 2, 4])
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([4]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_finds_known_updated_ports(self):
        self._test_scan_ports_with_updated_ports(set([4]))

    def test_scan_ports_ignores_unknown_updated_ports(self):
        # the port '5' was not seen on current ports. Hence it has either
        # never been wired or already removed and should be ignored
        self._test_scan_ports_with_updated_ports(set([4, 5]))

    def test_scan_ports_ignores_updated_port_if_removed(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        updated_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([1]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_no_vif_changes_returns_updated_port_only(self):
        vif_port_set = set([1, 2, 3])
        registered_ports = set([1, 2, 3])
        updated_ports = set([2])
        expected = dict(current=vif_port_set, updated=set([2]),
                        added=set(), removed=set())
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def _test_process_ports_events(self, events, registered_ports,
                                   ancillary_ports, expected_ports,
                                   expected_ancillary, updated_ports=None,
                                   ):
        with mock.patch.object(self.agent, 'check_changed_vlans',
                               return_value=set()):
            devices_not_ready_yet = set()
            failed_devices = {'added': set(), 'removed': set()}
            failed_ancillary_devices = {
                'added': set(), 'removed': set()}
            actual = self.agent.process_ports_events(
                events, registered_ports, ancillary_ports,
                devices_not_ready_yet, failed_devices,
                failed_ancillary_devices, updated_ports)
            self.assertEqual(
                (expected_ports, expected_ancillary, devices_not_ready_yet),
                actual)

    def test_process_ports_events_port_removed_and_added(self):
        port_id = 'f6f104bd-37c7-4f7b-9d70-53a6bb42728f'
        events = {
            'removed':
                [{'ofport': 1,
                  'external_ids': {'iface-id': port_id,
                                   'attached-mac': 'fa:16:3e:f6:1b:fb'},
                  'name': 'qvof6f104bd-37'}],
            'added':
                [{'ofport': 2,
                  'external_ids': {'iface-id': port_id,
                                   'attached-mac': 'fa:16:3e:f6:1b:fb'},
                  'name': 'qvof6f104bd-37'}]
        }
        registered_ports = {port_id}
        expected_ancillary = dict(current=set(), added=set(), removed=set())

        # port was removed and then added
        expected_ports = dict(current={port_id},
                              added={port_id},
                              removed=set())
        with mock.patch.object(ovs_lib.BaseOVS, "port_exists",
                               return_value=True):
            self._test_process_ports_events(events.copy(), registered_ports,
                                            set(), expected_ports,
                                            expected_ancillary)

        # port was added and then removed
        expected_ports = dict(current=set(),
                              added=set(),
                              removed={port_id})
        with mock.patch.object(ovs_lib.BaseOVS, "port_exists",
                               return_value=False):
            self._test_process_ports_events(events.copy(), registered_ports,
                                            set(), expected_ports,
                                            expected_ancillary)

    def test_process_ports_events_returns_current_for_unchanged_ports(self):
        events = {'added': [], 'removed': []}
        registered_ports = {1, 3}
        ancillary_ports = {2, 5}
        expected_ports = {'current': registered_ports, 'added': set(),
                          'removed': set()}
        expected_ancillary = {'current': ancillary_ports, 'added': set(),
                              'removed': set()}
        self._test_process_ports_events(events, registered_ports,
                                        ancillary_ports, expected_ports,
                                        expected_ancillary)

    def test_process_port_events_no_vif_changes_return_updated_port_only(self):
        events = {'added': [], 'removed': []}
        registered_ports = {1, 2, 3}
        updated_ports = {2}
        expected_ports = dict(current=registered_ports, updated={2},
                              added=set(), removed=set())
        expected_ancillary = dict(current=set(), added=set(), removed=set())
        self._test_process_ports_events(events, registered_ports,
                                        set(), expected_ports,
                                        expected_ancillary, updated_ports)

    def test_process_port_events_ignores_removed_port_if_never_added(self):
        events = {'added': [],
                  'removed': [{'name': 'port2', 'ofport': 2,
                               'external_ids': {'attached-mac': 'test-mac'}}]}
        registered_ports = {1}
        expected_ports = dict(current=registered_ports, added=set(),
                              removed=set())
        expected_ancillary = dict(current=set(), added=set(), removed=set())
        devices_not_ready_yet = set()
        with mock.patch.object(self.agent.int_br, 'portid_from_external_ids',
                               side_effect=[2]), \
            mock.patch.object(self.agent, 'check_changed_vlans',
                              return_value=set()):
            failed_devices = {'added': set(), 'removed': set()}
            failed_ancillary_devices = {
                'added': set(), 'removed': set()}
            ports_not_ready_yet = set()
            actual = self.agent.process_ports_events(
                events, registered_ports, set(), ports_not_ready_yet,
                failed_devices, failed_ancillary_devices)
            self.assertEqual(
                (expected_ports, expected_ancillary, devices_not_ready_yet),
                actual)

    def test_process_port_events_port_not_ready_yet(self):
        events = {'added': [{'name': 'port5', 'ofport': [],
                  'external_ids': {'attached-mac': 'test-mac'}}],
                  'removed': []}
        old_devices_not_ready = {'port4'}
        registered_ports = set([1, 2, 3])
        expected_ports = dict(current=set([1, 2, 3, 4]),
                              added=set([4]), removed=set())
        self.agent.ancillary_brs = []
        expected_ancillary = dict(current=set(), added=set(), removed=set())
        with mock.patch.object(self.agent.int_br, 'portid_from_external_ids',
                               side_effect=[5, 4]), \
            mock.patch.object(self.agent, 'check_changed_vlans',
                              return_value=set()), \
            mock.patch.object(self.agent.int_br, 'get_ports_attributes',
                              return_value=[{'name': 'port4', 'ofport': 4,
                                             'external_ids': {
                                                 'attached-mac': 'mac4'}}]):
            expected_devices_not_ready = {'port5'}
            failed_devices = {'added': set(), 'removed': set()}
            failed_ancillary_devices = {
                'added': set(), 'removed': set()}
            actual = self.agent.process_ports_events(
                events, registered_ports, set(), old_devices_not_ready,
                failed_devices, failed_ancillary_devices)
            self.assertEqual(
                (expected_ports, expected_ancillary,
                 expected_devices_not_ready), actual)

    def _test_process_port_events_with_updated_ports(self, updated_ports):
        events = {'added': [{'name': 'port3', 'ofport': 3,
                            'external_ids': {'attached-mac': 'test-mac'}},
                            {'name': 'qg-port2', 'ofport': 6,
                             'external_ids': {'attached-mac': 'test-mac'}}],
                  'removed': [{'name': 'port2', 'ofport': 2,
                               'external_ids': {'attached-mac': 'test-mac'}},
                              {'name': 'qg-port1', 'ofport': 5,
                               'external_ids': {'attached-mac': 'test-mac'}}]}
        registered_ports = {1, 2, 4}
        ancillary_ports = {5, 8}
        expected_ports = dict(current={1, 3, 4}, added={3}, removed={2})
        if updated_ports:
            expected_ports['updated'] = updated_ports
        expected_ancillary = dict(current={6, 8}, added={6},
                                  removed={5})
        ancillary_bridge = mock.Mock()
        ancillary_bridge.get_vif_port_set.return_value = {5, 6, 8}
        self.agent.ancillary_brs = [ancillary_bridge]
        with mock.patch.object(self.agent.int_br, 'portid_from_external_ids',
                              side_effect=[3, 6, 2, 5]), \
            mock.patch.object(self.agent, 'check_changed_vlans',
                              return_value=set()):

            devices_not_ready_yet = set()
            failed_devices = {'added': set(), 'removed': set()}
            failed_ancillary_devices = {
                'added': set(), 'removed': set()}
            actual = self.agent.process_ports_events(
                events, registered_ports, ancillary_ports,
                devices_not_ready_yet, failed_devices,
                failed_ancillary_devices, updated_ports)
            self.assertEqual(
                (expected_ports, expected_ancillary, devices_not_ready_yet),
                actual)

    def test_process_port_events_returns_port_changes(self):
        self._test_process_port_events_with_updated_ports(set())

    def test_process_port_events_finds_known_updated_ports(self):
        self._test_process_port_events_with_updated_ports({4})

    def test_process_port_events_ignores_unknown_updated_ports(self):
        # the port '10' was not seen on current ports. Hence it has either
        # never been wired or already removed and should be ignored
        self._test_process_port_events_with_updated_ports({4, 10})

    def test_process_port_events_ignores_updated_port_if_removed(self):
        self._test_process_port_events_with_updated_ports({4, 5})

    def test_update_ports_returns_changed_vlan(self):
        br = self.br_int_cls('br-int')
        mac = "ca:fe:de:ad:be:ef"
        port = ovs_lib.VifPort(1, 1, 1, mac, br)
        self.agent.vlan_manager.add(
            '1', 1, '1', None, 1, {port.vif_id: port})
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        port_tags_dict = {1: []}
        expected = dict(
            added=set([3]), current=vif_port_set,
            removed=set([2]), updated=set([1])
        )
        with mock.patch.object(self.agent, 'tun_br', autospec=True), \
                mock.patch.object(self.agent.plugin_rpc,
                                  'update_device_list') as upd_l:
            actual = self.mock_scan_ports(
                vif_port_set, registered_ports, port_tags_dict=port_tags_dict)
        self.assertEqual(expected, actual)
        upd_l.assert_called_once_with(mock.ANY, [], set([1]),
                                      self.agent.agent_id,
                                      self.agent.conf.host)

    def test_update_retries_map_and_remove_devs_not_to_retry(self):
        failed_devices_retries_map = {
            'device_not_to_retry': constants.MAX_DEVICE_RETRIES,
            'device_to_retry': 2,
            'ancillary_not_to_retry': constants.MAX_DEVICE_RETRIES,
            'ancillary_to_retry': 1}
        failed_devices = {
            'added': set(['device_not_to_retry']),
            'removed': set(['device_to_retry', 'new_device'])}
        failed_ancillary_devices = {'added': set(['ancillary_to_retry']),
                                    'removed': set(['ancillary_not_to_retry'])}
        expected_failed_devices_retries_map = {
            'device_to_retry': 3, 'new_device': 1, 'ancillary_to_retry': 2}
        (new_failed_devices_retries_map, devices_not_to_retry,
         ancillary_devices_not_t_retry) = self.agent._get_devices_not_to_retry(
            failed_devices, failed_ancillary_devices,
            failed_devices_retries_map)
        self.agent._remove_devices_not_to_retry(
            failed_devices, failed_ancillary_devices, devices_not_to_retry,
            ancillary_devices_not_t_retry)
        self.assertIn('device_to_retry', failed_devices['removed'])
        self.assertNotIn('device_not_to_retry', failed_devices['added'])
        self.assertEqual(
            expected_failed_devices_retries_map,
            new_failed_devices_retries_map)

    def test_add_port_tag_info(self):
        lvm = mock.Mock()
        lvm.vlan = "1"
        self.agent.vlan_manager.mapping["net1"] = lvm
        ovs_db_list = [{'name': 'tap1',
                        'tag': [],
                        'other_config': {'segmentation_id': '1'}},
                       {'name': 'tap2',
                        'tag': [],
                        'other_config': {}},
                       {'name': 'tap3',
                        'tag': [],
                        'other_config': None}]
        vif_port1 = mock.Mock()
        vif_port1.port_name = 'tap1'
        vif_port2 = mock.Mock()
        vif_port2.port_name = 'tap2'
        vif_port3 = mock.Mock()
        vif_port3.port_name = 'tap3'
        port_details = [
            {'network_id': 'net1', 'vif_port': vif_port1},
            {'network_id': 'net1', 'vif_port': vif_port2},
            {'network_id': 'net1', 'vif_port': vif_port3}]
        with mock.patch.object(self.agent, 'int_br') as int_br:
            int_br.get_ports_attributes.return_value = ovs_db_list
            self.agent._add_port_tag_info(port_details)
            set_db_attribute_calls = \
                [mock.call.set_db_attribute("Port", "tap1",
                    "other_config", {"segmentation_id": "1", "tag": "1"}),
                 mock.call.set_db_attribute("Port", "tap2",
                    "other_config", {"tag": "1"}),
                 mock.call.set_db_attribute("Port", "tap3",
                    "other_config", {"tag": "1"})]
            int_br.assert_has_calls(set_db_attribute_calls, any_order=True)

    def test_bind_devices(self):
        devices_up = ['tap1']
        devices_down = ['tap2']
        self.agent.vlan_manager.mapping["net1"] = mock.Mock()
        ovs_db_list = [{'name': 'tap1', 'tag': []},
                       {'name': 'tap2', 'tag': []}]
        vif_port1 = mock.Mock()
        vif_port1.port_name = 'tap1'
        vif_port2 = mock.Mock()
        vif_port2.port_name = 'tap2'
        port_details = [
            {'network_id': 'net1', 'vif_port': vif_port1,
             'device': devices_up[0],
             'device_owner': 'network:dhcp',
             'admin_state_up': True},
            {'network_id': 'net1', 'vif_port': vif_port2,
             'device': devices_down[0],
             'device_owner': 'network:dhcp',
             'admin_state_up': False}]
        with mock.patch.object(
            self.agent.plugin_rpc, 'update_device_list',
            return_value={'devices_up': devices_up,
                          'devices_down': devices_down,
                          'failed_devices_up': [],
                          'failed_devices_down': []}) as update_devices, \
                mock.patch.object(self.agent,
                                  'int_br') as int_br:
            int_br.get_ports_attributes.return_value = ovs_db_list
            self.agent._bind_devices(port_details)
            update_devices.assert_called_once_with(mock.ANY, devices_up,
                                                   devices_down,
                                                   mock.ANY, mock.ANY,
                                                   agent_restarted=True)

    def _test_arp_spoofing(self, enable_prevent_arp_spoofing):
        self.agent.prevent_arp_spoofing = enable_prevent_arp_spoofing

        ovs_db_list = [{'name': 'fake_device', 'tag': []}]
        self.agent.vlan_manager.add('fake_network', 1, None, None, 1)
        vif_port = mock.Mock()
        vif_port.port_name = 'fake_device'
        vif_port.ofport = 1
        need_binding_ports = [{'network_id': 'fake_network',
                               'vif_port': vif_port,
                               'device': 'fake_device',
                               'admin_state_up': True}]
        with mock.patch.object(
            self.agent.plugin_rpc, 'update_device_list',
            return_value={'devices_up': [],
                          'devices_down': [],
                          'failed_devices_up': [],
                          'failed_devices_down': []}), \
                mock.patch.object(self.agent,
                                  'int_br') as int_br, \
                mock.patch.object(
                    self.agent,
                    'setup_arp_spoofing_protection') as setup_arp:
            int_br.get_ports_attributes.return_value = ovs_db_list
            self.agent._bind_devices(need_binding_ports)
            self.assertEqual(enable_prevent_arp_spoofing, setup_arp.called)

    def test_setup_arp_spoofing_protection_enable(self):
        self._test_arp_spoofing(True)

    def test_setup_arp_spoofing_protection_disabled(self):
        self._test_arp_spoofing(False)

    def _mock_treat_devices_added_updated(self, details, port, func_name):
        """Mock treat devices added or updated.

        :param details: the details to return for the device
        :param port: the port that get_vif_port_by_id should return
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with mock.patch.object(self.agent.plugin_rpc,
                               'get_devices_details_list_and_failed_devices',
                               return_value={'devices': [details],
                                             'failed_devices': []}),\
                mock.patch.object(self.agent.int_br,
                                  'get_vifs_by_ids',
                                  return_value={details['device']: port}),\
                mock.patch.object(self.agent.plugin_rpc, 'update_device_list',
                                  return_value={'devices_up': [],
                                                'devices_down': details,
                                                'failed_devices_up': [],
                                                'failed_devices_down': []}),\
                mock.patch.object(self.agent.int_br,
                    'get_port_tag_dict',
                    return_value={}),\
                mock.patch.object(self.agent, func_name) as func:
            skip_devs, need_bound_devices, _ = (
                self.agent.treat_devices_added_or_updated([], False))
            # The function should not raise
            self.assertFalse(skip_devs)
            return func.called

    def test_treat_devices_added_updated_ignores_invalid_ofport(self):
        port = mock.Mock()
        port.ofport = -1
        self.assertFalse(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port, 'port_dead'))

    def test_treat_devices_added_updated_marks_unknown_port_as_dead(self):
        port = mock.Mock()
        port.ofport = 1
        self.assertTrue(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port, 'port_dead'))

    def test_treat_devices_added_does_not_process_missing_port(self):
        with mock.patch.object(
            self.agent.plugin_rpc,
            'get_devices_details_list_and_failed_devices') as get_dev_fn,\
                mock.patch.object(self.agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=None):
            self.assertFalse(get_dev_fn.called)

    def test_treat_devices_added_updated_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        self.assertTrue(self._mock_treat_devices_added_updated(
            details, mock.Mock(), 'treat_vif_port'))

    def test_treat_devices_added_updated_sends_vif_port_into_extension_manager(
        self, *args):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        port = mock.MagicMock()

        def fake_handle_port(context, port):
            self.assertIn('vif_port', port)

        with mock.patch.object(self.agent.plugin_rpc,
                               'get_devices_details_list_and_failed_devices',
                               return_value={'devices': [details],
                                             'failed_devices': []}),\
            mock.patch.object(self.agent.ext_manager,
                              'handle_port', new=fake_handle_port),\
            mock.patch.object(self.agent.int_br,
                              'get_vifs_by_ids',
                              return_value={details['device']: port}),\
            mock.patch.object(self.agent, 'treat_vif_port',
                              return_value=False):

            self.agent.treat_devices_added_or_updated([], False)

    def test_treat_devices_added_updated_skips_if_port_not_found(self):
        dev_mock = mock.MagicMock()
        dev_mock.__getitem__.return_value = 'the_skipped_one'
        with mock.patch.object(self.agent.plugin_rpc,
                               'get_devices_details_list_and_failed_devices',
                               return_value={'devices': [dev_mock],
                                             'failed_devices': []}),\
                mock.patch.object(self.agent.int_br,
                    'get_port_tag_dict',
                    return_value={}),\
                mock.patch.object(self.agent.int_br,
                                  'get_vifs_by_ids',
                                  return_value={}),\
                mock.patch.object(self.agent.ext_manager,
                                  "delete_port") as ext_mgr_delete_port,\
                mock.patch.object(self.agent,
                                  'treat_vif_port') as treat_vif_port:
            skip_devs = self.agent.treat_devices_added_or_updated([], False)
            # The function should return False for resync and no device
            # processed
            self.assertEqual((['the_skipped_one'], [], set()), skip_devs)
            ext_mgr_delete_port.assert_called_once_with(
                self.agent.context, {'port_id': 'the_skipped_one'})
            self.assertFalse(treat_vif_port.called)

    def test_treat_devices_added_failed_devices(self):
        dev_mock = 'the_failed_one'
        with mock.patch.object(self.agent.plugin_rpc,
                               'get_devices_details_list_and_failed_devices',
                               return_value={'devices': [],
                                             'failed_devices': [dev_mock]}),\
                mock.patch.object(self.agent.int_br,
                                  'get_vifs_by_ids',
                                  return_value={}),\
                mock.patch.object(self.agent,
                                  'treat_vif_port') as treat_vif_port:
            failed_devices = {'added': set(), 'removed': set()}
            (_, _, failed_devices['added']) = (
                self.agent.treat_devices_added_or_updated([], False))
            # The function should return False for resync and no device
            # processed
            self.assertEqual(set([dev_mock]), failed_devices.get('added'))
            self.assertFalse(treat_vif_port.called)

    def test_treat_devices_added_updated_put_port_down(self):
        fake_details_dict = {'admin_state_up': False,
                             'port_id': 'xxx',
                             'device': 'xxx',
                             'network_id': 'yyy',
                             'physical_network': 'foo',
                             'segmentation_id': 'bar',
                             'network_type': 'baz',
                             'fixed_ips': [{'subnet_id': 'my-subnet-uuid',
                                            'ip_address': '1.1.1.1'}],
                             'device_owner': DEVICE_OWNER_COMPUTE
                             }

        with mock.patch.object(self.agent.plugin_rpc,
                               'get_devices_details_list_and_failed_devices',
                               return_value={'devices': [fake_details_dict],
                                             'failed_devices': []}),\
                mock.patch.object(self.agent.int_br,
                                  'get_vifs_by_ids',
                                  return_value={'xxx': mock.MagicMock()}),\
                mock.patch.object(self.agent.int_br, 'get_port_tag_dict',
                                  return_value={}),\
                mock.patch.object(self.agent,
                                  'treat_vif_port') as treat_vif_port:
            skip_devs, need_bound_devices, _ = (
                self.agent.treat_devices_added_or_updated([], False))
            # The function should return False for resync
            self.assertFalse(skip_devs)
            self.assertTrue(treat_vif_port.called)

    def _mock_treat_devices_removed(self, port_exists):
        details = dict(exists=port_exists)
        with mock.patch.object(self.agent.plugin_rpc,
                               'update_device_list',
                               return_value={'devices_up': [],
                                             'devices_down': details,
                                             'failed_devices_up': [],
                                             'failed_devices_down': []}):
            with mock.patch.object(self.agent, 'port_unbound') as port_unbound:
                self.assertFalse(self.agent.treat_devices_removed([{}]))
        self.assertTrue(port_unbound.called)

    def test_treat_devices_removed_unbinds_port(self):
        self._mock_treat_devices_removed(True)

    def test_treat_devices_removed_ignores_missing_port(self):
        self._mock_treat_devices_removed(False)

    def test_treat_devices_removed_failed_devices(self):
        dev_mock = 'the_failed_one'
        with mock.patch.object(self.agent.plugin_rpc,
                               'update_device_list',
                               return_value={'devices_up': [],
                                             'devices_down': [],
                                             'failed_devices_up': [],
                                             'failed_devices_down': [
                                                 dev_mock]}):
            failed_devices = {'added': set(), 'removed': set()}
            failed_devices['removed'] = self.agent.treat_devices_removed([{}])
            self.assertEqual(set([dev_mock]), failed_devices.get('removed'))

    def test_treat_devices_removed_ext_delete_port(self):
        port_id = 'fake-id'

        m_delete = mock.patch.object(self.agent.ext_manager, 'delete_port')
        m_rpc = mock.patch.object(self.agent.plugin_rpc, 'update_device_list',
                                  return_value={'devices_up': [],
                                                'devices_down': [],
                                                'failed_devices_up': [],
                                                'failed_devices_down': []})
        m_unbound = mock.patch.object(self.agent, 'port_unbound')

        with m_delete as delete, m_rpc, m_unbound:
            self.agent.treat_devices_removed([port_id])
            delete.assert_called_with(mock.ANY, {'port_id': port_id})

    def test_treat_vif_port_shut_down_port(self):
        details = mock.MagicMock()
        vif_port = type('vif_port', (object,), {
            "vif_id": "12",
            "iface-id": "407a79e0-e0be-4b7d-92a6-513b2161011b",
            "vif_mac": "fa:16:3e:68:46:7b",
            "port_name": "qr-407a79e0-e0",
            "ofport": -1,
            "bridge_name": "br-int"})
        with mock.patch.object(
                self.agent.plugin_rpc, 'update_device_down'
        ) as update_device_down, mock.patch.object(
            self.agent, "port_dead"
        ) as port_dead:
            port_needs_binding = self.agent.treat_vif_port(
                vif_port, details['port_id'],
                details['network_id'],
                details['network_type'],
                details['physical_network'],
                details['segmentation_id'],
                False,
                details['fixed_ips'],
                details['device_owner'], False)
        self.assertFalse(port_needs_binding)
        port_dead.assert_called_once_with(vif_port)
        update_device_down.assert_called_once_with(
            self.agent.context, details['port_id'], self.agent.agent_id,
            self.agent.conf.host)

    def test_bind_port_with_missing_network(self):
        vif_port = mock.Mock()
        vif_port.name.return_value = 'port'
        self.agent._bind_devices([{'network_id': 'non-existent',
                                   'vif_port': vif_port}])

    def _test_process_network_ports(self, port_info, skipped_devices=None):
        failed_devices = {'added': set(), 'removed': set()}
        skipped_devices = skipped_devices or []
        added_devices = port_info.get('added', set())
        with mock.patch.object(self.agent.sg_agent,
                               "setup_port_filters") as setup_port_filters,\
                mock.patch.object(
                    self.agent, "treat_devices_added_or_updated",
                    return_value=(
                        skipped_devices, [],
                        failed_devices['added'])) as device_added_updated,\
                mock.patch.object(self.agent.int_br, "get_ports_attributes",
                                  return_value=[]),\
                mock.patch.object(self.agent,
                                  "treat_devices_removed",
                                  return_value=(
                                      failed_devices[
                                          'removed'])) as device_removed,\
                mock.patch.object(self.agent,
                                  "treat_devices_skipped",
                                  return_value=(
                                      skipped_devices)) as device_skipped:
            self.assertEqual(
                failed_devices,
                self.agent.process_network_ports(port_info, False))
            setup_port_filters.assert_called_once_with(
                added_devices - set(skipped_devices),
                port_info.get('updated', set()))
            devices_added_updated = (added_devices |
                                     port_info.get('updated', set()))
            if devices_added_updated:
                device_added_updated.assert_called_once_with(
                    devices_added_updated, False)
            if port_info.get('removed', set()):
                device_removed.assert_called_once_with(port_info['removed'])
            if skipped_devices:
                device_skipped.assert_called_once_with(set(skipped_devices))

    def test_process_network_ports(self):
        self._test_process_network_ports(
            {'current': set(['tap0']),
             'removed': set(['eth0']),
             'added': set(['eth1'])})

    def test_process_network_port_with_updated_ports(self):
        self._test_process_network_ports(
            {'current': set(['tap0', 'tap1']),
             'updated': set(['tap1', 'eth1']),
             'removed': set(['eth0']),
             'added': set(['eth1'])})

    def test_process_network_port_with_skipped_ports(self):
        port_info = {'current': set(['tap0', 'tap1']),
                     'removed': set(['eth0']),
                     'added': set(['eth1', 'eth2'])}
        self._test_process_network_ports(port_info, skipped_devices=['eth1'])

    def test_process_network_port_with_empty_port(self):
        self._test_process_network_ports({})

    def test_hybrid_plug_flag_based_on_firewall(self):
        cfg.CONF.set_default(
            'firewall_driver',
            'neutron.agent.firewall.NoopFirewallDriver',
            group='SECURITYGROUP')
        agt = self._make_agent()
        self.assertFalse(agt.agent_state['configurations']['ovs_hybrid_plug'])
        cfg.CONF.set_default(
            'firewall_driver',
            'neutron.agent.linux.openvswitch_firewall.OVSFirewallDriver',
            group='SECURITYGROUP')
        with mock.patch('neutron.agent.linux.openvswitch_firewall.'
                        'OVSFirewallDriver.initialize_bridge'):
            agt = self._make_agent()
        self.assertFalse(agt.agent_state['configurations']['ovs_hybrid_plug'])
        cfg.CONF.set_default(
            'firewall_driver',
            'neutron.agent.linux.iptables_firewall.'
            'OVSHybridIptablesFirewallDriver',
            group='SECURITYGROUP')
        with mock.patch('neutron.agent.linux.ip_conntrack.'
                        'IpConntrackManager._populate_initial_zone_map'):
            agt = self._make_agent()
        self.assertTrue(agt.agent_state['configurations']['ovs_hybrid_plug'])

    def test_report_state(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            self.agent.int_br_device_count = 5
            self.systemd_notify.assert_not_called()
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state, True)
            self.systemd_notify.assert_called_once_with()
            self.systemd_notify.reset_mock()
            # agent keeps sending "start_flag" while iter 0 not completed
            self.assertIn("start_flag", self.agent.agent_state)
            self.assertEqual(
                self.agent.agent_state["configurations"]["devices"],
                self.agent.int_br_device_count
            )
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state, True)
            self.systemd_notify.assert_not_called()

    def test_report_state_fail(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            report_st.side_effect = Exception()
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state, True)
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state, True)
            self.systemd_notify.assert_not_called()

    def test_report_state_revived(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            report_st.return_value = agent_consts.AGENT_REVIVED
            self.agent._report_state()
            self.assertTrue(self.agent.fullsync)

    def test_port_update(self):
        port = {"id": TEST_PORT_ID1,
                "network_id": TEST_NETWORK_ID1,
                "admin_state_up": False}
        self.agent.port_update("unused_context",
                               port=port,
                               network_type="vlan",
                               segmentation_id="1",
                               physical_network="physnet")
        self.assertEqual(set([TEST_PORT_ID1]), self.agent.updated_ports)

    def test_port_delete_after_update(self):
        """Make sure a port is not marked for delete and update."""
        port = {'id': TEST_PORT_ID1}

        self.agent.port_update(context=None, port=port)
        self.agent.port_delete(context=None, port_id=port['id'])
        self.assertEqual(set(), self.agent.updated_ports)
        self.assertEqual(set([port['id']]), self.agent.deleted_ports)

    def test_process_deleted_ports_cleans_network_ports(self):
        self.agent._update_port_network(TEST_PORT_ID1, TEST_NETWORK_ID1)
        self.agent.port_delete(context=None, port_id=TEST_PORT_ID1)
        self.agent.sg_agent = mock.Mock()
        self.agent.int_br = mock.Mock()
        self.agent.process_deleted_ports(port_info={})
        self.assertEqual(set(), self.agent.network_ports[TEST_NETWORK_ID1])

    def test_network_update(self):
        """Network update marks port for update. """
        network = {'id': TEST_NETWORK_ID1}
        port = {'id': TEST_PORT_ID1, 'network_id': network['id']}

        self.agent._update_port_network(port['id'], port['network_id'])
        self.agent.network_update(context=None, network=network)
        self.assertEqual(set([port['id']]), self.agent.updated_ports)

    def test_network_update_outoforder(self):
        """Network update arrives later than port_delete.

        But the main agent loop still didn't process the ports,
        so we ensure the port is not marked for update.
        """
        network = {'id': TEST_NETWORK_ID1}
        port = {'id': TEST_PORT_ID1, 'network_id': network['id']}

        self.agent._update_port_network(port['id'], port['network_id'])
        self.agent.port_delete(context=None, port_id=port['id'])
        self.agent.network_update(context=None, network=network)
        self.assertEqual(set(), self.agent.updated_ports)

    def test_update_port_network(self):
        """Ensure ports are associated and moved across networks correctly."""
        self.agent._update_port_network(TEST_PORT_ID1, TEST_NETWORK_ID1)
        self.agent._update_port_network(TEST_PORT_ID2, TEST_NETWORK_ID1)
        self.agent._update_port_network(TEST_PORT_ID3, TEST_NETWORK_ID2)
        self.agent._update_port_network(TEST_PORT_ID1, TEST_NETWORK_ID2)

        self.assertEqual(set([TEST_PORT_ID2]),
                         self.agent.network_ports[TEST_NETWORK_ID1])
        self.assertEqual(set([TEST_PORT_ID1, TEST_PORT_ID3]),
                         self.agent.network_ports[TEST_NETWORK_ID2])

    def test_port_delete(self):
        vif = FakeVif()
        with mock.patch.object(self.agent, 'int_br') as int_br:
            int_br.get_vif_by_port_id.return_value = vif.port_name
            int_br.get_vif_port_by_id.return_value = vif
            self.agent.port_delete("unused_context",
                                   port_id='id')
            self.agent.process_deleted_ports(port_info={})
            # the main things we care about are that it gets put in the
            # dead vlan and gets blocked
            int_br.set_db_attribute.assert_any_call(
                'Port', vif.port_name, 'tag', constants.DEAD_VLAN_TAG,
                log_errors=False)
            int_br.drop_port.assert_called_once_with(in_port=vif.ofport)

    def test_port_delete_removed_port(self):
        with mock.patch.object(self.agent, 'int_br') as int_br:
            self.agent.port_delete("unused_context",
                                   port_id='id')
            # if it was removed from the bridge, we shouldn't be processing it
            self.agent.process_deleted_ports(port_info={'removed': {'id', }})
            self.assertFalse(int_br.set_db_attribute.called)
            self.assertFalse(int_br.drop_port.called)

    def _test_setup_physical_bridges(self, port_exists=False):
        with mock.patch.object(ip_lib.IPDevice, "exists") as devex_fn,\
                mock.patch.object(sys, "exit"),\
                mock.patch.object(self.agent, 'br_phys_cls') as phys_br_cls,\
                mock.patch.object(self.agent, 'int_br') as int_br,\
                mock.patch.object(self.agent, '_check_bridge_datapath_id'),\
                mock.patch.object(ovs_lib.BaseOVS, 'get_bridges'):
            devex_fn.return_value = True
            parent = mock.MagicMock()
            phys_br = phys_br_cls()
            parent.attach_mock(phys_br_cls, 'phys_br_cls')
            parent.attach_mock(phys_br, 'phys_br')
            parent.attach_mock(int_br, 'int_br')
            if port_exists:
                phys_br.get_port_ofport.return_value = "phy_ofport"
                int_br.get_port_ofport.return_value = "int_ofport"
            else:
                phys_br.add_patch_port.return_value = "phy_ofport"
                int_br.add_patch_port.return_value = "int_ofport"
            phys_br.port_exists.return_value = port_exists
            int_br.port_exists.return_value = port_exists
            self.agent.setup_physical_bridges({"physnet1": "br-eth"})
            expected_calls = [
                mock.call.phys_br_cls('br-eth'),
                mock.call.phys_br.create(),
                mock.call.phys_br.set_secure_mode(),
                mock.call.phys_br.setup_controllers(mock.ANY),
                mock.call.phys_br.setup_default_table(),
                mock.call.int_br.db_get_val('Interface', 'int-br-eth',
                                            'type', log_errors=False),
                # Have to use __getattr__ here to avoid mock._Call.__eq__
                # method being called
                mock.call.int_br.db_get_val().__getattr__('__eq__')('veth'),
                mock.call.int_br.port_exists('int-br-eth'),
            ]
            if port_exists:
                expected_calls += [
                    mock.call.int_br.get_port_ofport('int-br-eth'),
                ]
            else:
                expected_calls += [
                    mock.call.int_br.add_patch_port(
                        'int-br-eth', constants.NONEXISTENT_PEER),
                ]
            expected_calls += [
                mock.call.phys_br.port_exists('phy-br-eth'),
            ]
            if port_exists:
                expected_calls += [
                    mock.call.phys_br.get_port_ofport('phy-br-eth'),
                ]
            else:
                expected_calls += [
                    mock.call.phys_br.add_patch_port(
                        'phy-br-eth', constants.NONEXISTENT_PEER),
                ]
            expected_calls += [
                mock.call.int_br.drop_port(in_port='int_ofport'),
                mock.call.phys_br.drop_port(in_port='phy_ofport'),
                mock.call.int_br.set_db_attribute('Interface', 'int-br-eth',
                                                  'options',
                                                  {'peer': 'phy-br-eth'}),
                mock.call.phys_br.set_db_attribute('Interface', 'phy-br-eth',
                                                   'options',
                                                   {'peer': 'int-br-eth'}),
            ]
            parent.assert_has_calls(expected_calls)
            self.assertEqual("int_ofport",
                             self.agent.int_ofports["physnet1"])
            self.assertEqual("phy_ofport",
                             self.agent.phys_ofports["physnet1"])

    def test_setup_physical_bridges(self):
        self._test_setup_physical_bridges()

    def test_setup_physical_bridges_port_exists(self):
        self._test_setup_physical_bridges(port_exists=True)

    def test_setup_physical_bridges_using_veth_interconnection(self):
        self.agent.use_veth_interconnection = True
        with mock.patch.object(ip_lib.IPDevice, "exists") as devex_fn,\
                mock.patch.object(sys, "exit"),\
                mock.patch.object(utils, "execute") as utilsexec_fn,\
                mock.patch.object(self.agent, 'br_phys_cls') as phys_br_cls,\
                mock.patch.object(self.agent, 'int_br') as int_br,\
                mock.patch.object(self.agent, '_check_bridge_datapath_id'),\
                mock.patch.object(ip_lib.IPWrapper, "add_veth") as addveth_fn,\
                mock.patch.object(ip_lib.IpLinkCommand,
                                  "delete") as linkdel_fn,\
                mock.patch.object(ip_lib.IpLinkCommand, "set_up"),\
                mock.patch.object(ip_lib.IpLinkCommand, "set_mtu"),\
                mock.patch.object(ovs_lib.BaseOVS, "get_bridges") as get_br_fn:
            devex_fn.return_value = True
            parent = mock.MagicMock()
            parent.attach_mock(utilsexec_fn, 'utils_execute')
            parent.attach_mock(linkdel_fn, 'link_delete')
            parent.attach_mock(addveth_fn, 'add_veth')
            addveth_fn.return_value = (ip_lib.IPDevice("int-br-eth1"),
                                       ip_lib.IPDevice("phy-br-eth1"))
            phys_br = phys_br_cls()
            phys_br.add_port.return_value = "phys_veth_ofport"
            int_br.add_port.return_value = "int_veth_ofport"
            get_br_fn.return_value = ["br-eth"]
            self.agent.setup_physical_bridges({"physnet1": "br-eth"})
            expected_calls = [mock.call.link_delete(),
                              mock.call.utils_execute(['udevadm',
                                                       'settle',
                                                       '--timeout=10']),
                              mock.call.add_veth('int-br-eth',
                                                 'phy-br-eth')]
            parent.assert_has_calls(expected_calls, any_order=False)
            self.assertEqual("int_veth_ofport",
                             self.agent.int_ofports["physnet1"])
            self.assertEqual("phys_veth_ofport",
                             self.agent.phys_ofports["physnet1"])
            int_br.add_port.assert_called_with("int-br-eth")
            phys_br.add_port.assert_called_with("phy-br-eth")

    def _test_setup_physical_bridges_change_from_veth_to_patch_conf(
            self, port_exists=False):
        with mock.patch.object(sys, "exit"),\
                mock.patch.object(self.agent, 'br_phys_cls') as phys_br_cls,\
                mock.patch.object(self.agent, 'int_br') as int_br,\
                mock.patch.object(self.agent.int_br, 'db_get_val',
                                  return_value='veth'), \
                mock.patch.object(self.agent, '_check_bridge_datapath_id'), \
                mock.patch.object(ovs_lib.BaseOVS, 'get_bridges'):
            phys_br = phys_br_cls()
            parent = mock.MagicMock()
            parent.attach_mock(phys_br_cls, 'phys_br_cls')
            parent.attach_mock(phys_br, 'phys_br')
            parent.attach_mock(int_br, 'int_br')
            if port_exists:
                phys_br.get_port_ofport.return_value = "phy_ofport"
                int_br.get_port_ofport.return_value = "int_ofport"
            else:
                phys_br.add_patch_port.return_value = "phy_ofport"
                int_br.add_patch_port.return_value = "int_ofport"
            phys_br.port_exists.return_value = port_exists
            int_br.port_exists.return_value = port_exists
            self.agent.setup_physical_bridges({"physnet1": "br-eth"})
            expected_calls = [
                mock.call.phys_br_cls('br-eth'),
                mock.call.phys_br.create(),
                mock.call.phys_br.set_secure_mode(),
                mock.call.phys_br.setup_controllers(mock.ANY),
                mock.call.phys_br.setup_default_table(),
                mock.call.int_br.delete_port('int-br-eth'),
                mock.call.phys_br.delete_port('phy-br-eth'),
                mock.call.int_br.port_exists('int-br-eth'),
            ]
            if port_exists:
                expected_calls += [
                    mock.call.int_br.get_port_ofport('int-br-eth'),
                ]
            else:
                expected_calls += [
                    mock.call.int_br.add_patch_port(
                        'int-br-eth', constants.NONEXISTENT_PEER),
                ]
            expected_calls += [
                mock.call.phys_br.port_exists('phy-br-eth'),
            ]
            if port_exists:
                expected_calls += [
                    mock.call.phys_br.get_port_ofport('phy-br-eth'),
                ]
            else:
                expected_calls += [
                    mock.call.phys_br.add_patch_port(
                        'phy-br-eth', constants.NONEXISTENT_PEER),
                ]
            expected_calls += [
                mock.call.int_br.drop_port(in_port='int_ofport'),
                mock.call.phys_br.drop_port(in_port='phy_ofport'),
                mock.call.int_br.set_db_attribute('Interface', 'int-br-eth',
                                                  'options',
                                                  {'peer': 'phy-br-eth'}),
                mock.call.phys_br.set_db_attribute('Interface', 'phy-br-eth',
                                                   'options',
                                                   {'peer': 'int-br-eth'}),
            ]
            parent.assert_has_calls(expected_calls)
            self.assertEqual("int_ofport",
                             self.agent.int_ofports["physnet1"])
            self.assertEqual("phy_ofport",
                             self.agent.phys_ofports["physnet1"])

    def test_setup_physical_bridges_change_from_veth_to_patch_conf(self):
        self._test_setup_physical_bridges_change_from_veth_to_patch_conf()

    def test_setup_physical_bridges_change_from_veth_to_patch_conf_port_exists(
            self):
        self._test_setup_physical_bridges_change_from_veth_to_patch_conf(
            port_exists=True)

    def test_setup_tunnel_br(self):
        self.tun_br = mock.Mock()
        with mock.patch.object(self.agent.int_br,
                               "add_patch_port",
                               return_value=1) as int_patch_port,\
                mock.patch.object(self.agent.tun_br,
                                  "add_patch_port",
                                  return_value=1) as tun_patch_port,\
                mock.patch.object(self.agent.tun_br, 'bridge_exists',
                                  return_value=False),\
                mock.patch.object(self.agent.tun_br, 'create') as create_tun,\
                mock.patch.object(self.agent.tun_br,
                                  'setup_controllers') as setup_controllers,\
                mock.patch.object(self.agent.tun_br, 'port_exists',
                                  return_value=False),\
                mock.patch.object(self.agent.int_br, 'port_exists',
                                  return_value=False),\
                mock.patch.object(sys, "exit"):
            self.agent.setup_tunnel_br(None)
            self.agent.setup_tunnel_br()
            self.assertTrue(create_tun.called)
            self.assertTrue(setup_controllers.called)
            self.assertTrue(int_patch_port.called)
            self.assertTrue(tun_patch_port.called)

    def test_setup_tunnel_br_ports_exits_drop_flows(self):
        cfg.CONF.set_override('drop_flows_on_start', True, 'AGENT')
        with mock.patch.object(self.agent.tun_br, 'port_exists',
                               return_value=True),\
                mock.patch.object(self.agent, 'tun_br'),\
                mock.patch.object(self.agent.int_br, 'port_exists',
                                  return_value=True),\
                mock.patch.object(self.agent.tun_br, 'setup_controllers'),\
                mock.patch.object(self.agent, 'patch_tun_ofport', new=2),\
                mock.patch.object(self.agent, 'patch_int_ofport', new=2),\
                mock.patch.object(self.agent.tun_br,
                                  'uninstall_flows') as delete,\
                mock.patch.object(self.agent.int_br,
                                  "add_patch_port") as int_patch_port,\
                mock.patch.object(self.agent.tun_br,
                                  "add_patch_port") as tun_patch_port,\
                mock.patch.object(sys, "exit"):
            self.agent.setup_tunnel_br(None)
            self.agent.setup_tunnel_br()
            self.assertFalse(int_patch_port.called)
            self.assertFalse(tun_patch_port.called)
            self.assertTrue(delete.called)

    def test_setup_tunnel_port(self):
        self.agent.tun_br = mock.Mock()
        self.agent.l2_pop = False
        self.agent.udp_vxlan_port = 8472
        self.agent.tun_br_ofports['vxlan'] = {}
        self.agent.local_ip = '2.3.4.5'
        with mock.patch.object(self.agent.tun_br,
                               "add_tunnel_port",
                               return_value='6') as add_tun_port_fn,\
                mock.patch.object(self.agent.tun_br, "add_flow"):
            self.agent._setup_tunnel_port(self.agent.tun_br, 'portname',
                                          '1.2.3.4', 'vxlan')
            self.assertTrue(add_tun_port_fn.called)

    def test_port_unbound(self):
        with mock.patch.object(self.agent, "reclaim_local_vlan") as reclvl_fn:
            self.agent.enable_tunneling = True
            lvm = mock.Mock()
            lvm.network_type = "gre"
            lvm.vif_ports = {"vif1": mock.Mock()}
            self.agent.vlan_manager.mapping["netuid12345"] = lvm
            self.agent.port_unbound("vif1", "netuid12345")
            self.assertTrue(reclvl_fn.called)

            lvm.vif_ports = {}
            self.agent.port_unbound("vif1", "netuid12345")
            self.assertEqual(2, reclvl_fn.call_count)

            lvm.vif_ports = {"vif1": mock.Mock()}
            self.agent.port_unbound("vif3", "netuid12345")
            self.assertEqual(2, reclvl_fn.call_count)

    def _prepare_l2_pop_ofports(self):
        lvm1 = mock.Mock()
        lvm1.network_type = 'gre'
        lvm1.vlan = 'vlan1'
        lvm1.segmentation_id = 'seg1'
        lvm1.tun_ofports = set(['1'])
        lvm2 = mock.Mock()
        lvm2.network_type = 'gre'
        lvm2.vlan = 'vlan2'
        lvm2.segmentation_id = 'seg2'
        lvm2.tun_ofports = set(['1', '2'])
        self.agent.vlan_manager.mapping = {'net1': lvm1, 'net2': lvm2}
        self.agent.tun_br_ofports = {'gre':
                                     {'1.1.1.1': '1', '2.2.2.2': '2'}}
        self.agent.arp_responder_enabled = True

    def test_fdb_ignore_network(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net3': {}}
        with mock.patch.object(self.agent.tun_br, 'add_flow') as add_flow_fn,\
                mock.patch.object(self.agent.tun_br,
                                  'uninstall_flows') as del_flow_fn,\
                mock.patch.object(self.agent,
                                  '_setup_tunnel_port') as add_tun_fn,\
                mock.patch.object(self.agent,
                                  'cleanup_tunnel_port') as clean_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(add_flow_fn.called)
            self.assertFalse(add_tun_fn.called)
            self.agent.fdb_remove(None, fdb_entry)
            self.assertFalse(del_flow_fn.called)
            self.assertFalse(clean_tun_fn.called)

    def test_fdb_ignore_self(self):
        self._prepare_l2_pop_ofports()
        self.agent.local_ip = 'agent_ip'
        fdb_entry = {'net2':
                     {'network_type': 'gre',
                      'segment_id': 'tun2',
                      'ports':
                      {'agent_ip':
                       [l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP1),
                        n_const.FLOODING_ENTRY]}}}
        with mock.patch.object(self.agent.tun_br,
                               "deferred") as defer_fn:
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(defer_fn.called)

            self.agent.fdb_remove(None, fdb_entry)
            self.assertFalse(defer_fn.called)

    def test_fdb_add_flows(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net1':
                     {'network_type': 'gre',
                      'segment_id': 'tun1',
                      'ports':
                      {'2.2.2.2':
                       [l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP1),
                        n_const.FLOODING_ENTRY]}}}

        with mock.patch.object(self.agent, 'tun_br', autospec=True) as tun_br,\
                mock.patch.object(self.agent,
                                  '_setup_tunnel_port',
                                  autospec=True) as add_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(add_tun_fn.called)
            deferred_br_call = mock.call.deferred().__enter__()
            expected_calls = [
                deferred_br_call.install_arp_responder('vlan1', FAKE_IP1,
                                                       FAKE_MAC),
                deferred_br_call.install_unicast_to_tun('vlan1', 'seg1', '2',
                                                        FAKE_MAC),
                deferred_br_call.install_flood_to_tun('vlan1', 'seg1',
                                                      set(['1', '2'])),
            ]
            tun_br.assert_has_calls(expected_calls)

    def test_fdb_del_flows(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net2':
                     {'network_type': 'gre',
                      'segment_id': 'tun2',
                      'ports':
                      {'2.2.2.2':
                       [l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP1),
                        n_const.FLOODING_ENTRY]}}}
        with mock.patch.object(self.agent, 'tun_br', autospec=True) as br_tun:
            self.agent.fdb_remove(None, fdb_entry)
            deferred_br_call = mock.call.deferred().__enter__()
            expected_calls = [
                mock.call.deferred(),
                mock.call.deferred().__enter__(),
                deferred_br_call.delete_arp_responder('vlan2', FAKE_IP1),
                deferred_br_call.delete_unicast_to_tun('vlan2', FAKE_MAC),
                deferred_br_call.install_flood_to_tun('vlan2', 'seg2',
                                                      set(['1'])),
                deferred_br_call.delete_port('gre-02020202'),
                deferred_br_call.cleanup_tunnel_port('2'),
                mock.call.deferred().__exit__(None, None, None),
            ]
            br_tun.assert_has_calls(expected_calls)

    def test_fdb_add_port(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net1':
                     {'network_type': 'gre',
                      'segment_id': 'tun1',
                      'ports': {'1.1.1.1': [l2pop_rpc.PortInfo(FAKE_MAC,
                                                               FAKE_IP1)]}}}
        with mock.patch.object(self.agent, 'tun_br', autospec=True) as tun_br,\
                mock.patch.object(self.agent,
                                  '_setup_tunnel_port') as add_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(add_tun_fn.called)
            fdb_entry['net1']['ports']['10.10.10.10'] = [
                l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP1)]
            self.agent.fdb_add(None, fdb_entry)
            deferred_br = tun_br.deferred().__enter__()
            add_tun_fn.assert_called_with(
                deferred_br, 'gre-0a0a0a0a', '10.10.10.10', 'gre')

    def test_fdb_del_port(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net2':
                     {'network_type': 'gre',
                      'segment_id': 'tun2',
                      'ports': {'2.2.2.2': [n_const.FLOODING_ENTRY]}}}
        with mock.patch.object(self.agent.tun_br, 'deferred') as defer_fn,\
                mock.patch.object(self.agent.tun_br,
                                  'delete_port') as delete_port_fn:
            self.agent.fdb_remove(None, fdb_entry)
            deferred_br = defer_fn().__enter__()
            deferred_br.delete_port.assert_called_once_with('gre-02020202')
            self.assertFalse(delete_port_fn.called)

    def test_fdb_update_chg_ip(self):
        self._prepare_l2_pop_ofports()
        fdb_entries = {'chg_ip':
                       {'net1':
                        {'agent_ip':
                         {'before': [l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP1)],
                          'after': [l2pop_rpc.PortInfo(FAKE_MAC, FAKE_IP2)]}}}}
        with mock.patch.object(self.agent.tun_br, 'deferred') as deferred_fn:
            self.agent.fdb_update(None, fdb_entries)
            deferred_br = deferred_fn().__enter__()
            deferred_br.assert_has_calls([
                mock.call.install_arp_responder('vlan1', FAKE_IP2, FAKE_MAC),
                mock.call.delete_arp_responder('vlan1', FAKE_IP1)
            ])

    def test_del_fdb_flow_idempotency(self):
        lvm = mock.Mock()
        lvm.network_type = 'gre'
        lvm.vlan = 'vlan1'
        lvm.segmentation_id = 'seg1'
        lvm.tun_ofports = set(['1', '2'])
        with mock.patch.object(self.agent.tun_br, 'mod_flow') as mod_flow_fn,\
                mock.patch.object(self.agent.tun_br,
                                  'uninstall_flows') as uninstall_flows_fn:
            self.agent.del_fdb_flow(self.agent.tun_br, n_const.FLOODING_ENTRY,
                                    '1.1.1.1', lvm, '3')
            self.assertFalse(mod_flow_fn.called)
            self.assertFalse(uninstall_flows_fn.called)

    def test_recl_lv_port_to_preserve(self):
        self._prepare_l2_pop_ofports()
        self.agent.l2_pop = True
        self.agent.enable_tunneling = True
        with mock.patch.object(self.agent, 'tun_br', autospec=True) as tun_br:
            self.agent.reclaim_local_vlan('net1')
            self.assertFalse(tun_br.cleanup_tunnel_port.called)

    def test_recl_lv_port_to_remove(self):
        self._prepare_l2_pop_ofports()
        self.agent.l2_pop = True
        self.agent.enable_tunneling = True
        with mock.patch.object(self.agent, 'tun_br', autospec=True) as tun_br:
            self.agent.reclaim_local_vlan('net2')
            tun_br.delete_port.assert_called_once_with('gre-02020202')

    def test_ext_br_recreated(self):
        bridge_mappings = {'physnet0': 'br-ex0',
                           'physnet1': 'br-ex1'}
        ex_br_mocks = [mock.Mock(br_name='br-ex0'),
                       mock.Mock(br_name='br-ex1')]
        phys_bridges = {'physnet0': ex_br_mocks[0],
                        'physnet1': ex_br_mocks[1]},
        bm_mock = mock.Mock()
        with mock.patch(
            'neutron.agent.linux.ovsdb_monitor.get_bridges_monitor',
            return_value=bm_mock),\
                mock.patch.object(
                    self.agent,
                    'check_ovs_status',
                    return_value=constants.OVS_NORMAL),\
                mock.patch.object(
                    self.agent,
                    '_agent_has_updates',
                    side_effect=TypeError('loop exit')),\
                mock.patch.dict(
                    self.agent.bridge_mappings, bridge_mappings, clear=True),\
                mock.patch.dict(
                    self.agent.phys_brs, phys_bridges, clear=True),\
                mock.patch.object(
                    self.agent,
                    'setup_physical_bridges') as setup_physical_bridges:
            bm_mock.bridges_added = ['br-ex0']
            try:
                self.agent.rpc_loop(polling_manager=mock.Mock(),
                                    bridges_monitor=bm_mock)
            except TypeError:
                pass
        setup_physical_bridges.assert_called_once_with(
            {'physnet0': 'br-ex0'})

    def test_daemon_loop_uses_polling_manager(self):
        ex_br_mock = mock.Mock(br_name="br-ex0")
        with mock.patch(
            'neutron.agent.common.polling.get_polling_manager'
        ) as mock_get_pm, mock.patch(
            'neutron.agent.linux.ovsdb_monitor.get_bridges_monitor'
        ) as mock_get_bm, mock.patch.object(
            self.agent, 'rpc_loop'
        ) as mock_loop, mock.patch.dict(
            self.agent.phys_brs, {'physnet0': ex_br_mock}, clear=True):

            self.agent.daemon_loop()
        mock_get_pm.assert_called_with(True,
                                       constants.DEFAULT_OVSDBMON_RESPAWN)
        mock_get_bm.assert_called_once_with(
            ['br-ex0'], constants.DEFAULT_OVSDBMON_RESPAWN)
        mock_loop.assert_called_once_with(
            polling_manager=mock.ANY, bridges_monitor=mock.ANY)

    def test_setup_tunnel_port_invalid_ofport(self):
        remote_ip = '1.2.3.4'
        with mock.patch.object(
            self.agent.tun_br,
            'add_tunnel_port',
            return_value=ovs_lib.INVALID_OFPORT) as add_tunnel_port_fn,\
                mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.local_ip = '1.2.3.4'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', remote_ip, self.agent.local_ip, n_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment,
                self.agent.tunnel_csum, self.agent.tos)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': n_const.TYPE_GRE, 'ip': remote_ip})
            self.assertEqual(0, ofport)

    def test_setup_tunnel_port_invalid_address_mismatch(self):
        remote_ip = '2001:db8::2'
        with mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.local_ip = '1.2.3.4'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            log_error_fn.assert_called_once_with(
                _("IP version mismatch, cannot create tunnel: "
                  "local_ip=%(lip)s remote_ip=%(rip)s"),
                {'lip': self.agent.local_ip, 'rip': remote_ip})
            self.assertEqual(0, ofport)

    def test_setup_tunnel_port_invalid_netaddr_exception(self):
        remote_ip = '2001:db8::2'
        with mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.local_ip = '1.2.3.4.5'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            log_error_fn.assert_called_once_with(
                _("Invalid local or remote IP, cannot create tunnel: "
                  "local_ip=%(lip)s remote_ip=%(rip)s"),
                {'lip': self.agent.local_ip, 'rip': remote_ip})
            self.assertEqual(0, ofport)

    def test_setup_tunnel_port_error_negative_df_disabled(self):
        remote_ip = '1.2.3.4'
        with mock.patch.object(
            self.agent.tun_br,
            'add_tunnel_port',
            return_value=ovs_lib.INVALID_OFPORT) as add_tunnel_port_fn,\
                mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.dont_fragment = False
            self.agent.tunnel_csum = False
            self.agent.local_ip = '2.3.4.5'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', remote_ip, self.agent.local_ip, n_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment,
                self.agent.tunnel_csum, self.agent.tos)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': n_const.TYPE_GRE, 'ip': remote_ip})
            self.assertEqual(0, ofport)

    def test_setup_tunnel_port_error_negative_tunnel_csum(self):
        remote_ip = '1.2.3.4'
        with mock.patch.object(
            self.agent.tun_br,
            'add_tunnel_port',
            return_value=ovs_lib.INVALID_OFPORT) as add_tunnel_port_fn,\
                mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.dont_fragment = True
            self.agent.tunnel_csum = True
            self.agent.local_ip = '2.3.4.5'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', remote_ip, self.agent.local_ip, n_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment,
                self.agent.tunnel_csum, self.agent.tos)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': n_const.TYPE_GRE, 'ip': remote_ip})
            self.assertEqual(0, ofport)

    def test_setup_tunnel_port_error_negative_tos_inherit(self):
        remote_ip = '1.2.3.4'
        with mock.patch.object(
            self.agent.tun_br,
            'add_tunnel_port',
            return_value=ovs_lib.INVALID_OFPORT) as add_tunnel_port_fn,\
                mock.patch.object(self.mod_agent.LOG, 'error') as log_error_fn:
            self.agent.tos = 'inherit'
            self.agent.local_ip = '2.3.4.5'
            ofport = self.agent._setup_tunnel_port(
                self.agent.tun_br, 'gre-1', remote_ip, n_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', remote_ip, self.agent.local_ip, n_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment,
                self.agent.tunnel_csum, self.agent.tos)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': n_const.TYPE_GRE, 'ip': remote_ip})
            self.assertEqual(0, ofport)

    def test_tunnel_sync_with_ml2_plugin(self):
        fake_tunnel_details = {'tunnels': [{'ip_address': '100.101.31.15'}]}
        with mock.patch.object(self.agent.plugin_rpc,
                               'tunnel_sync',
                               return_value=fake_tunnel_details),\
                mock.patch.object(
                    self.agent,
                    '_setup_tunnel_port') as _setup_tunnel_port_fn,\
                mock.patch.object(self.agent,
                                  'cleanup_stale_flows') as cleanup:
            self.agent.tunnel_types = ['vxlan']
            self.agent.tunnel_sync()
            expected_calls = [mock.call(self.agent.tun_br, 'vxlan-64651f0f',
                                        '100.101.31.15', 'vxlan')]
            _setup_tunnel_port_fn.assert_has_calls(expected_calls)
            self.assertEqual([], cleanup.mock_calls)

    def test_tunnel_sync_invalid_ip_address(self):
        fake_tunnel_details = {'tunnels': [{'ip_address': '300.300.300.300'},
                                           {'ip_address': '100.100.100.100'}]}
        with mock.patch.object(self.agent.plugin_rpc,
                               'tunnel_sync',
                               return_value=fake_tunnel_details),\
                mock.patch.object(
                    self.agent,
                    '_setup_tunnel_port') as _setup_tunnel_port_fn,\
                mock.patch.object(self.agent,
                                  'cleanup_stale_flows') as cleanup:
            self.agent.tunnel_types = ['vxlan']
            self.agent.tunnel_sync()
            _setup_tunnel_port_fn.assert_called_once_with(self.agent.tun_br,
                                                          'vxlan-64646464',
                                                          '100.100.100.100',
                                                          'vxlan')
            self.assertEqual([], cleanup.mock_calls)

    def test_tunnel_sync_setup_tunnel_flood_flow_once(self):
        fake_tunnel_details = {'tunnels': [{'ip_address': '200.200.200.200'},
                                           {'ip_address': '100.100.100.100'}]}
        with mock.patch.object(self.agent.plugin_rpc,
                               'tunnel_sync',
                               return_value=fake_tunnel_details),\
                mock.patch.object(
                    self.agent,
                    '_setup_tunnel_port') as _setup_tunnel_port_fn,\
                mock.patch.object(
                    self.agent,
                    '_setup_tunnel_flood_flow') as _setup_tunnel_flood_flow:
            self.agent.tunnel_types = ['vxlan']
            self.agent.tunnel_sync()
            expected_calls = [mock.call(self.agent.tun_br, 'vxlan-c8c8c8c8',
                                        '200.200.200.200', 'vxlan'),
                              mock.call(self.agent.tun_br, 'vxlan-64646464',
                                        '100.100.100.100', 'vxlan')]
            _setup_tunnel_port_fn.assert_has_calls(expected_calls)
            _setup_tunnel_flood_flow.assert_called_once_with(self.agent.tun_br,
                                                             'vxlan')

    def test_tunnel_update(self):
        kwargs = {'tunnel_ip': '10.10.10.10',
                  'tunnel_type': 'gre'}
        self.agent._setup_tunnel_port = mock.Mock()
        self.agent.enable_tunneling = True
        self.agent.tunnel_types = ['gre']
        self.agent.l2_pop = False
        self.agent.tunnel_update(context=None, **kwargs)
        expected_calls = [
            mock.call(self.agent.tun_br, 'gre-0a0a0a0a', '10.10.10.10', 'gre')]
        self.agent._setup_tunnel_port.assert_has_calls(expected_calls)

    def test_tunnel_delete(self):
        kwargs = {'tunnel_ip': '10.10.10.10',
                  'tunnel_type': 'gre'}
        self.agent.enable_tunneling = True
        self.agent.tunnel_types = ['gre']
        self.agent.tun_br_ofports = {'gre': {'10.10.10.10': '1'}}
        with mock.patch.object(
            self.agent, 'cleanup_tunnel_port'
        ) as clean_tun_fn:
            self.agent.tunnel_delete(context=None, **kwargs)
            self.assertTrue(clean_tun_fn.called)

    def test_reset_tunnel_ofports(self):
        tunnel_handles = self.agent.tun_br_ofports
        self.agent.tun_br_ofports = {'gre': {'10.10.10.10': '1'}}
        self.agent._reset_tunnel_ofports()
        self.assertEqual(self.agent.tun_br_ofports, tunnel_handles)

    def _test_ovs_status(self, *args):
        reply2 = {'current': set(['tap0']),
                  'added': set(['tap2']),
                  'removed': set([])}

        reply3 = {'current': set(['tap2']),
                  'added': set([]),
                  'removed': set(['tap0'])}

        reply_ancillary = {'current': set([]),
                           'added': set([]),
                           'removed': set([])}

        self.agent.enable_tunneling = True

        with mock.patch.object(async_process.AsyncProcess, "_spawn"),\
                mock.patch.object(async_process.AsyncProcess, "start"),\
                mock.patch.object(async_process.AsyncProcess,
                                  "is_active", return_value=True),\
                mock.patch.object(async_process.AsyncProcess, "stop"),\
                mock.patch.object(log.KeywordArgumentAdapter,
                                  'exception') as log_exception,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'process_ports_events') as process_p_events,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'process_network_ports') as process_network_ports,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'check_ovs_status') as check_ovs_status,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'setup_integration_br') as setup_int_br,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'setup_physical_bridges') as setup_phys_br,\
                mock.patch.object(time, 'sleep'),\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'update_stale_ofport_rules') as update_stale, \
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'cleanup_stale_flows') as cleanup, \
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'setup_tunnel_br') as setup_tunnel_br,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'setup_tunnel_br_flows') as setup_tunnel_br_flows,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    '_reset_tunnel_ofports') as reset_tunnel_ofports,\
                mock.patch.object(self.agent.state_rpc,
                                  'report_state') as report_st:
            log_exception.side_effect = Exception(
                'Fake exception to get out of the loop')
            devices_not_ready = set()
            process_p_events.side_effect = [(reply2, reply_ancillary,
                                             devices_not_ready),
                                            (reply3, reply_ancillary,
                                             devices_not_ready)]
            failed_devices = {'added': set(), 'removed': set()}
            failed_ancillary_devices = {'added': set(), 'removed': set()}
            process_network_ports.side_effect = [
                failed_devices,
                Exception('Fake exception to get out of the loop')]
            check_ovs_status.side_effect = args

            if self.agent.enable_tunneling:
                self.agent.agent_state.pop("start_flag")

            try:
                self.agent.daemon_loop()
            except Exception:
                pass

            process_p_events.assert_has_calls([
                mock.call({'removed': [], 'added': []}, set(), set(), set(),
                          failed_devices, failed_ancillary_devices,
                          set()),
                mock.call({'removed': [], 'added': []}, set(['tap0']), set(),
                          set(), failed_devices, failed_ancillary_devices,
                          set())
            ])

            process_network_ports.assert_has_calls([
                mock.call(reply2, False),
                mock.call(reply3, True)
            ])
            cleanup.assert_called_once_with()
            self.assertTrue(update_stale.called)
            # Verify the OVS restart we triggered in the loop
            # re-setup the bridges
            setup_int_br.assert_has_calls([mock.call()])
            setup_phys_br.assert_has_calls([mock.call({})])
            # Ensure that tunnel handles are reset and bridge
            # and flows reconfigured.
            self.assertTrue(reset_tunnel_ofports.called)
            self.assertTrue(setup_tunnel_br_flows.called)
            self.assertTrue(setup_tunnel_br.called)
            if self.agent.enable_tunneling:
                self.agent.agent_state['start_flag'] = True
                report_st.assert_called_once_with(
                    self.agent.context, self.agent.agent_state, True)

    def test_ovs_status(self):
        self._test_ovs_status(constants.OVS_NORMAL,
                              constants.OVS_DEAD,
                              constants.OVS_RESTARTED)
        # OVS will not DEAD in some exception, like DBConnectionError.
        self._test_ovs_status(constants.OVS_NORMAL,
                              constants.OVS_RESTARTED)

    def test_rpc_loop_fail_to_process_network_ports_keep_flows(self):
        with mock.patch.object(async_process.AsyncProcess, "_spawn"),\
                mock.patch.object(async_process.AsyncProcess, "start"),\
                mock.patch.object(async_process.AsyncProcess,
                                  "is_active", return_value=True),\
                mock.patch.object(async_process.AsyncProcess, "stop"),\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'process_network_ports') as process_network_ports,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'check_ovs_status') as check_ovs_status,\
                mock.patch.object(time, 'sleep'),\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'update_stale_ofport_rules') as update_stale, \
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'cleanup_stale_flows') as cleanup,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    '_check_and_handle_signal') as check_and_handle_signal:
            process_network_ports.side_effect = Exception("Trigger resync")
            check_ovs_status.return_value = constants.OVS_NORMAL
            check_and_handle_signal.side_effect = [True, False]
            self.agent.daemon_loop()
            self.assertTrue(update_stale.called)
            self.assertFalse(cleanup.called)

    def test_set_rpc_timeout(self):
        with mock.patch.object(
            n_rpc.BackingOffClient, 'set_max_timeout') as smt:
            self.agent._handle_sigterm(None, None)
            for rpc_client in (self.agent.plugin_rpc.client,
                               self.agent.sg_plugin_rpc.client,
                               self.agent.dvr_plugin_rpc.client,
                               self.agent.state_rpc.client):
                smt.assert_called_with(10)

    def test_set_rpc_timeout_no_value(self):
        self.agent.quitting_rpc_timeout = None
        with mock.patch.object(self.agent, 'set_rpc_timeout') as mock_set_rpc:
            self.agent._handle_sigterm(None, None)
        self.assertFalse(mock_set_rpc.called)

    def test_arp_spoofing_network_port(self):
        int_br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(
            int_br, FakeVif(),
            {'device_owner': n_const.DEVICE_OWNER_ROUTER_INTF})
        self.assertTrue(int_br.delete_arp_spoofing_protection.called)
        self.assertFalse(int_br.install_arp_spoofing_protection.called)

    def test_arp_spoofing_port_security_disabled(self):
        int_br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(
            int_br, FakeVif(), {'port_security_enabled': False})
        self.assertTrue(int_br.delete_arp_spoofing_protection.called)
        self.assertFalse(int_br.install_arp_spoofing_protection.called)

    def test_arp_spoofing_basic_rule_setup(self):
        vif = FakeVif()
        fake_details = {'fixed_ips': [], 'device_owner': 'nobody'}
        self.agent.prevent_arp_spoofing = True
        int_br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(int_br, vif, fake_details)
        self.assertEqual(
            [mock.call(port=vif.ofport)],
            int_br.delete_arp_spoofing_allow_rules.mock_calls)
        self.assertEqual(
            [mock.call(ip_addresses=set(), port=vif.ofport)],
            int_br.install_arp_spoofing_protection.mock_calls)

    def test_arp_spoofing_basic_rule_setup_fixed_ipv6(self):
        vif = FakeVif()
        fake_details = {'fixed_ips': [{'ip_address': 'fdf8:f53b:82e4::1'}],
                        'device_owner': 'nobody'}
        self.agent.prevent_arp_spoofing = True
        br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(br, vif, fake_details)
        self.assertEqual(
            [mock.call(port=vif.ofport)],
            br.delete_arp_spoofing_allow_rules.mock_calls)
        self.assertTrue(br.install_icmpv6_na_spoofing_protection.called)

    def test_arp_spoofing_fixed_and_allowed_addresses(self):
        vif = FakeVif()
        fake_details = {
            'device_owner': 'nobody',
            'fixed_ips': [{'ip_address': '192.168.44.100'},
                          {'ip_address': '192.168.44.101'}],
            'allowed_address_pairs': [{'ip_address': '192.168.44.102/32'},
                                      {'ip_address': '192.168.44.103/32'}]
        }
        self.agent.prevent_arp_spoofing = True
        int_br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(int_br, vif, fake_details)
        # make sure all addresses are allowed
        addresses = {'192.168.44.100', '192.168.44.101', '192.168.44.102/32',
                     '192.168.44.103/32'}
        self.assertEqual(
            [mock.call(port=vif.ofport, ip_addresses=addresses)],
            int_br.install_arp_spoofing_protection.mock_calls)

    def test_arp_spoofing_fixed_and_allowed_addresses_ipv6(self):
        vif = FakeVif()
        fake_details = {
            'device_owner': 'nobody',
            'fixed_ips': [{'ip_address': '2001:db8::1'},
                          {'ip_address': '2001:db8::2'}],
            'allowed_address_pairs': [{'ip_address': '2001:db8::200',
                                       'mac_address': 'aa:22:33:44:55:66'}]
        }
        self.agent.prevent_arp_spoofing = True
        int_br = mock.create_autospec(self.agent.int_br)
        self.agent.setup_arp_spoofing_protection(int_br, vif, fake_details)
        # make sure all addresses are allowed including ipv6 LLAs
        addresses = {'2001:db8::1', '2001:db8::2', '2001:db8::200',
                     'fe80::a822:33ff:fe44:5566', 'fe80::a8bb:ccff:fe11:2233'}
        self.assertEqual(
            [mock.call(port=vif.ofport, ip_addresses=addresses)],
            int_br.install_icmpv6_na_spoofing_protection.mock_calls)

    def test__get_ofport_moves(self):
        previous = {'port1': 1, 'port2': 2}
        current = {'port1': 5, 'port2': 2}
        # we expect it to tell us port1 moved
        expected = ['port1']
        self.assertEqual(expected,
                         self.agent._get_ofport_moves(current, previous))

    def test_update_stale_ofport_rules_clears_old(self):
        self.agent.prevent_arp_spoofing = True
        self.agent.vifname_to_ofport_map = {'port1': 1, 'port2': 2}
        self.agent.int_br = mock.Mock()
        # simulate port1 was removed
        newmap = {'port2': 2}
        self.agent.int_br.get_vif_port_to_ofport_map.return_value = newmap
        self.agent.update_stale_ofport_rules()
        # rules matching port 1 should have been deleted
        self.assertEqual(
            [mock.call(port=1)],
            self.agent.int_br.delete_arp_spoofing_protection.mock_calls)
        # make sure the state was updated with the new map
        self.assertEqual(newmap, self.agent.vifname_to_ofport_map)

    def test_update_stale_ofport_rules_treats_moved(self):
        self.agent.prevent_arp_spoofing = True
        self.agent.vifname_to_ofport_map = {'port1': 1, 'port2': 2}
        self.agent.treat_devices_added_or_updated = mock.Mock()
        self.agent.int_br = mock.Mock()
        # simulate port1 was moved
        newmap = {'port2': 2, 'port1': 90}
        self.agent.int_br.get_vif_port_to_ofport_map.return_value = newmap
        ofport_changed_ports = self.agent.update_stale_ofport_rules()
        self.assertEqual(['port1'], ofport_changed_ports)

    def test_update_stale_ofport_rules_removes_drop_flow(self):
        self.agent.prevent_arp_spoofing = False
        self.agent.vifname_to_ofport_map = {'port1': 1, 'port2': 2}
        self.agent.int_br = mock.Mock()
        # simulate port1 was removed
        newmap = {'port2': 2}
        self.agent.int_br.get_vif_port_to_ofport_map.return_value = newmap
        self.agent.update_stale_ofport_rules()
        # drop flow rule matching port 1 should have been deleted
        ofport_changed_ports = self.agent.update_stale_ofport_rules()
        expected = [
            mock.call(in_port=1)
        ]
        self.assertEqual(expected,
                         self.agent.int_br.uninstall_flows.mock_calls)
        self.assertEqual(newmap, self.agent.vifname_to_ofport_map)
        self.assertFalse(
            self.agent.int_br.delete_arp_spoofing_protection.called)
        self.assertEqual([], ofport_changed_ports)

    def test__setup_tunnel_port_while_new_mapping_is_added(self):
        """
        Test that _setup_tunnel_port doesn't fail if new vlan mapping is
        added in a different coroutine while iterating over existing mappings.
        See bug 1449944 for more info.
        """

        def add_new_vlan_mapping(*args, **kwargs):
            self.agent.vlan_manager.add('bar', 1, 2, 3, 4)
        bridge = mock.Mock()
        tunnel_type = 'vxlan'
        self.agent.tun_br_ofports = {tunnel_type: dict()}
        self.agent.l2_pop = False
        self.agent.vlan_manager.add('foo', 4, tunnel_type, 2, 1)
        self.agent.local_ip = '2.3.4.5'
        bridge.install_flood_to_tun.side_effect = add_new_vlan_mapping
        self.agent._setup_tunnel_port(bridge, 1, '1.2.3.4',
                                      tunnel_type=tunnel_type)
        self.agent._setup_tunnel_flood_flow(bridge, tunnel_type)
        self.assertIn('bar', self.agent.vlan_manager)

    def test_setup_entry_for_arp_reply_ignores_ipv6_addresses(self):
        self.agent.arp_responder_enabled = True
        ip = '2001:db8::1'
        br = mock.Mock()
        self.agent.setup_entry_for_arp_reply(
            br, 'add', mock.Mock(), mock.Mock(), ip)
        self.assertFalse(br.install_arp_responder.called)

    def test__check_bridge_datapath_id(self):
        datapath_id = u'0000622486fa3f42'
        datapath_ids_set = set()
        for i in range(5):
            dpid = format((i << 48) + int(datapath_id, 16), '0x').zfill(16)
            bridge = mock.Mock()
            bridge.br_name = 'bridge_%s' % i
            bridge.get_datapath_id = mock.Mock(return_value=datapath_id)
            self.agent._check_bridge_datapath_id(bridge, datapath_ids_set)
            self.assertEqual(i + 1, len(datapath_ids_set))
            self.assertIn(dpid, datapath_ids_set)
            if i == 0:
                bridge.set_datapath_id.assert_not_called()
            else:
                bridge.set_datapath_id.assert_called_once_with(dpid)


class TestOvsNeutronAgentOFCtl(TestOvsNeutronAgent,
                               ovs_test_base.OVSOFCtlTestBase):
    def test_cleanup_stale_flows(self):
        with mock.patch.object(self.agent.int_br,
                              'dump_flows_all_tables') as dump_flows,\
                mock.patch.object(self.agent.int_br,
                                  'delete_flows') as del_flow:
            self.agent.int_br.set_agent_uuid_stamp(1234)
            dump_flows.return_value = [
                'cookie=0x4d2, duration=50.156s, table=0,actions=drop',
                'cookie=0x4321, duration=54.143s, table=2, priority=0',
                'cookie=0x2345, duration=50.125s, table=2, priority=0',
                'cookie=0x4d2, duration=52.112s, table=3, actions=drop',
            ]
            self.agent.iter_num = 3
            self.agent.cleanup_stale_flows()
            expected = [
                mock.call(cookie='0x4321/-1', table='2'),
                mock.call(cookie='0x2345/-1', table='2'),
            ]
            self.assertEqual(expected, del_flow.mock_calls)


class TestOvsNeutronAgentRyu(TestOvsNeutronAgent,
                             ovs_test_base.OVSRyuTestBase):
    def test_cleanup_stale_flows(self):
        uint64_max = (1 << 64) - 1
        with mock.patch.object(self.agent.int_br,
                               'dump_flows') as dump_flows,\
                mock.patch.object(self.agent.int_br,
                                  'uninstall_flows') as uninstall_flows:
            self.agent.int_br.set_agent_uuid_stamp(1234)
            fake_flows = [
                # mock ryu.ofproto.ofproto_v1_3_parser.OFPFlowStats
                mock.Mock(cookie=1234, table_id=0),
                mock.Mock(cookie=17185, table_id=2),
                mock.Mock(cookie=9029, table_id=2),
                mock.Mock(cookie=1234, table_id=3),
            ]
            dump_flows.return_value = fake_flows
            self.agent.iter_num = 3
            self.agent.cleanup_stale_flows()

            dump_flows_expected = [
                mock.call(tid) for tid in constants.INT_BR_ALL_TABLES]
            dump_flows.assert_has_calls(dump_flows_expected)

            expected = [mock.call(cookie=17185,
                                  cookie_mask=uint64_max),
                        mock.call(cookie=9029,
                                  cookie_mask=uint64_max)]
            uninstall_flows.assert_has_calls(expected, any_order=True)
            self.assertEqual(len(constants.INT_BR_ALL_TABLES) * len(expected),
                             len(uninstall_flows.mock_calls))


class AncillaryBridgesTest(object):

    def setUp(self):
        super(AncillaryBridgesTest, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        mock.patch(PULLAPI).start()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        mock.patch('neutron.agent.common.ovs_lib.BaseOVS.config',
                   new_callable=mock.PropertyMock,
                   return_value={}).start()

    def _test_ancillary_bridges(self, bridges, ancillary):
        device_ids = ancillary[:]

        def pullup_side_effect(*args, **kwargs):
            # Check that the device_id exists, if it does return it
            # if it does not return None
            try:
                device_ids.remove(args[0])
                return args[0]
            except Exception:
                return None

        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'),\
                mock.patch('neutron.agent.linux.ip_lib.get_device_mac',
                           return_value='00:00:00:00:00:01'),\
                mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges',
                           return_value=bridges),\
                mock.patch('neutron.agent.common.ovs_lib.BaseOVS.'
                           'get_bridge_external_bridge_id',
                           side_effect=pullup_side_effect),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.OVSBridge.'
                    'get_ports_attributes',
                    return_value=[]),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.OVSBridge.' 'get_vif_ports',
                    return_value=[]):
            ext_manager = mock.Mock()
            self.agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                        ext_manager, cfg.CONF)
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

    def mock_scan_ancillary_ports(self, vif_port_set=None,
                                  registered_ports=None, sync=False):
        bridges = ['br-int', 'br-ex']
        ancillary = ['br-ex']

        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'), \
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  '_restore_local_vlan_map'), \
                mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges',
                           return_value=bridges), \
                mock.patch('neutron.agent.common.ovs_lib.BaseOVS.'
                           'get_bridge_external_bridge_id',
                           side_effect=ancillary), \
                mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                           'get_vif_port_set',
                           return_value=vif_port_set):
            ext_manager = mock.Mock()
            self.agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                        ext_manager, cfg.CONF)
            return self.agent.scan_ancillary_ports(registered_ports, sync)

    def test_scan_ancillary_ports_returns_cur_only_for_unchanged_ports(self):
        vif_port_set = set([1, 2])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set,
                        added=set(),
                        removed=set())
        actual = self.mock_scan_ancillary_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_scan_ancillary_ports_returns_port_changes(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]), removed=set([2]))
        actual = self.mock_scan_ancillary_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_scan_ancillary_ports_returns_port_changes_with_sync(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=vif_port_set,
                        removed=set([2]))
        actual = self.mock_scan_ancillary_ports(vif_port_set, registered_ports,
                                                sync=True)
        self.assertEqual(expected, actual)


class AncillaryBridgesTestOFCtl(AncillaryBridgesTest,
                                ovs_test_base.OVSOFCtlTestBase):
    pass


class AncillaryBridgesTestRyu(AncillaryBridgesTest,
                              ovs_test_base.OVSRyuTestBase):
    pass


class TestOvsDvrNeutronAgent(object):

    def setUp(self):
        super(TestOvsDvrNeutronAgent, self).setUp()
        mock.patch(PULLAPI).start()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')

        mock.patch('neutron.agent.common.ovs_lib.BaseOVS.config',
                   new_callable=mock.PropertyMock,
                   return_value={}).start()
        mock.patch('neutron.agent.ovsdb.impl_idl._connection').start()
        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'setup_integration_br'),\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'setup_ancillary_bridges',
                                  return_value=[]),\
                mock.patch('neutron.agent.linux.ip_lib.get_device_mac',
                           return_value='00:00:00:00:00:01'),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.BaseOVS.get_bridges'),\
                mock.patch('oslo_service.loopingcall.'
                           'FixedIntervalLoopingCall',
                           new=MockFixedIntervalLoopingCall),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.OVSBridge.'
                    'get_ports_attributes',
                    return_value=[]),\
                mock.patch(
                    'neutron.agent.common.ovs_lib.OVSBridge.' 'get_vif_ports',
                    return_value=[]):
            ext_manager = mock.Mock()
            self.agent = self.mod_agent.OVSNeutronAgent(self._bridge_classes(),
                                                       ext_manager, cfg.CONF)
            self.agent.tun_br = self.br_tun_cls(br_name='br-tun')
        self.agent.sg_agent = mock.Mock()

    def _setup_for_dvr_test(self):
        self._port = mock.Mock()
        self._port.ofport = 10
        self._port.vif_id = "1234-5678-90"
        self._physical_network = 'physeth1'
        self._old_local_vlan = None
        self._segmentation_id = 2001
        self.agent.enable_distributed_routing = True
        self.agent.enable_tunneling = True
        self.agent.patch_tun_ofport = 1
        self.agent.patch_int_ofport = 2
        self.agent.dvr_agent.local_ports = {}
        self.agent.vlan_manager = self.useFixture(
            test_vlanmanager.LocalVlanManagerFixture()).manager
        self.agent.dvr_agent.enable_distributed_routing = True
        self.agent.dvr_agent.enable_tunneling = True
        self.agent.dvr_agent.patch_tun_ofport = 1
        self.agent.dvr_agent.patch_int_ofport = 2
        self.agent.dvr_agent.tun_br = mock.Mock()
        self.agent.dvr_agent.phys_brs[self._physical_network] = mock.Mock()
        self.agent.dvr_agent.bridge_mappings = {self._physical_network:
                                                'br-eth1'}
        self.agent.dvr_agent.int_ofports[self._physical_network] = 30
        self.agent.dvr_agent.phys_ofports[self._physical_network] = 40
        self.agent.dvr_agent.local_dvr_map = {}
        self.agent.dvr_agent.registered_dvr_macs = set()
        self.agent.dvr_agent.dvr_mac_address = 'aa:22:33:44:55:66'
        self._net_uuid = 'my-net-uuid'
        self._fixed_ips = [{'subnet_id': 'my-subnet-uuid',
                            'ip_address': '1.1.1.1'}]
        self._compute_port = mock.Mock()
        self._compute_port.ofport = 20
        self._compute_port.vif_id = "1234-5678-91"
        self._compute_fixed_ips = [{'subnet_id': 'my-subnet-uuid',
                                    'ip_address': '1.1.1.3'}]

    @staticmethod
    def _expected_port_bound(port, lvid, is_dvr=True):
        resp = [
            mock.call.db_get_val('Port', port.port_name, 'other_config'),
            mock.call.set_db_attribute('Port', port.port_name, 'other_config',
                                       mock.ANY),
        ]
        if is_dvr:
            resp = [mock.call.get_vifs_by_ids([])] + resp
        return resp

    def _expected_install_dvr_process(self, lvid, port, ip_version,
                                      gateway_ip):
        if ip_version == 4:
            ipvx_calls = [
                mock.call.install_dvr_process_ipv4(
                    vlan_tag=lvid,
                    gateway_ip=gateway_ip),
            ]
        else:
            ipvx_calls = [
                mock.call.install_dvr_process_ipv6(
                    vlan_tag=lvid,
                    gateway_mac=port.vif_mac),
            ]
        return ipvx_calls + [
            mock.call.install_dvr_process(
                vlan_tag=lvid,
                dvr_mac_address=self.agent.dvr_agent.dvr_mac_address,
                vif_mac=port.vif_mac,
            ),
        ]

    def _test_port_bound_for_dvr_on_vlan_network(self, device_owner,
                                                 ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.10'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        self._port.vif_mac = 'aa:bb:cc:11:22:33'
        gateway_mac = 'aa:bb:cc:66:66:66'
        self._compute_port.vif_mac = '77:88:99:00:11:22'
        physical_network = self._physical_network
        segmentation_id = self._segmentation_id
        network_type = n_const.TYPE_VLAN
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        phys_br = mock.create_autospec(self.br_phys_cls('br-phys'))
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': gateway_ip,
                                             'cidr': cidr,
                                             'ip_version': ip_version,
                                             'gateway_mac': gateway_mac}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.phys_brs,
                                {physical_network: phys_br}),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.dvr_agent.phys_brs,
                                {physical_network: phys_br}):
            self.agent.port_bound(
                self._port, self._net_uuid, network_type,
                physical_network, segmentation_id, self._fixed_ips,
                n_const.DEVICE_OWNER_DVR_INTERFACE, False)
            phy_ofp = self.agent.dvr_agent.phys_ofports[physical_network]
            int_ofp = self.agent.dvr_agent.int_ofports[physical_network]
            lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
            expected_on_phys_br = [
                mock.call.provision_local_vlan(
                    port=phy_ofp,
                    lvid=lvid,
                    segmentation_id=segmentation_id,
                    distributed=True,
                ),
            ] + self._expected_install_dvr_process(
                port=self._port,
                lvid=lvid,
                ip_version=ip_version,
                gateway_ip=self._fixed_ips[0]['ip_address'])
            expected_on_int_br = [
                mock.call.provision_local_vlan(
                    port=int_ofp,
                    lvid=lvid,
                    segmentation_id=segmentation_id,
                ),
            ] + self._expected_port_bound(self._port, lvid)
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual([], tun_br.mock_calls)
            self.assertEqual(expected_on_phys_br, phys_br.mock_calls)
            int_br.reset_mock()
            tun_br.reset_mock()
            phys_br.reset_mock()
            self.agent.port_bound(self._compute_port, self._net_uuid,
                                  network_type, physical_network,
                                  segmentation_id,
                                  self._compute_fixed_ips,
                                  device_owner, False)
            expected_on_int_br = [
                mock.call.install_dvr_to_src_mac(
                    network_type=network_type,
                    gateway_mac=gateway_mac,
                    dst_mac=self._compute_port.vif_mac,
                    dst_port=self._compute_port.ofport,
                    vlan_tag=segmentation_id,
                ),
            ] + self._expected_port_bound(self._compute_port, lvid, False)
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertFalse([], tun_br.mock_calls)
            self.assertFalse([], phys_br.mock_calls)

    def _test_port_bound_for_dvr_on_vxlan_network(self, device_owner,
                                                  ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        network_type = n_const.TYPE_VXLAN
        self._port.vif_mac = gateway_mac = 'aa:bb:cc:11:22:33'
        self._compute_port.vif_mac = '77:88:99:00:11:22'
        physical_network = self._physical_network
        segmentation_id = self._segmentation_id
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        phys_br = mock.create_autospec(self.br_phys_cls('br-phys'))
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': gateway_ip,
                                             'cidr': cidr,
                                             'ip_version': ip_version,
                                             'gateway_mac': gateway_mac}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.phys_brs,
                                {physical_network: phys_br}),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.dvr_agent.phys_brs,
                                {physical_network: phys_br}):
            self.agent.port_bound(
                self._port, self._net_uuid, network_type,
                physical_network, segmentation_id, self._fixed_ips,
                n_const.DEVICE_OWNER_DVR_INTERFACE, False)
            lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
            expected_on_int_br = self._expected_port_bound(
                self._port, lvid)
            expected_on_tun_br = [
                mock.call.provision_local_vlan(
                    network_type=network_type,
                    segmentation_id=segmentation_id,
                    lvid=lvid,
                    distributed=True),
            ] + self._expected_install_dvr_process(
                port=self._port,
                lvid=lvid,
                ip_version=ip_version,
                gateway_ip=gateway_ip)
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)
            self.assertEqual([], phys_br.mock_calls)
            int_br.reset_mock()
            tun_br.reset_mock()
            phys_br.reset_mock()
            self.agent.port_bound(self._compute_port, self._net_uuid,
                                  network_type, physical_network,
                                  segmentation_id,
                                  self._compute_fixed_ips,
                                  device_owner, False)
            expected_on_int_br = [
                mock.call.install_dvr_to_src_mac(
                    network_type=network_type,
                    gateway_mac=gateway_mac,
                    dst_mac=self._compute_port.vif_mac,
                    dst_port=self._compute_port.ofport,
                    vlan_tag=lvid,
                ),
            ] + self._expected_port_bound(self._compute_port, lvid, False)
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual([], tun_br.mock_calls)
            self.assertEqual([], phys_br.mock_calls)

    def test_port_bound_for_dvr_with_compute_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=DEVICE_OWNER_COMPUTE)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=DEVICE_OWNER_COMPUTE, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=DEVICE_OWNER_COMPUTE)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=DEVICE_OWNER_COMPUTE, ip_version=6)

    def test_port_bound_for_dvr_with_lbaas_vip_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)

    def test_port_bound_for_dvr_with_lbaasv2_vip_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2, ip_version=6)

    def test_port_bound_for_dvr_with_dhcp_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)

    def test_port_bound_for_dvr_with_csnat_ports(self):
        self._setup_for_dvr_test()
        int_br, tun_br = self._port_bound_for_dvr_with_csnat_ports()
        lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
        expected_on_int_br = [
            mock.call.install_dvr_to_src_mac(
                network_type='vxlan',
                gateway_mac='aa:bb:cc:11:22:33',
                dst_mac=self._port.vif_mac,
                dst_port=self._port.ofport,
                vlan_tag=lvid,
            ),
        ] + self._expected_port_bound(self._port, lvid, is_dvr=False)
        self.assertEqual(expected_on_int_br, int_br.mock_calls)
        expected_on_tun_br = [
            mock.call.provision_local_vlan(
                network_type='vxlan',
                lvid=lvid,
                segmentation_id=None,
                distributed=True,
            ),
        ]
        self.assertEqual(expected_on_tun_br, tun_br.mock_calls)

    def test_port_bound_for_dvr_with_csnat_port_without_passing_fixed_ip(self):
        self._setup_for_dvr_test()
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr') as mock_getsub,\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            self.agent.port_bound(
                self._port, self._net_uuid, 'vxlan',
                None, None, self._fixed_ips,
                n_const.DEVICE_OWNER_ROUTER_SNAT,
                False)
            mock_getsub.assert_called_with(
                self.agent.context, mock.ANY, fixed_ips=None)

    def test_port_bound_for_dvr_with_csnat_ports_ofport_change(self):
        self._setup_for_dvr_test()
        self._port_bound_for_dvr_with_csnat_ports()
        # simulate a replug
        self._port.ofport = 12
        int_br, tun_br = self._port_bound_for_dvr_with_csnat_ports()
        lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
        expected_on_int_br = [
            mock.call.delete_dvr_to_src_mac(
                network_type='vxlan',
                dst_mac=self._port.vif_mac,
                vlan_tag=lvid,
            ),
            mock.call.install_dvr_to_src_mac(
                network_type='vxlan',
                gateway_mac='aa:bb:cc:11:22:33',
                dst_mac=self._port.vif_mac,
                dst_port=self._port.ofport,
                vlan_tag=lvid,
            ),
        ] + self._expected_port_bound(self._port, lvid, is_dvr=False)
        self.assertEqual(expected_on_int_br, int_br.mock_calls)
        # a local vlan was already provisioned so there should be no new
        # calls to tunbr
        self.assertEqual([], tun_br.mock_calls)
        # make sure ofport was updated
        self.assertEqual(12,
            self.agent.dvr_agent.local_ports[self._port.vif_id].ofport)

    def _port_bound_for_dvr_with_csnat_ports(self):
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': '1.1.1.1',
                               'cidr': '1.1.1.0/24',
                               'ip_version': 4,
                               'gateway_mac': 'aa:bb:cc:11:22:33'}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            self.agent.port_bound(
                self._port, self._net_uuid, 'vxlan',
                None, None, self._fixed_ips,
                n_const.DEVICE_OWNER_ROUTER_SNAT,
                False)
        return int_br, tun_br

    def test_port_bound_for_dvr_with_csnat_ports_without_subnet(self):
        self._setup_for_dvr_test()
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)

        # get_subnet_for_dvr RPC returns {} on error
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={}),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            self.agent.port_bound(
                self._port, self._net_uuid, 'vxlan',
                None, None, self._fixed_ips,
                n_const.DEVICE_OWNER_ROUTER_SNAT,
                False)
            self.assertFalse(int_br.install_dvr_to_src_mac.called)

    def test_treat_devices_removed_for_dvr_interface(self):
        self._test_treat_devices_removed_for_dvr_interface()
        self._test_treat_devices_removed_for_dvr_interface(ip_version=6)
        self._test_treat_devices_removed_for_dvr_interface(network_type='vlan')
        self._test_treat_devices_removed_for_dvr_interface(ip_version=6,
                                                           network_type='vlan')

    def _test_treat_devices_removed_for_dvr_interface(
            self, ip_version=4, network_type='vxlan'):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        gateway_mac = 'aa:bb:cc:11:22:33'
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': gateway_ip,
                               'cidr': cidr,
                               'ip_version': ip_version,
                               'gateway_mac': gateway_mac}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port):
            if network_type == 'vlan':
                self.agent.port_bound(self._port, self._net_uuid,
                                      network_type, self._physical_network,
                                      self._segmentation_id,
                                      self._compute_fixed_ips,
                                      n_const.DEVICE_OWNER_DVR_INTERFACE,
                                      False)
            else:
                self.agent.port_bound(
                    self._port, self._net_uuid, 'vxlan',
                    None, None, self._fixed_ips,
                    n_const.DEVICE_OWNER_DVR_INTERFACE,
                    False)
                lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
                self.assertEqual(self._expected_port_bound(self._port, lvid),
                                 int_br.mock_calls)
                expected_on_tun_br = [
                    mock.call.provision_local_vlan(network_type='vxlan',
                        lvid=lvid, segmentation_id=None, distributed=True),
                ] + self._expected_install_dvr_process(
                    port=self._port,
                    lvid=lvid,
                    ip_version=ip_version,
                    gateway_ip=gateway_ip)
                self.assertEqual(expected_on_tun_br, tun_br.mock_calls)

        int_br.reset_mock()
        tun_br.reset_mock()
        phys_br = mock.create_autospec(self.br_phys_cls('br-phys'))
        with mock.patch.object(self.agent, 'reclaim_local_vlan'),\
                mock.patch.object(self.agent.plugin_rpc, 'update_device_list',
                                  return_value={
                                      'devices_up': [],
                                      'devices_down': [self._port.vif_id],
                                      'failed_devices_up': [],
                                      'failed_devices_down': []}),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.phys_brs,
                                {self._physical_network: phys_br}),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.dvr_agent.phys_brs,
                                {self._physical_network: phys_br}):
            failed_devices = {'added': set(), 'removed': set()}
            failed_devices['removed'] = self.agent.treat_devices_removed(
                [self._port.vif_id])
            lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
            if ip_version == 4:
                expected = [
                    mock.call.delete_dvr_process_ipv4(
                        vlan_tag=lvid,
                        gateway_ip=gateway_ip),
                ]
            else:
                expected = [
                    mock.call.delete_dvr_process_ipv6(
                        vlan_tag=lvid,
                        gateway_mac=gateway_mac),
                ]
            expected.extend([
                mock.call.delete_dvr_process(
                    vlan_tag=lvid,
                    vif_mac=self._port.vif_mac),
            ])
            if network_type == 'vlan':
                self.assertEqual([], int_br.mock_calls)
                self.assertEqual([], tun_br.mock_calls)
                self.assertEqual(expected, phys_br.mock_calls)
                self.assertEqual({}, self.agent.dvr_agent.local_ports)
            else:
                self.assertEqual([], int_br.mock_calls)
                self.assertEqual(expected, tun_br.mock_calls)
                self.assertEqual([], phys_br.mock_calls)

    def _test_treat_devices_removed_for_dvr(self, device_owner, ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        gateway_mac = 'aa:bb:cc:11:22:33'
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': gateway_ip,
                               'cidr': cidr,
                               'ip_version': ip_version,
                               'gateway_mac': gateway_mac}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            self.agent.port_bound(
                self._port, self._net_uuid, 'vxlan',
                None, None, self._fixed_ips,
                n_const.DEVICE_OWNER_DVR_INTERFACE,
                False)
            lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
            self.assertEqual(
                self._expected_port_bound(self._port, lvid),
                int_br.mock_calls)
            expected_on_tun_br = [
                mock.call.provision_local_vlan(
                    network_type='vxlan',
                    segmentation_id=None,
                    lvid=lvid,
                    distributed=True),
            ] + self._expected_install_dvr_process(
                port=self._port,
                lvid=lvid,
                ip_version=ip_version,
                gateway_ip=gateway_ip)
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)
            int_br.reset_mock()
            tun_br.reset_mock()
            self.agent.port_bound(self._compute_port,
                                  self._net_uuid, 'vxlan',
                                  None, None,
                                  self._compute_fixed_ips,
                                  device_owner, False)
            self.assertEqual(
                [
                    mock.call.install_dvr_to_src_mac(
                        network_type='vxlan',
                        gateway_mac='aa:bb:cc:11:22:33',
                        dst_mac=self._compute_port.vif_mac,
                        dst_port=self._compute_port.ofport,
                        vlan_tag=lvid,
                    ),
                ] + self._expected_port_bound(self._compute_port, lvid, False),
                int_br.mock_calls)
            self.assertEqual([], tun_br.mock_calls)

        int_br.reset_mock()
        tun_br.reset_mock()
        with mock.patch.object(self.agent, 'reclaim_local_vlan'),\
                mock.patch.object(self.agent.plugin_rpc, 'update_device_list',
                                  return_value={
                                      'devices_up': [],
                                      'devices_down': [
                                          self._compute_port.vif_id],
                                      'failed_devices_up': [],
                                      'failed_devices_down': []}),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            failed_devices = {'added': set(), 'removed': set()}
            failed_devices['removed'] = self.agent.treat_devices_removed(
                [self._compute_port.vif_id])
            int_br.assert_has_calls([
                mock.call.delete_dvr_to_src_mac(
                    network_type='vxlan',
                    vlan_tag=lvid,
                    dst_mac=self._compute_port.vif_mac,
                ),
            ])
            self.assertEqual([], tun_br.mock_calls)

    def test_treat_devices_removed_for_dvr_with_compute_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=DEVICE_OWNER_COMPUTE)
        self._test_treat_devices_removed_for_dvr(
            device_owner=DEVICE_OWNER_COMPUTE, ip_version=6)

    def test_treat_devices_removed_for_dvr_with_lbaas_vip_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)

    def test_treat_devices_removed_for_dvr_with_lbaasv2_vip_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2)
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCERV2, ip_version=6)

    def test_treat_devices_removed_for_dvr_with_dhcp_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)

    def test_treat_devices_removed_for_dvr_csnat_port(self):
        self._setup_for_dvr_test()
        gateway_mac = 'aa:bb:cc:11:22:33'
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        int_br.set_db_attribute.return_value = True
        int_br.db_get_val.return_value = {}
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_subnet_for_dvr',
                               return_value={'gateway_ip': '1.1.1.1',
                               'cidr': '1.1.1.0/24',
                               'ip_version': 4,
                               'gateway_mac': gateway_mac}),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_ports_on_host_by_subnet',
                                  return_value=[]),\
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            self.agent.port_bound(
                self._port, self._net_uuid, 'vxlan',
                None, None, self._fixed_ips,
                n_const.DEVICE_OWNER_ROUTER_SNAT,
                False)
            lvid = self.agent.vlan_manager.get(self._net_uuid).vlan
            expected_on_int_br = [
                mock.call.install_dvr_to_src_mac(
                    network_type='vxlan',
                    gateway_mac=gateway_mac,
                    dst_mac=self._port.vif_mac,
                    dst_port=self._port.ofport,
                    vlan_tag=lvid,
                ),
            ] + self._expected_port_bound(self._port, lvid, is_dvr=False)
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            expected_on_tun_br = [
                mock.call.provision_local_vlan(
                    network_type='vxlan',
                    lvid=lvid,
                    segmentation_id=None,
                    distributed=True,
                ),
            ]
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)

        int_br.reset_mock()
        tun_br.reset_mock()
        with mock.patch.object(self.agent, 'reclaim_local_vlan'),\
                mock.patch.object(self.agent.plugin_rpc, 'update_device_list',
                                  return_value={
                                      'devices_up': [],
                                      'devices_down': [self._port.vif_id],
                                      'failed_devices_up': [],
                                      'failed_devices_down': []}),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br):
            failed_devices = {'added': set(), 'removed': set()}
            failed_devices['removed'] = self.agent.treat_devices_removed(
                [self._port.vif_id])
            expected_on_int_br = [
                mock.call.delete_dvr_to_src_mac(
                    network_type='vxlan',
                    dst_mac=self._port.vif_mac,
                    vlan_tag=lvid,
                ),
            ]
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            expected_on_tun_br = []
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)

    def test_setup_dvr_flows_on_int_br(self):
        self._setup_for_dvr_test()
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        with mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_dvr_mac_address_list',
                                  return_value=[{'host': 'cn1',
                                  'mac_address': 'aa-bb-cc-dd-ee-ff'},
                                  {'host': 'cn2',
                                  'mac_address': '11-22-33-44-55-66'}]):
            self.agent.dvr_agent.setup_dvr_flows_on_integ_br()
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())
            physical_networks = list(
                self.agent.dvr_agent.bridge_mappings.keys())
            ioport = self.agent.dvr_agent.int_ofports[physical_networks[0]]
            expected_on_int_br = [
                # setup_dvr_flows_on_integ_br
                mock.call.setup_canary_table(),
                mock.call.install_drop(table_id=constants.DVR_TO_SRC_MAC,
                                       priority=1),
                mock.call.install_drop(table_id=constants.DVR_TO_SRC_MAC_VLAN,
                                       priority=1),
                mock.call.install_drop(table_id=constants.LOCAL_SWITCHING,
                                       priority=2,
                                       in_port=ioport),
            ]
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual([], tun_br.mock_calls)

    def test_get_dvr_mac_address(self):
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               return_value={'host': 'cn1',
                                  'mac_address': 'aa-22-33-44-55-66'}):
            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertEqual('aa:22:33:44:55:66',
                             self.agent.dvr_agent.dvr_mac_address)
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())

    def test_get_dvr_mac_address_exception(self):
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        int_br = mock.create_autospec(self.agent.int_br)
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               side_effect=oslo_messaging.RemoteError),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br):
            with testtools.ExpectedException(SystemExit):
                self.agent.dvr_agent.get_dvr_mac_address()
                self.assertIsNone(self.agent.dvr_agent.dvr_mac_address)
                self.assertFalse(self.agent.dvr_agent.in_distributed_mode())

    def test_get_dvr_mac_address_retried(self):
        valid_entry = {'host': 'cn1', 'mac_address': 'aa-22-33-44-55-66'}
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout the first 2 times it calls get_dvr_mac_address()
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               side_effect=(raise_timeout, raise_timeout,
                                            valid_entry)):
            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertEqual('aa:22:33:44:55:66',
                             self.agent.dvr_agent.dvr_mac_address)
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())
            self.assertEqual(self.agent.dvr_agent.plugin_rpc.
                             get_dvr_mac_address_by_host.call_count, 3)

    def test_get_dvr_mac_address_retried_max(self):
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout every time until we give up, currently 5 tries
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        int_br = mock.create_autospec(self.agent.int_br)
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               side_effect=raise_timeout),\
                mock.patch.object(utils, "execute"),\
                mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br):
            with testtools.ExpectedException(SystemExit):
                self.agent.dvr_agent.get_dvr_mac_address()
                self.assertIsNone(self.agent.dvr_agent.dvr_mac_address)
                self.assertFalse(self.agent.dvr_agent.in_distributed_mode())
                self.assertEqual(self.agent.dvr_agent.plugin_rpc.
                                 get_dvr_mac_address_by_host.call_count, 5)

    def test_dvr_mac_address_update(self):
        self._setup_for_dvr_test()
        newhost = 'cn2'
        newmac = 'aa:bb:cc:dd:ee:ff'
        int_br = mock.create_autospec(self.agent.int_br)
        tun_br = mock.create_autospec(self.agent.tun_br)
        phys_br = mock.create_autospec(self.br_phys_cls('br-phys'))
        physical_network = 'physeth1'
        with mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.phys_brs,
                                {physical_network: phys_br}),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.dvr_agent.phys_brs,
                                {physical_network: phys_br}):
            self.agent.dvr_agent.\
                dvr_mac_address_update(
                    dvr_macs=[{'host': newhost,
                               'mac_address': newmac}])
            expected_on_int_br = [
                mock.call.add_dvr_mac_vlan(
                    mac=newmac,
                    port=self.agent.int_ofports[physical_network]),
                mock.call.add_dvr_mac_tun(
                    mac=newmac,
                    port=self.agent.patch_tun_ofport),
            ]
            expected_on_tun_br = [
                mock.call.add_dvr_mac_tun(
                    mac=newmac,
                    port=self.agent.patch_int_ofport),
            ]
            expected_on_phys_br = [
                mock.call.add_dvr_mac_vlan(
                    mac=newmac,
                    port=self.agent.phys_ofports[physical_network]),
            ]
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)
            self.assertEqual(expected_on_phys_br, phys_br.mock_calls)
        int_br.reset_mock()
        tun_br.reset_mock()
        phys_br.reset_mock()
        with mock.patch.object(self.agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.phys_brs,
                                {physical_network: phys_br}),\
                mock.patch.object(self.agent.dvr_agent, 'int_br', new=int_br),\
                mock.patch.object(self.agent.dvr_agent, 'tun_br', new=tun_br),\
                mock.patch.dict(self.agent.dvr_agent.phys_brs,
                                {physical_network: phys_br}):
            self.agent.dvr_agent.dvr_mac_address_update(dvr_macs=[])
            expected_on_int_br = [
                mock.call.remove_dvr_mac_vlan(
                    mac=newmac),
                mock.call.remove_dvr_mac_tun(
                    mac=newmac,
                    port=self.agent.patch_tun_ofport),
            ]
            expected_on_tun_br = [
                mock.call.remove_dvr_mac_tun(
                    mac=newmac),
            ]
            expected_on_phys_br = [
                mock.call.remove_dvr_mac_vlan(
                    mac=newmac),
            ]
            self.assertEqual(expected_on_int_br, int_br.mock_calls)
            self.assertEqual(expected_on_tun_br, tun_br.mock_calls)
            self.assertEqual(expected_on_phys_br, phys_br.mock_calls)

    def test_ovs_restart(self):
        self._setup_for_dvr_test()
        reset_methods = (
            'reset_ovs_parameters', 'reset_dvr_parameters',
            'setup_dvr_flows_on_integ_br', 'setup_dvr_flows_on_tun_br',
            'setup_dvr_flows_on_phys_br', 'setup_dvr_mac_flows_on_all_brs')
        reset_mocks = [mock.patch.object(self.agent.dvr_agent, method).start()
                       for method in reset_methods]
        tun_br = mock.create_autospec(self.agent.tun_br)
        with mock.patch.object(self.agent,
                               'check_ovs_status',
                               return_value=constants.OVS_RESTARTED),\
                mock.patch.object(self.agent,
                                  '_agent_has_updates',
                                  side_effect=TypeError('loop exit')),\
                mock.patch.object(self.agent, 'tun_br', new=tun_br),\
                mock.patch.object(self.agent, 'setup_physical_bridges'),\
                mock.patch.object(self.agent, 'setup_integration_br'),\
                mock.patch.object(self.agent, 'setup_tunnel_br'),\
                mock.patch.object(self.agent, 'state_rpc'):
            try:
                self.agent.rpc_loop(polling_manager=mock.Mock())
            except TypeError:
                pass
        self.assertTrue(all([x.called for x in reset_mocks]))

    def test_rpc_loop_survives_error_in_check_canary_table(self):
        with mock.patch.object(self.agent.int_br,
                               'check_canary_table',
                               side_effect=TypeError('borked')),\
                mock.patch.object(self.agent, '_check_and_handle_signal',
                                  side_effect=[True, False]):
            self.agent.rpc_loop(polling_manager=mock.Mock())

    def _test_scan_ports_failure(self, scan_method_name):
        with mock.patch.object(self.agent,
                               'check_ovs_status',
                               return_value=constants.OVS_RESTARTED),\
                mock.patch.object(self.agent, scan_method_name,
                               side_effect=TypeError('broken')),\
                mock.patch.object(self.agent, '_agent_has_updates',
                                  return_value=True),\
                mock.patch.object(self.agent, '_check_and_handle_signal',
                                  side_effect=[True, False]),\
                mock.patch.object(self.agent, 'setup_physical_bridges'),\
                mock.patch.object(self.agent, 'setup_integration_br'),\
                mock.patch.object(self.agent, 'state_rpc'):
            # block RPC calls and bridge calls
            self.agent.rpc_loop(polling_manager=mock.Mock())

    def test_scan_ports_failure(self):
        self._test_scan_ports_failure('scan_ports')

    def test_scan_ancillary_ports_failure(self):
        with mock.patch.object(self.agent, 'scan_ports'):
            with mock.patch.object(self.agent, 'update_stale_ofport_rules'):
                self.agent.ancillary_brs = mock.Mock()
                self._test_scan_ports_failure('scan_ancillary_ports')


class TestOvsDvrNeutronAgentOFCtl(TestOvsDvrNeutronAgent,
                                  ovs_test_base.OVSOFCtlTestBase):
    pass


class TestOvsDvrNeutronAgentRyu(TestOvsDvrNeutronAgent,
                                ovs_test_base.OVSRyuTestBase):
    pass


class TestValidateTunnelLocalIP(base.BaseTestCase):
    def test_validate_local_ip_with_valid_ip(self):
        mock_get_device_by_ip = mock.patch.object(
            ip_lib.IPWrapper, 'get_device_by_ip').start()
        ovs_agent.validate_local_ip(FAKE_IP1)
        mock_get_device_by_ip.assert_called_once_with(FAKE_IP1)

    def test_validate_local_ip_with_valid_ipv6(self):
        mock_get_device_by_ip = mock.patch.object(
            ip_lib.IPWrapper, 'get_device_by_ip').start()
        ovs_agent.validate_local_ip(FAKE_IP6)
        mock_get_device_by_ip.assert_called_once_with(FAKE_IP6)

    def test_validate_local_ip_with_none_ip(self):
        with testtools.ExpectedException(SystemExit):
            ovs_agent.validate_local_ip(None)

    def test_validate_local_ip_with_invalid_ip(self):
        mock_get_device_by_ip = mock.patch.object(
            ip_lib.IPWrapper, 'get_device_by_ip').start()
        mock_get_device_by_ip.return_value = None
        with testtools.ExpectedException(SystemExit):
            ovs_agent.validate_local_ip(FAKE_IP1)
        mock_get_device_by_ip.assert_called_once_with(FAKE_IP1)

    def test_validate_local_ip_with_invalid_ipv6(self):
        mock_get_device_by_ip = mock.patch.object(
            ip_lib.IPWrapper, 'get_device_by_ip').start()
        mock_get_device_by_ip.return_value = None
        with testtools.ExpectedException(SystemExit):
            ovs_agent.validate_local_ip(FAKE_IP6)
        mock_get_device_by_ip.assert_called_once_with(FAKE_IP6)


class TestOvsAgentTunnelName(base.BaseTestCase):
    def test_get_tunnel_hash_invalid_address(self):
        hashlen = n_const.DEVICE_NAME_MAX_LEN
        self.assertIsNone(
            ovs_agent.OVSNeutronAgent.get_tunnel_hash('a.b.c.d', hashlen))

    def test_get_tunnel_name_vxlan(self):
        self.assertEqual(
            'vxlan-7f000002',
            ovs_agent.OVSNeutronAgent.get_tunnel_name(
                'vxlan', '127.0.0.1', '127.0.0.2'))

    def test_get_tunnel_name_gre(self):
        self.assertEqual(
            'gre-7f000002',
            ovs_agent.OVSNeutronAgent.get_tunnel_name(
                'gre', '127.0.0.1', '127.0.0.2'))

    def test_get_tunnel_name_vxlan_ipv6(self):
        self.assertEqual(
            'vxlan-pehtjzksi',
            ovs_agent.OVSNeutronAgent.get_tunnel_name(
                'vxlan', '2001:db8::1', '2001:db8::2'))

    def test_get_tunnel_name_gre_ipv6(self):
        self.assertEqual(
            'gre-pehtjzksiqr',
            ovs_agent.OVSNeutronAgent.get_tunnel_name(
                'gre', '2001:db8::1', '2001:db8::2'))
