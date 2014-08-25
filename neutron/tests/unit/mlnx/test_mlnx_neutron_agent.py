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

import contextlib

import mock
from oslo.config import cfg
import testtools

from neutron.plugins.mlnx.agent import eswitch_neutron_agent
from neutron.plugins.mlnx.agent import utils
from neutron.plugins.mlnx.common import exceptions
from neutron.tests import base


class TestEswichManager(base.BaseTestCase):

    def setUp(self):
        super(TestEswichManager, self).setUp()

        class MockEswitchUtils(object):
            def __init__(self, endpoint, timeout):
                pass

        mock.patch('neutron.plugins.mlnx.agent.utils.EswitchManager',
                   new=MockEswitchUtils)

        with mock.patch.object(utils, 'zmq'):
            self.manager = eswitch_neutron_agent.EswitchManager({}, None, None)

    def test_get_not_exist_port_id(self):
        with testtools.ExpectedException(exceptions.MlnxException):
            self.manager.get_port_id_by_mac('no-such-mac')


class TestMlnxEswitchRpcCallbacks(base.BaseTestCase):

    def setUp(self):
        super(TestMlnxEswitchRpcCallbacks, self).setUp()
        agent = mock.Mock()
        self.rpc_callbacks = eswitch_neutron_agent.MlnxEswitchRpcCallbacks(
            'context',
            agent
        )

    def test_port_update(self):
        port = {'mac_address': '10:20:30:40:50:60'}
        add_port_update = self.rpc_callbacks.agent.add_port_update
        self.rpc_callbacks.port_update('context', port=port)
        add_port_update.assert_called_once_with(port['mac_address'])


class TestEswitchAgent(base.BaseTestCase):

    def setUp(self):
        super(TestEswitchAgent, self).setUp()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        mock.patch('neutron.openstack.common.loopingcall.'
                   'FixedIntervalLoopingCall',
                   new=MockFixedIntervalLoopingCall)

        with mock.patch.object(utils, 'zmq'):
            self.agent = eswitch_neutron_agent.MlnxEswitchNeutronAgent({})
        self.agent.plugin_rpc = mock.Mock()
        self.agent.context = mock.Mock()
        self.agent.agent_id = mock.Mock()
        self.agent.eswitch = mock.Mock()
        self.agent.eswitch.get_vnics_mac.return_value = []

    def test_treat_devices_added_returns_true_for_missing_device(self):
        attrs = {'get_devices_details_list.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with contextlib.nested(
            mock.patch('neutron.plugins.mlnx.agent.eswitch_neutron_agent.'
                       'EswitchManager.get_vnics_mac',
                       return_value=[])):
            self.assertTrue(self.agent.treat_devices_added_or_updated([{}]))

    def _mock_treat_devices_added_updated(self, details, func_name):
        """Mock treat devices added.

        :param details: the details to return for the device
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with contextlib.nested(
            mock.patch('neutron.plugins.mlnx.agent.eswitch_neutron_agent.'
                       'EswitchManager.get_vnics_mac',
                       return_value=[]),
            mock.patch.object(self.agent.plugin_rpc,
                              'get_devices_details_list',
                              return_value=[details]),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent, func_name)
        ) as (vnics_fn, get_dev_fn, upd_dev_up, func):
            self.assertFalse(self.agent.treat_devices_added_or_updated([{}]))
        return (func.called, upd_dev_up.called)

    def test_treat_devices_added_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        func, dev_up = self._mock_treat_devices_added_updated(details,
                                                              'treat_vif_port')
        self.assertTrue(func)
        self.assertTrue(dev_up)

    def test_treat_devices_added_updates_known_port_admin_down(self):
        details = {'port_id': '1234567890',
                   'device': '01:02:03:04:05:06',
                   'network_id': '123456789',
                   'network_type': 'vlan',
                   'physical_network': 'default',
                   'segmentation_id': 2,
                   'admin_state_up': False}
        func, dev_up = self._mock_treat_devices_added_updated(details,
                                                              'treat_vif_port')
        self.assertTrue(func)
        self.assertFalse(dev_up)

    def test_treat_devices_removed_returns_true_for_missing_device(self):
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               side_effect=Exception()):
            self.assertTrue(self.agent.treat_devices_removed([{}]))

    def test_treat_devices_removed_releases_port(self):
        details = dict(exists=False)
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               return_value=details):
            with mock.patch.object(self.agent.eswitch,
                                   'port_release') as port_release:
                self.assertFalse(self.agent.treat_devices_removed([{}]))
                self.assertTrue(port_release.called)

    def _test_process_network_ports(self, port_info):
        with contextlib.nested(
            mock.patch.object(self.agent, 'treat_devices_added_or_updated',
                              return_value=False),
            mock.patch.object(self.agent, 'treat_devices_removed',
                              return_value=False)
        ) as (device_added_updated, device_removed):
            self.assertFalse(self.agent.process_network_ports(port_info))
            device_added_updated.assert_called_once_with(
                port_info['added'] | port_info['updated'])
            device_removed.assert_called_once_with(port_info['removed'])

    def test_process_network_ports(self):
        self._test_process_network_ports(
            {'current': set(['10:20:30:40:50:60']),
             'updated': set(),
             'added': set(['11:21:31:41:51:61']),
             'removed': set(['13:23:33:43:53:63'])})

    def test_process_network_ports_with_updated_ports(self):
        self._test_process_network_ports(
            {'current': set(['10:20:30:40:50:60']),
             'updated': set(['12:22:32:42:52:62']),
             'added': set(['11:21:31:41:51:61']),
             'removed': set(['13:23:33:43:53:63'])})

    def test_add_port_update(self):
        mac_addr = '10:20:30:40:50:60'
        self.agent.add_port_update(mac_addr)
        self.assertEqual(set([mac_addr]), self.agent.updated_ports)

    def _mock_scan_ports(self, vif_port_set, previous,
                         updated_ports, sync=False):
        self.agent.updated_ports = updated_ports
        with mock.patch.object(self.agent.eswitch, 'get_vnics_mac',
                               return_value=vif_port_set):
            return self.agent.scan_ports(previous, sync)

    def test_scan_ports_return_current_for_unchanged_ports(self):
        vif_port_set = set([1, 2])
        previous = dict(current=set([1, 2]), added=set(),
                        removed=set(), updated=set())
        expected = dict(current=vif_port_set, added=set(),
                        removed=set(), updated=set())
        actual = self._mock_scan_ports(vif_port_set,
                                       previous, set())
        self.assertEqual(expected, actual)

    def test_scan_ports_return_port_changes(self):
        vif_port_set = set([1, 3])
        previous = dict(current=set([1, 2]), added=set(),
                        removed=set(), updated=set())
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set())
        actual = self._mock_scan_ports(vif_port_set,
                                       previous, set())
        self.assertEqual(expected, actual)

    def test_scan_ports_with_updated_ports(self):
        vif_port_set = set([1, 3, 4])
        previous = dict(current=set([1, 2, 4]), added=set(),
                        removed=set(), updated=set())
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([4]))
        actual = self._mock_scan_ports(vif_port_set,
                                       previous, set([4]))
        self.assertEqual(expected, actual)

    def test_scan_ports_with_unknown_updated_ports(self):
        vif_port_set = set([1, 3, 4])
        previous = dict(current=set([1, 2, 4]), added=set(),
                        removed=set(), updated=set())
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([4]))
        actual = self._mock_scan_ports(vif_port_set,
                                       previous,
                                       updated_ports=set([4, 5]))
        self.assertEqual(expected, actual)
