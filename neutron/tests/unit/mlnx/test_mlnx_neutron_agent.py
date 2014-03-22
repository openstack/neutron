# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

from neutron.plugins.mlnx.agent import eswitch_neutron_agent
from neutron.plugins.mlnx.agent import utils
from neutron.tests import base


class TestEswitchAgent(base.BaseTestCase):

    def setUp(self):
        super(TestEswitchAgent, self).setUp()
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
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
        attrs = {'get_device_details.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with contextlib.nested(
            mock.patch('neutron.plugins.mlnx.agent.eswitch_neutron_agent.'
                       'EswitchManager.get_vnics_mac',
                       return_value=[])):
            self.assertTrue(self.agent.treat_devices_added([{}]))

    def _mock_treat_devices_added(self, details, func_name):
        """Mock treat devices added.

        :param details: the details to return for the device
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with contextlib.nested(
            mock.patch('neutron.plugins.mlnx.agent.eswitch_neutron_agent.'
                       'EswitchManager.get_vnics_mac',
                       return_value=[]),
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              return_value=details),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent, func_name)
        ) as (vnics_fn, get_dev_fn, upd_dev_up, func):
            self.assertFalse(self.agent.treat_devices_added([{}]))
        return (func.called, upd_dev_up.called)

    def test_treat_devices_added_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        func, dev_up = self._mock_treat_devices_added(details,
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
        func, dev_up = self._mock_treat_devices_added(details,
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

    def test_process_network_ports(self):
        current_ports = set(['01:02:03:04:05:06'])
        added_ports = set(['10:20:30:40:50:60'])
        removed_ports = set(['11:22:33:44:55:66'])
        reply = {'current': current_ports,
                 'removed': removed_ports,
                 'added': added_ports}
        with mock.patch.object(self.agent, 'treat_devices_added',
                               return_value=False) as device_added:
            with mock.patch.object(self.agent, 'treat_devices_removed',
                                   return_value=False) as device_removed:
                self.assertFalse(self.agent.process_network_ports(reply))
                device_added.assert_called_once_with(added_ports)
                device_removed.assert_called_once_with(removed_ports)
