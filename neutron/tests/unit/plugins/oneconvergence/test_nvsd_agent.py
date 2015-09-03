# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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

import time

import mock
from oslo_config import cfg
from six import moves
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import topics
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.oneconvergence.agent import nvsd_neutron_agent
from neutron.tests import base

DAEMON_LOOP_COUNT = 5


class TestOneConvergenceAgentBase(base.BaseTestCase):

    def setUp(self):
        super(TestOneConvergenceAgentBase, self).setUp()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        with mock.patch('oslo_service.loopingcall.'
                        'FixedIntervalLoopingCall') as loopingcall:
            kwargs = {'integ_br': 'integration_bridge',
                      'polling_interval': 5}
            context = mock.Mock()
            self.agent = nvsd_neutron_agent.NVSDNeutronAgent(**kwargs)
            sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
            self.sg_agent = sg_rpc.SecurityGroupAgentRpc(context,
                    sg_plugin_rpc)
            self.callback_nvsd = nvsd_neutron_agent.NVSDAgentRpcCallback(
                context, self.agent, self.sg_agent)
            self.loopingcall = loopingcall


class TestOneConvergenceAgentCallback(TestOneConvergenceAgentBase):

    def test_port_update(self):
        with mock.patch.object(ovs_lib.OVSBridge,
                               'get_vif_port_by_id') as get_vif_port_by_id,\
                mock.patch.object(self.sg_agent,
                                  'refresh_firewall') as refresh_firewall:
            context = mock.Mock()
            vifport = ovs_lib.VifPort('port1', '1', 'id-1', 'mac-1',
                                      self.agent.int_br)

            # The OVS port does not exist.
            get_vif_port_by_id.return_value = None
            port = {'id': 'update-port-1'}
            self.callback_nvsd.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 1)
            self.assertFalse(refresh_firewall.call_count)

            # The OVS port exists but no security group is associated.
            get_vif_port_by_id.return_value = vifport
            port = {'id': 'update-port-1'}
            self.callback_nvsd.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 2)
            self.assertFalse(refresh_firewall.call_count)

            # The OVS port exists but a security group is associated.
            get_vif_port_by_id.return_value = vifport
            port = {'id': 'update-port-1',
                    ext_sg.SECURITYGROUPS: ['default']}
            self.callback_nvsd.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 3)
            self.assertEqual(refresh_firewall.call_count, 1)

            get_vif_port_by_id.return_value = None
            port = {'id': 'update-port-1',
                    ext_sg.SECURITYGROUPS: ['default']}
            self.callback_nvsd.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 4)
            self.assertEqual(refresh_firewall.call_count, 1)


class TestNVSDAgent(TestOneConvergenceAgentBase):

    def _setup_mock(self):
        self.get_vif_ports = mock.patch.object(
            ovs_lib.OVSBridge, 'get_vif_port_set',
            return_value=set(['id-1', 'id-2'])).start()
        self.prepare_devices_filter = mock.patch.object(
            self.agent.sg_agent, 'prepare_devices_filter').start()
        self.remove_devices_filter = mock.patch.object(
            self.agent.sg_agent, 'remove_devices_filter').start()

    def test_daemon_loop(self):

        def state_check(index):
            self.assertEqual(len(self.vif_ports_scenario[index]),
                             len(self.agent.ports))

        # Fake time.sleep to stop the infinite loop in daemon_loop()
        self.sleep_count = 0

        def sleep_mock(*args, **kwargs):
            state_check(self.sleep_count)
            self.sleep_count += 1
            if self.sleep_count >= DAEMON_LOOP_COUNT:
                raise RuntimeError()

        self.vif_ports_scenario = [set(), set(), set(), set(['id-1', 'id-2']),
                                   set(['id-2', 'id-3'])]

        # Ensure vif_ports_scenario is longer than DAEMON_LOOP_COUNT
        if len(self.vif_ports_scenario) < DAEMON_LOOP_COUNT:
            self.vif_ports_scenario.extend(
                [] for _i in moves.range(DAEMON_LOOP_COUNT -
                                         len(self.vif_ports_scenario)))

        with mock.patch.object(time,
                               'sleep',
                               side_effect=sleep_mock) as sleep,\
                mock.patch.object(ovs_lib.OVSBridge,
                                  'get_vif_port_set') as get_vif_port_set,\
                mock.patch.object(
                    self.agent.sg_agent,
                    'prepare_devices_filter') as prepare_devices_filter,\
                mock.patch.object(
                    self.agent.sg_agent,
                    'remove_devices_filter') as remove_devices_filter:
            get_vif_port_set.side_effect = self.vif_ports_scenario

            with testtools.ExpectedException(RuntimeError):
                self.agent.daemon_loop()
            self.assertEqual(sleep.call_count, DAEMON_LOOP_COUNT)

            expected = [mock.call(set(['id-1', 'id-2'])),
                        mock.call(set(['id-3']))]

            self.assertEqual(prepare_devices_filter.call_count, 2)
            prepare_devices_filter.assert_has_calls(expected)

            expected = [mock.call(set([])), mock.call(set(['id-1']))]

            self.assertEqual(remove_devices_filter.call_count, 2)
            remove_devices_filter.assert_has_calls(expected)

            sleep.assert_called_with(self.agent.polling_interval)


class TestOneConvergenceAgentMain(base.BaseTestCase):
    def test_main(self):
        with mock.patch.object(nvsd_neutron_agent,
                               'NVSDNeutronAgent') as agent,\
                mock.patch.object(nvsd_neutron_agent,
                                  'common_config') as common_config,\
                mock.patch.object(nvsd_neutron_agent, 'config') as config:
            config.AGENT.integration_bridge = 'br-int-dummy'
            config.AGENT.polling_interval = 5

            nvsd_neutron_agent.main()

            self.assertTrue(common_config.setup_logging.called)
            agent.assert_has_calls([
                mock.call('br-int-dummy', 5),
                mock.call().daemon_loop()
            ])
