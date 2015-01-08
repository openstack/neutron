# Copyright 2013 NEC Corporation.  All rights reserved.
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

import contextlib
import copy
import itertools
import time

import mock
from oslo_config import cfg
from six import moves
import testtools

from neutron.agent.linux import ovs_lib
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.nec.agent import nec_neutron_agent
from neutron.tests import base

DAEMON_LOOP_COUNT = 10
OVS_DPID = '00000629355b6943'
OVS_DPID_0X = '0x' + OVS_DPID


class TestNecAgentBase(base.BaseTestCase):

    def setUp(self):
        super(TestNecAgentBase, self).setUp()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_override('host', 'dummy-host')
        with contextlib.nested(
            mock.patch.object(ovs_lib.OVSBridge, 'get_datapath_id',
                              return_value=OVS_DPID),
            mock.patch('socket.gethostname', return_value='dummy-host'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall'),
            mock.patch('neutron.agent.rpc.PluginReportStateAPI')
        ) as (get_datapath_id, gethostname,
              loopingcall, state_rpc_api):
            kwargs = {'integ_br': 'integ_br',
                      'root_helper': 'dummy_wrapper',
                      'polling_interval': 1}
            self.agent = nec_neutron_agent.NECNeutronAgent(**kwargs)
            self.loopingcall = loopingcall
            self.state_rpc_api = state_rpc_api


class TestNecAgent(TestNecAgentBase):

    def _setup_mock(self):
        vif_ports = [ovs_lib.VifPort('port1', '1', 'id-1', 'mac-1',
                                     self.agent.int_br),
                     ovs_lib.VifPort('port2', '2', 'id-2', 'mac-2',
                                     self.agent.int_br)]
        self.get_vif_ports = mock.patch.object(
            ovs_lib.OVSBridge, 'get_vif_ports',
            return_value=vif_ports).start()
        self.update_ports = mock.patch.object(
            nec_neutron_agent.NECPluginApi, 'update_ports').start()
        self.prepare_devices_filter = mock.patch.object(
            self.agent.sg_agent, 'prepare_devices_filter').start()
        self.remove_devices_filter = mock.patch.object(
            self.agent.sg_agent, 'remove_devices_filter').start()

    def _test_single_loop(self, with_exc=False, need_sync=False):
        self.agent.cur_ports = ['id-0', 'id-1']
        self.agent.need_sync = need_sync

        self.agent.loop_handler()
        if with_exc:
            self.assertEqual(self.agent.cur_ports, ['id-0', 'id-1'])
            self.assertTrue(self.agent.need_sync)
        else:
            self.assertEqual(self.agent.cur_ports, ['id-1', 'id-2'])
            self.assertFalse(self.agent.need_sync)

    def test_single_loop_normal(self):
        self._setup_mock()
        self._test_single_loop()
        agent_id = 'nec-q-agent.dummy-host'
        self.update_ports.assert_called_once_with(
            mock.ANY, agent_id, OVS_DPID_0X,
            [{'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}],
            ['id-0'])
        self.prepare_devices_filter.assert_called_once_with(['id-2'])
        self.remove_devices_filter.assert_called_once_with(['id-0'])

    def test_single_loop_need_sync(self):
        self._setup_mock()
        self._test_single_loop(need_sync=True)
        agent_id = 'nec-q-agent.dummy-host'
        self.update_ports.assert_called_once_with(
            mock.ANY, agent_id, OVS_DPID_0X,
            [{'id': 'id-1', 'mac': 'mac-1', 'port_no': '1'},
             {'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}],
            [])
        self.prepare_devices_filter.assert_called_once_with(['id-1', 'id-2'])
        self.assertFalse(self.remove_devices_filter.call_count)

    def test_single_loop_with_sg_exception_remove(self):
        self._setup_mock()
        self.update_ports.side_effect = Exception()
        self._test_single_loop(with_exc=True)

    def test_single_loop_with_sg_exception_prepare(self):
        self._setup_mock()
        self.prepare_devices_filter.side_effect = Exception()
        self._test_single_loop(with_exc=True)

    def test_single_loop_with_update_ports_exception(self):
        self._setup_mock()
        self.remove_devices_filter.side_effect = Exception()
        self._test_single_loop(with_exc=True)

    def test_daemon_loop(self):

        def state_check(index):
            self.assertEqual(len(self.vif_ports_scenario[index]),
                             len(self.agent.cur_ports))

        # Fake time.sleep to stop the infinite loop in daemon_loop()
        self.sleep_count = 0

        def sleep_mock(*args, **kwargs):
            state_check(self.sleep_count)
            self.sleep_count += 1
            if self.sleep_count >= DAEMON_LOOP_COUNT:
                raise RuntimeError()

        vif_ports = [ovs_lib.VifPort('port1', '1', 'id-1', 'mac-1',
                                     self.agent.int_br),
                     ovs_lib.VifPort('port2', '2', 'id-2', 'mac-2',
                                     self.agent.int_br)]

        self.vif_ports_scenario = [[], [], vif_ports[0:1], vif_ports[0:2],
                                   vif_ports[1:2], []]

        # Ensure vif_ports_scenario is longer than DAEMON_LOOP_COUNT
        if len(self.vif_ports_scenario) < DAEMON_LOOP_COUNT:
            self.vif_ports_scenario.extend(
                [] for _i in moves.xrange(DAEMON_LOOP_COUNT -
                                          len(self.vif_ports_scenario)))

        with contextlib.nested(
            mock.patch.object(time, 'sleep', side_effect=sleep_mock),
            mock.patch.object(ovs_lib.OVSBridge, 'get_vif_ports'),
            mock.patch.object(nec_neutron_agent.NECPluginApi, 'update_ports'),
            mock.patch.object(self.agent.sg_agent, 'prepare_devices_filter'),
            mock.patch.object(self.agent.sg_agent, 'remove_devices_filter')
        ) as (sleep, get_vif_potrs, update_ports,
              prepare_devices_filter, remove_devices_filter):
            get_vif_potrs.side_effect = self.vif_ports_scenario

            with testtools.ExpectedException(RuntimeError):
                self.agent.daemon_loop()
            self.assertEqual(update_ports.call_count, 4)
            self.assertEqual(sleep.call_count, DAEMON_LOOP_COUNT)

            agent_id = 'nec-q-agent.dummy-host'
            expected = [
                mock.call(mock.ANY, agent_id, OVS_DPID_0X,
                          [{'id': 'id-1', 'mac': 'mac-1', 'port_no': '1'}],
                          []),
                mock.call(mock.ANY, agent_id, OVS_DPID_0X,
                          [{'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}],
                          []),
                mock.call(mock.ANY, agent_id, OVS_DPID_0X,
                          [], ['id-1']),
                mock.call(mock.ANY, agent_id, OVS_DPID_0X,
                          [], ['id-2'])
            ]
            update_ports.assert_has_calls(expected)

            expected = [mock.call(['id-1']),
                        mock.call(['id-2'])]
            self.assertEqual(prepare_devices_filter.call_count, 2)
            prepare_devices_filter.assert_has_calls(expected)
            self.assertEqual(remove_devices_filter.call_count, 2)
            remove_devices_filter.assert_has_calls(expected)

            sleep.assert_called_with(self.agent.polling_interval)

    def test_report_state_installed(self):
        self.loopingcall.assert_called_once_with(self.agent._report_state)
        instance = self.loopingcall.return_value
        self.assertTrue(instance.start.called)

    def _check_report_state(self, cur_ports, num_ports, fail_mode,
                            first=False):
        self.assertEqual(first or fail_mode,
                         'start_flag' in self.agent.agent_state)
        self.agent.cur_ports = cur_ports

        self.agent._report_state()

        self.assertEqual(fail_mode,
                         'start_flag' in self.agent.agent_state)
        self.assertEqual(self.agent.
                         agent_state['configurations']['devices'],
                         num_ports)
        self.num_ports_hist.append(num_ports)

    def _test_report_state(self, fail_mode):
        log_mocked = mock.patch.object(nec_neutron_agent, 'LOG')
        log_patched = log_mocked.start()

        def record_state(*args, **kwargs):
            self.record_calls.append(copy.deepcopy(args))
            if fail_mode:
                raise Exception()

        self.record_calls = []
        self.num_ports_hist = []
        state_rpc = self.state_rpc_api.return_value
        state_rpc.report_state.side_effect = record_state
        dummy_vif = ovs_lib.VifPort('port1', '1', 'id-1', 'mac-1', None)

        self.state_rpc_api.assert_called_once_with('q-plugin')
        self.assertIn('start_flag', self.agent.agent_state)

        self._check_report_state([], 0, fail_mode, first=True)
        self._check_report_state([dummy_vif] * 2, 2, fail_mode)
        self._check_report_state([dummy_vif] * 5, 5, fail_mode)
        self._check_report_state([], 0, fail_mode)

        # Since loopingcall start is mocked, call_count is same as
        # the call count of check_report_state.
        self.assertEqual(state_rpc.report_state.call_count, 4)
        self.assertEqual(len(self.record_calls), 4)

        for i, x in enumerate(itertools.izip(self.record_calls,
                                             self.num_ports_hist)):
            rec, num_ports = x
            expected_state = {
                'binary': 'neutron-nec-agent',
                'host': 'dummy-host',
                'topic': 'N/A',
                'configurations': {'devices': 0},
                'agent_type': 'NEC plugin agent'}
            expected_state['configurations']['devices'] = num_ports
            if i == 0 or fail_mode:
                expected_state['start_flag'] = True
            self.assertEqual(expected_state, rec[1])

        self.assertEqual(fail_mode, log_patched.exception.called)

    def test_report_state(self):
        self._test_report_state(fail_mode=False)

    def test_report_state_fail(self):
        self._test_report_state(fail_mode=True)


class TestNecAgentCallback(TestNecAgentBase):

    def test_port_update(self):
        with contextlib.nested(
            mock.patch.object(ovs_lib.OVSBridge, 'get_vif_port_by_id'),
            mock.patch.object(self.agent.sg_agent, 'refresh_firewall')
        ) as (get_vif_port_by_id, refresh_firewall):
            context = mock.Mock()
            vifport = ovs_lib.VifPort('port1', '1', 'id-1', 'mac-1',
                                      self.agent.int_br)

            # The OVS port does not exist.
            get_vif_port_by_id.return_value = None
            port = {'id': 'update-port-1'}
            self.agent.callback_nec.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 1)
            self.assertFalse(refresh_firewall.call_count)

            # The OVS port exists but no security group is associated.
            get_vif_port_by_id.return_value = vifport
            port = {'id': 'update-port-1'}
            self.agent.callback_nec.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 2)
            self.assertFalse(refresh_firewall.call_count)

            # The OVS port exists but a security group is associated.
            get_vif_port_by_id.return_value = vifport
            port = {'id': 'update-port-1',
                    ext_sg.SECURITYGROUPS: ['default']}
            self.agent.callback_nec.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 3)
            self.assertEqual(refresh_firewall.call_count, 1)

            get_vif_port_by_id.return_value = None
            port = {'id': 'update-port-1',
                    ext_sg.SECURITYGROUPS: ['default']}
            self.agent.callback_nec.port_update(context, port=port)
            self.assertEqual(get_vif_port_by_id.call_count, 4)
            self.assertEqual(refresh_firewall.call_count, 1)


class TestNecAgentPluginApi(TestNecAgentBase):

    def test_plugin_api(self):
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc.client, 'prepare'),
            mock.patch.object(self.agent.plugin_rpc.client, 'call'),
        ) as (mock_prepare, mock_call):
            mock_prepare.return_value = self.agent.plugin_rpc.client

            agent_id = 'nec-q-agent.dummy-host'
            port_added = [{'id': 'id-1', 'mac': 'mac-1', 'port_no': '1'},
                          {'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}]
            port_removed = ['id-3', 'id-4', 'id-5']

            self.agent.plugin_rpc.update_ports(
                mock.sentinel.ctx, agent_id, OVS_DPID_0X,
                port_added, port_removed)

            mock_call.assert_called_once_with(
                    mock.sentinel.ctx, 'update_ports',
                    agent_id=agent_id, datapath_id=OVS_DPID_0X,
                    port_added=port_added, port_removed=port_removed)


class TestNecAgentMain(base.BaseTestCase):
    def test_main(self):
        with contextlib.nested(
            mock.patch.object(nec_neutron_agent, 'NECNeutronAgent'),
            mock.patch.object(nec_neutron_agent, 'common_config'),
            mock.patch.object(nec_neutron_agent, 'config')
        ) as (agent, common_config, cfg):
            cfg.OVS.integration_bridge = 'br-int-x'
            cfg.AGENT.root_helper = 'dummy-helper'
            cfg.AGENT.polling_interval = 10

            nec_neutron_agent.main()

            self.assertTrue(common_config.setup_logging.called)
            agent.assert_has_calls([
                mock.call('br-int-x', 'dummy-helper', 10),
                mock.call().daemon_loop()
            ])
