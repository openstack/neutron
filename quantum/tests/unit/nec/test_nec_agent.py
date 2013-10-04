# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
from oslo.config import cfg
import testtools

from quantum.agent.linux import ovs_lib
from quantum.extensions import securitygroup as ext_sg
from quantum.plugins.nec.agent import nec_quantum_agent
from quantum.tests import base

DAEMON_LOOP_COUNT = 10
OVS_DPID = '00000629355b6943'
OVS_DPID_0X = '0x' + OVS_DPID


class TestNecAgentBase(base.BaseTestCase):

    def setUp(self):
        super(TestNecAgentBase, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(mock.patch.stopall)
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('host', 'dummy-host')
        with contextlib.nested(
            mock.patch.object(ovs_lib.OVSBridge, 'get_datapath_id',
                              return_value=OVS_DPID),
            mock.patch('socket.gethostname', return_value='dummy-host'),
            mock.patch('quantum.openstack.common.loopingcall.LoopingCall'),
            mock.patch('quantum.agent.rpc.PluginReportStateAPI')
        ) as (get_datapath_id, gethostname,
              loopingcall, state_rpc_api):
            kwargs = {'integ_br': 'integ_br',
                      'root_helper': 'dummy_wrapper',
                      'polling_interval': 1}
            self.agent = nec_quantum_agent.NECQuantumAgent(**kwargs)
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
            nec_quantum_agent.NECPluginApi, 'update_ports').start()
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
                [] for _i in xrange(DAEMON_LOOP_COUNT -
                                    len(self.vif_ports_scenario)))

        with contextlib.nested(
            mock.patch.object(time, 'sleep', side_effect=sleep_mock),
            mock.patch.object(ovs_lib.OVSBridge, 'get_vif_ports'),
            mock.patch.object(nec_quantum_agent.NECPluginApi, 'update_ports'),
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


class TestNecAgentPluginApi(TestNecAgentBase):

    def _test_plugin_api(self, expected_failure=False):
        with contextlib.nested(
            mock.patch.object(nec_quantum_agent.NECPluginApi, 'make_msg'),
            mock.patch.object(nec_quantum_agent.NECPluginApi, 'call'),
            mock.patch.object(nec_quantum_agent, 'LOG')
        ) as (make_msg, apicall, log):
            agent_id = 'nec-q-agent.dummy-host'
            if expected_failure:
                apicall.side_effect = Exception()

            self.agent.plugin_rpc.update_ports(
                mock.sentinel.ctx, agent_id, OVS_DPID_0X,
                # port_added
                [{'id': 'id-1', 'mac': 'mac-1', 'port_no': '1'},
                 {'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}],
                # port_removed
                ['id-3', 'id-4', 'id-5'])

            make_msg.assert_called_once_with(
                'update_ports', topic='q-agent-notifier',
                agent_id=agent_id, datapath_id=OVS_DPID_0X,
                port_added=[{'id': 'id-1', 'mac': 'mac-1', 'port_no': '1'},
                            {'id': 'id-2', 'mac': 'mac-2', 'port_no': '2'}],
                port_removed=['id-3', 'id-4', 'id-5'])

            apicall.assert_called_once_with(mock.sentinel.ctx,
                                            make_msg.return_value)

            self.assertTrue(log.info.called)
            if expected_failure:
                self.assertTrue(log.warn.called)

    def test_plugin_api(self):
        self._test_plugin_api()
