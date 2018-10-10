# Copyright (c) 2012 OpenStack Foundation.
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

import signal

import mock
import testtools

from neutron.cmd import netns_cleanup as util
from neutron.tests import base

NETSTAT_NETNS_OUTPUT = ("""
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State\
       PID/Program name
tcp        0      0 0.0.0.0:9697            0.0.0.0:*               LISTEN\
      1347/python
raw        0      0 0.0.0.0:112             0.0.0.0:*               7\
           1279/keepalived
raw        0      0 0.0.0.0:112             0.0.0.0:*               7\
           1279/keepalived
raw6       0      0 :::58                   :::*                    7\
           1349/radvd
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name\
     Path
unix  2      [ ACC ]     STREAM     LISTENING     82039530 1353/python\
          /tmp/rootwrap-VKSm8a/rootwrap.sock
""")

NETSTAT_NO_NAMESPACE = ("""
Cannot open network namespace "qrouter-e6f206b2-4e8d-4597-a7e1-c3a20337e9c6":\
 No such file or directory
""")

NETSTAT_NO_LISTEN_PROCS = ("""
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State\
       PID/Program name
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name\
     Path
""")


class TestNetnsCleanup(base.BaseTestCase):
    def setUp(self):
        super(TestNetnsCleanup, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)

    def test_kill_dhcp(self, dhcp_active=True):
        conf = mock.Mock()
        conf.dhcp_driver = 'driver'

        method_to_patch = 'oslo_utils.importutils.import_object'

        with mock.patch(method_to_patch) as import_object:
            driver = mock.Mock()
            driver.active = dhcp_active
            import_object.return_value = driver

            util.kill_dhcp(conf, 'ns')

            expected_params = {'conf': conf, 'network': mock.ANY,
                               'process_monitor': mock.ANY,
                               'plugin': mock.ANY}
            import_object.assert_called_once_with('driver', **expected_params)

            if dhcp_active:
                driver.assert_has_calls([mock.call.disable()])
            else:
                self.assertFalse(driver.called)

    def test_kill_dhcp_no_active(self):
        self.test_kill_dhcp(False)

    def test_eligible_for_deletion_ns_not_uuid(self):
        conf = mock.Mock()
        conf.agent_type = None
        ns = 'not_a_uuid'
        self.assertFalse(util.eligible_for_deletion(conf, ns))

    def _test_eligible_for_deletion_helper(self, prefix, force, is_empty,
                                           expected):
        ns = prefix + '6e322ac7-ab50-4f53-9cdc-d1d3c1164b6d'
        conf = mock.Mock()
        conf.agent_type = None

        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip_wrap:
            ip_wrap.return_value.namespace_is_empty.return_value = is_empty
            self.assertEqual(expected,
                             util.eligible_for_deletion(conf, ns, force))

            expected_calls = [mock.call(namespace=ns)]
            if not force:
                expected_calls.append(mock.call().namespace_is_empty())
            ip_wrap.assert_has_calls(expected_calls)

    def test_eligible_for_deletion_empty(self):
        self._test_eligible_for_deletion_helper('qrouter-', False, True, True)

    def test_eligible_for_deletion_not_empty(self):
        self._test_eligible_for_deletion_helper('qdhcp-', False, False, False)

    def test_eligible_for_deletion_not_empty_forced(self):
        self._test_eligible_for_deletion_helper('qdhcp-', True, False, True)

    def test_eligible_for_deletion_fip_namespace(self):
        self._test_eligible_for_deletion_helper('fip-', False, True, True)

    def test_eligible_for_deletion_lbaas_namespace(self):
        self._test_eligible_for_deletion_helper('qlbaas-', False, True, True)

    def test_eligible_for_deletion_snat_namespace(self):
        self._test_eligible_for_deletion_helper('snat-', False, True, True)

    def test_eligible_for_deletion_filtered_by_agent_type(self):
        ns_dhcp = 'qdhcp-' + '6e322ac7-ab50-4f53-9cdc-d1d3c1164b6d'
        ns_l3 = 'qrouter-' + '6e322ac7-ab50-4f53-9cdc-d1d3c1164b6d'
        conf = mock.Mock()
        conf.agent_type = 'dhcp'

        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip_wrap:
            ip_wrap.return_value.namespace_is_empty.return_value = True
            self.assertTrue(util.eligible_for_deletion(conf, ns_dhcp, False))
            self.assertFalse(util.eligible_for_deletion(conf, ns_l3, False))

            expected_calls = [mock.call(namespace=ns_dhcp),
                              mock.call().namespace_is_empty()]
            ip_wrap.assert_has_calls(expected_calls)

    def test_unplug_device_regular_device(self):
        device = mock.Mock()

        util.unplug_device(device)
        device.assert_has_calls([mock.call.link.delete()])

    def test_unplug_device_ovs_port(self):
        device = mock.Mock()
        device.name = 'tap1'
        device.link.delete.side_effect = RuntimeError

        with mock.patch(
                'neutron.agent.common.ovs_lib.OVSBridge') as ovs_br_cls:
            br_patch = mock.patch(
                'neutron.agent.common.ovs_lib.BaseOVS.get_bridge_for_iface')
            with br_patch as mock_get_bridge_for_iface:
                mock_get_bridge_for_iface.return_value = 'br-int'
                ovs_bridge = mock.Mock()
                ovs_br_cls.return_value = ovs_bridge

                util.unplug_device(device)

                mock_get_bridge_for_iface.assert_called_once_with('tap1')
                ovs_br_cls.assert_called_once_with('br-int')
                ovs_bridge.assert_has_calls(
                    [mock.call.delete_port(device.name)])

    def test_unplug_device_cannot_determine_bridge_port(self):
        device = mock.Mock()
        device.name = 'tap1'
        device.link.delete.side_effect = RuntimeError

        with mock.patch(
                'neutron.agent.common.ovs_lib.OVSBridge') as ovs_br_cls:
            br_patch = mock.patch(
                'neutron.agent.common.ovs_lib.BaseOVS.get_bridge_for_iface')
            with br_patch as mock_get_bridge_for_iface:
                with mock.patch.object(util.LOG, 'debug') as debug:
                    mock_get_bridge_for_iface.return_value = None
                    ovs_bridge = mock.Mock()
                    ovs_br_cls.return_value = ovs_bridge

                    util.unplug_device(device)

                    mock_get_bridge_for_iface.assert_called_once_with('tap1')
                    self.assertEqual([], ovs_br_cls.mock_calls)
                    self.assertTrue(debug.called)

    def _test_find_listen_pids_namespace_helper(self, expected,
                                                netstat_output=None):
        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip_wrap:
            ip_wrap.return_value.netns.execute.return_value = netstat_output
            observed = util.find_listen_pids_namespace(mock.ANY)
            self.assertEqual(expected, observed)

    def test_find_listen_pids_namespace_correct_output(self):
        expected = set(['1347', '1279', '1349', '1353'])
        self._test_find_listen_pids_namespace_helper(expected,
                                                     NETSTAT_NETNS_OUTPUT)

    def test_find_listen_pids_namespace_no_procs(self):
        expected = set()
        self._test_find_listen_pids_namespace_helper(expected,
                                                     NETSTAT_NO_LISTEN_PROCS)

    def test_find_listen_pids_namespace_no_namespace(self):
        expected = set()
        self._test_find_listen_pids_namespace_helper(expected,
                                                     NETSTAT_NO_NAMESPACE)

    def _test__kill_listen_processes_helper(self, pids, parents, children,
                                            kills_expected, force):
        def _get_element(dct, x):
            return dct.get(x, [])

        def _find_childs(x, recursive):
            return _get_element(children, x)

        def _find_parent(x):
            return _get_element(parents, x)

        utils_mock = dict(
            find_fork_top_parent=mock.DEFAULT,
            find_child_pids=mock.DEFAULT,
            get_cmdline_from_pid=mock.DEFAULT,
            kill_process=mock.DEFAULT)

        self.log_mock = mock.patch.object(util, 'LOG').start()
        with mock.patch.multiple('neutron.agent.linux.utils', **utils_mock)\
                as mocks:
            mocks['find_fork_top_parent'].side_effect = _find_parent
            mocks['find_child_pids'].side_effect = _find_childs

            with mock.patch.object(util, 'find_listen_pids_namespace',
                                   return_value=pids):
                calls = []
                for pid, sig in kills_expected:
                    calls.append(mock.call(pid, sig, run_as_root=True))
                util._kill_listen_processes(mock.ANY, force=force)
                mocks['kill_process'].assert_has_calls(calls, any_order=True)

    def test__kill_listen_processes_only_parents_force_false(self):
        pids = ['4', '5', '6']
        parents = {'4': '1', '5': '5', '6': '2'}
        children = {}
        kills_expected = [('1', signal.SIGTERM),
                          ('5', signal.SIGTERM),
                          ('2', signal.SIGTERM)]

        self._test__kill_listen_processes_helper(pids, parents, children,
                                                 kills_expected, False)

    def test__kill_listen_processes_parents_and_childs(self):
        pids = ['4', '5', '6']
        parents = {'4': '1', '5': '2', '6': '3'}
        children = {'1': ['4'], '2': ['5'], '3': ['6', '8', '7']}
        kills_expected = [(str(x), signal.SIGKILL) for x in range(1, 9)]
        self._test__kill_listen_processes_helper(pids, parents, children,
                                                 kills_expected, True)

    def test_kill_listen_processes(self):
        with mock.patch.object(util, '_kill_listen_processes',
                               return_value=1) as mock_kill_listen:
            with mock.patch.object(util, 'wait_until_no_listen_pids_namespace',
                                   side_effect=[util.PidsInNamespaceException,
                                                None]):
                namespace = mock.ANY
                util.kill_listen_processes(namespace)
                mock_kill_listen.assert_has_calls(
                    [mock.call(namespace, force=False),
                     mock.call(namespace, force=True)])

    def test_kill_listen_processes_still_procs(self):
        with mock.patch.object(util, '_kill_listen_processes',
                               return_value=1):
            with mock.patch.object(util, 'wait_until_no_listen_pids_namespace',
                            side_effect=util.PidsInNamespaceException):
                namespace = mock.ANY
                with testtools.ExpectedException(
                        util.PidsInNamespaceException):
                    util.kill_listen_processes(namespace)

    def test_kill_listen_processes_no_procs(self):
        with mock.patch.object(util, '_kill_listen_processes',
                               return_value=0) as mock_kill_listen:
            with mock.patch.object(util,
                                   'wait_until_no_listen_pids_namespace')\
                    as wait_until_mock:
                namespace = mock.ANY
                util.kill_listen_processes(namespace)
                mock_kill_listen.assert_called_once_with(namespace,
                                                         force=False)
                self.assertFalse(wait_until_mock.called)

    def _test_destroy_namespace_helper(self, force, num_devices):
        ns = 'qrouter-6e322ac7-ab50-4f53-9cdc-d1d3c1164b6d'
        conf = mock.Mock()

        lo_device = mock.Mock()
        lo_device.name = 'lo'

        devices = [lo_device]

        while num_devices:
            dev = mock.Mock()
            dev.name = 'tap%d' % num_devices
            devices.append(dev)
            num_devices -= 1

        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip_wrap:
            ip_wrap.return_value.get_devices.return_value = devices
            ip_wrap.return_value.netns.exists.return_value = True

            with mock.patch.object(util, 'kill_listen_processes'):

                with mock.patch.object(util, 'unplug_device') as unplug:

                    with mock.patch.object(util, 'kill_dhcp') as kill_dhcp:
                        util.destroy_namespace(conf, ns, force)
                        expected = [mock.call(namespace=ns)]

                        if force:
                            expected.extend([
                                mock.call().netns.exists(ns),
                                mock.call().get_devices()])
                            self.assertTrue(kill_dhcp.called)
                            unplug.assert_has_calls(
                                [mock.call(d) for d in devices[1:]])

                        expected.append(
                            mock.call().garbage_collect_namespace())
                        ip_wrap.assert_has_calls(expected)

    def test_destroy_namespace_empty(self):
        self._test_destroy_namespace_helper(False, 0)

    def test_destroy_namespace_not_empty(self):
        self._test_destroy_namespace_helper(False, 1)

    def test_destroy_namespace_not_empty_forced(self):
        self._test_destroy_namespace_helper(True, 2)

    def test_destroy_namespace_exception(self):
        ns = 'qrouter-6e322ac7-ab50-4f53-9cdc-d1d3c1164b6d'
        conf = mock.Mock()
        with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip_wrap:
            ip_wrap.side_effect = Exception()
            util.destroy_namespace(conf, ns)

    def test_main(self):
        namespaces = ['ns1', 'ns2']
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'list_network_namespaces') as listnetns:
            listnetns.return_value = namespaces

            with mock.patch('time.sleep') as time_sleep:
                conf = mock.Mock()
                conf.force = False
                methods_to_mock = dict(
                    eligible_for_deletion=mock.DEFAULT,
                    destroy_namespace=mock.DEFAULT,
                    setup_conf=mock.DEFAULT)

                with mock.patch.multiple(util, **methods_to_mock) as mocks:
                    mocks['eligible_for_deletion'].return_value = True
                    mocks['setup_conf'].return_value = conf
                    with mock.patch('neutron.common.config.setup_logging'):
                        util.main()

                        mocks['eligible_for_deletion'].assert_has_calls(
                            [mock.call(conf, 'ns1', False),
                             mock.call(conf, 'ns2', False)])

                        mocks['destroy_namespace'].assert_has_calls(
                            [mock.call(conf, 'ns1', False),
                             mock.call(conf, 'ns2', False)])

                        self.assertEqual(1, listnetns.call_count)

                        time_sleep.assert_called_once_with(2)

    def test_main_no_candidates(self):
        namespaces = ['ns1', 'ns2']
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'list_network_namespaces') as listnetns:
            listnetns.return_value = namespaces

            with mock.patch('time.sleep') as time_sleep:
                conf = mock.Mock()
                conf.force = False
                methods_to_mock = dict(
                    eligible_for_deletion=mock.DEFAULT,
                    destroy_namespace=mock.DEFAULT,
                    setup_conf=mock.DEFAULT)

                with mock.patch.multiple(util, **methods_to_mock) as mocks:
                    mocks['eligible_for_deletion'].return_value = False
                    mocks['setup_conf'].return_value = conf
                    with mock.patch('neutron.common.config.setup_logging'):
                        util.main()

                        self.assertEqual(1, listnetns.call_count)

                        mocks['eligible_for_deletion'].assert_has_calls(
                            [mock.call(conf, 'ns1', False),
                             mock.call(conf, 'ns2', False)])

                        self.assertFalse(mocks['destroy_namespace'].called)

                        self.assertFalse(time_sleep.called)
