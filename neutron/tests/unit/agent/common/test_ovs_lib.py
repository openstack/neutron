# Copyright 2012, VMware, Inc.
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

import mock
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import tenacity
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.conf.agent import common as config
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as p_const
from neutron.tests import base
from neutron.tests import tools


OVS_LINUX_KERN_VERS_WITHOUT_VXLAN = "3.12.0"

# some test data for get_vif_port_to_ofport_map that exhibited bug 1444269
OVSLIST_WITH_UNSET_PORT = (
    '{"data":[["patch-tun",["map",[]],1],["tap2ab72a72-44",["map",[["attached-'
    'mac","fa:16:3e:b0:f8:38"],["iface-id","2ab72a72-4407-4ef3-806a-b2172f3e4d'
    'c7"],["iface-status","active"]]],2],["tap6b108774-15",["map",[["attached-'
    'mac","fa:16:3e:02:f5:91"],["iface-id","6b108774-1559-45e9-a7c3-b714f11722'
    'cf"],["iface-status","active"]]],["set",[]]]],"headings":["name","externa'
    'l_ids","ofport"]}')


class OFCTLParamListMatcher(object):

    def _parse(self, params):
        actions_pos = params.find('actions')
        return set(params[:actions_pos].split(',')), params[actions_pos:]

    def __init__(self, params):
        self.expected = self._parse(params)

    def __eq__(self, other):
        return self.expected == self._parse(other)

    def __str__(self):
        return 'ovs-ofctl parameters: %s, "%s"' % self.expected

    __repr__ = __str__


class StringSetMatcher(object):
    """A helper object for unordered CSV strings

    Will compare equal if both strings, when read as a comma-separated set
    of values, represent the same set.

    Example: "a,b,45" == "b,45,a"
    """
    def __init__(self, string, separator=','):
        self.separator = separator
        self.set = set(string.split(self.separator))

    def __eq__(self, other):
        return self.set == set(other.split(self.separator))

    def __ne__(self, other):
        return self.set != set(other.split(self.separator))

    def __repr__(self):
        sep = '' if self.separator == ',' else " on %s" % self.separator
        return '<comma-separated string for %s%s>' % (self.set, sep)


def vsctl_only(f):
    # NOTE(ivasilevskaya) as long as some tests rely heavily on mocking
    # direct vsctl commands, need to ensure that ovsdb_interface = 'vsctl'
    # TODO(ivasilevskaya) introduce alternative tests for native interface?
    def wrapper(*args, **kwargs):
        config.cfg.CONF.set_override("ovsdb_interface", "vsctl", group="OVS")
        return f(*args, **kwargs)
    return wrapper


class OVS_Lib_Test(base.BaseTestCase):
    """A test suite to exercise the OVS libraries shared by Neutron agents.

    Note: these tests do not actually execute ovs-* utilities, and thus
    can run on any system.  That does, however, limit their scope.
    """

    @vsctl_only
    def setUp(self):
        super(OVS_Lib_Test, self).setUp()
        self.BR_NAME = "br-int"

        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        self.execute = mock.patch.object(
            utils, "execute", spec=utils.execute).start()

    @property
    def TO(self):
        return "--timeout=%s" % self.br.vsctl_timeout

    def _vsctl_args(self, *args):
        cmd = ['ovs-vsctl', self.TO, '--oneline', '--format=json', '--']
        cmd += args
        return cmd

    def _vsctl_mock(self, *args):
        cmd = self._vsctl_args(*args)
        return mock.call(cmd, run_as_root=True, log_fail_as_error=False)

    def _verify_vsctl_mock(self, *args):
        cmd = self._vsctl_args(*args)
        self.execute.assert_called_once_with(cmd, run_as_root=True,
                                             log_fail_as_error=False)

    def test_vifport(self):
        """Create and stringify vif port, confirm no exceptions."""

        pname = "vif1.0"
        ofport = 5
        vif_id = uuidutils.generate_uuid()
        mac = "ca:fe:de:ad:be:ef"

        # test __init__
        port = ovs_lib.VifPort(pname, ofport, vif_id, mac, self.br)
        self.assertEqual(port.port_name, pname)
        self.assertEqual(port.ofport, ofport)
        self.assertEqual(port.vif_id, vif_id)
        self.assertEqual(port.vif_mac, mac)
        self.assertEqual(port.switch.br_name, self.BR_NAME)

        # test __str__
        str(port)

    def _build_timeout_opt(self, exp_timeout):
        return "--timeout=%d" % exp_timeout if exp_timeout else self.TO

    def test_add_flow(self):
        ofport = "99"
        vid = 4000
        lsw_id = 18
        cidr = '192.168.1.0/24'

        flow_dict_1 = collections.OrderedDict([
            ('cookie', 1234),
            ('priority', 2),
            ('dl_src', 'ca:fe:de:ad:be:ef'),
            ('actions', 'strip_vlan,output:0')])
        flow_dict_2 = collections.OrderedDict([
            ('cookie', 1254),
            ('priority', 1),
            ('actions', 'normal')])
        flow_dict_3 = collections.OrderedDict([
            ('cookie', 1257),
            ('priority', 2),
            ('actions', 'drop')])
        flow_dict_4 = collections.OrderedDict([
            ('cookie', 1274),
            ('priority', 2),
            ('in_port', ofport),
            ('actions', 'drop')])
        flow_dict_5 = collections.OrderedDict([
            ('cookie', 1284),
            ('priority', 4),
            ('in_port', ofport),
            ('dl_vlan', vid),
            ('actions', "strip_vlan,set_tunnel:%s,normal" % (lsw_id))])
        flow_dict_6 = collections.OrderedDict([
            ('cookie', 1754),
            ('priority', 3),
            ('tun_id', lsw_id),
            ('actions', "mod_vlan_vid:%s,output:%s" % (vid, ofport))])
        flow_dict_7 = collections.OrderedDict([
            ('cookie', 1256),
            ('priority', 4),
            ('nw_src', cidr),
            ('proto', 'arp'),
            ('actions', 'drop')])

        self.br.add_flow(**flow_dict_1)
        self.br.add_flow(**flow_dict_2)
        self.br.add_flow(**flow_dict_3)
        self.br.add_flow(**flow_dict_4)
        self.br.add_flow(**flow_dict_5)
        self.br.add_flow(**flow_dict_6)
        self.br.add_flow(**flow_dict_7)
        expected_calls = [
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1234,"
                                 "priority=2,dl_src=ca:fe:de:ad:be:ef,"
                                 "actions=strip_vlan,output:0")),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1254,"
                                 "priority=1,actions=normal")),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1257,"
                                 "priority=2,actions=drop")),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1274,"
                                 "priority=2,in_port=%s,actions=drop" % ofport
                             )),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1284,"
                                 "priority=4,dl_vlan=%s,in_port=%s,"
                                 "actions=strip_vlan,set_tunnel:%s,normal" %
                                 (vid, ofport, lsw_id))),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1754,"
                                 "priority=3,"
                                 "tun_id=%s,actions=mod_vlan_vid:%s,output:%s"
                                 % (lsw_id, vid, ofport))),
            self._ofctl_mock("add-flows", self.BR_NAME, '-',
                             process_input=OFCTLParamListMatcher(
                                 "hard_timeout=0,idle_timeout=0,cookie=1256,"
                                 "priority=4,nw_src=%s,arp,actions=drop"
                                 % cidr)),
        ]
        self.execute.assert_has_calls(expected_calls)

    def _ofctl_args(self, cmd, *args):
        cmd = ['ovs-ofctl', cmd, '-O', self.br._highest_protocol_needed]
        cmd += args
        return cmd

    def _ofctl_mock(self, cmd, *args, **kwargs):
        cmd = self._ofctl_args(cmd, *args)
        return mock.call(cmd, run_as_root=True, **kwargs)

    def _verify_ofctl_mock(self, cmd, *args, **kwargs):
        cmd = self._ofctl_args(cmd, *args)
        return self.execute.assert_called_once_with(cmd, run_as_root=True,
                                                    **kwargs)

    def test_add_flow_timeout_set(self):
        flow_dict = collections.OrderedDict([
            ('cookie', 1234),
            ('priority', 1),
            ('hard_timeout', 1000),
            ('idle_timeout', 2000),
            ('actions', 'normal')])

        self.br.add_flow(**flow_dict)
        self._verify_ofctl_mock(
            "add-flows", self.BR_NAME, '-',
            process_input="hard_timeout=1000,idle_timeout=2000,"
                          "priority=1,cookie=1234,actions=normal")

    def test_add_flow_default_priority(self):
        flow_dict = collections.OrderedDict([('actions', 'normal'),
                                             ('cookie', 1234)])

        self.br.add_flow(**flow_dict)
        self._verify_ofctl_mock(
            "add-flows", self.BR_NAME, '-',
            process_input="hard_timeout=0,idle_timeout=0,priority=1,"
                          "cookie=1234,actions=normal")

    def _test_get_port_ofport(self, ofport, expected_result):
        pname = "tap99"
        self.br.vsctl_timeout = 0  # Don't waste precious time retrying
        self.execute.return_value = self._encode_ovs_json(
            ['ofport'], [[ofport]])
        self.assertEqual(self.br.get_port_ofport(pname), expected_result)
        self._verify_vsctl_mock("--columns=ofport", "list", "Interface", pname)

    def test_get_port_ofport_succeeds_for_valid_ofport(self):
        self._test_get_port_ofport(6, 6)

    def test_get_port_ofport_returns_invalid_ofport_for_non_int(self):
        self._test_get_port_ofport([], ovs_lib.INVALID_OFPORT)

    def test_get_port_ofport_returns_invalid_for_invalid(self):
        self._test_get_port_ofport(ovs_lib.INVALID_OFPORT,
                                   ovs_lib.INVALID_OFPORT)

    def test_get_port_mac(self):
        pname = "tap99"
        self.br.vsctl_timeout = 0  # Don't waste precious time retrying
        self.execute.return_value = self._encode_ovs_json(
            ['mac_in_use'], [['00:01:02:03:04:05']])
        expected_result = '00:01:02:03:04:05'
        self.assertEqual(self.br.get_port_mac(pname), expected_result)

    def test_default_datapath(self):
        # verify kernel datapath is default
        expected = p_const.OVS_DATAPATH_SYSTEM
        self.assertEqual(expected, self.br.datapath_type)

    def test_non_default_datapath(self):
        expected = p_const.OVS_DATAPATH_NETDEV
        self.br = ovs_lib.OVSBridge(self.BR_NAME, datapath_type=expected)
        br2 = self.br.add_bridge('another-br', datapath_type=expected)
        self.assertEqual(expected, self.br.datapath_type)
        self.assertEqual(expected, br2.datapath_type)

    def test_count_flows(self):
        self.execute.return_value = 'ignore\nflow-1\n'
        # counts the number of flows as total lines of output - 2
        self.assertEqual(self.br.count_flows(), 1)
        self._verify_ofctl_mock("dump-flows", self.BR_NAME, process_input=None)

    def test_delete_flow(self):
        ofport = 5
        lsw_id = 40
        vid = 39
        self.br.delete_flows(in_port=ofport)
        self.br.delete_flows(tun_id=lsw_id)
        self.br.delete_flows(dl_vlan=vid)
        self.br.delete_flows()
        cookie_spec = "cookie=%s/-1" % self.br._default_cookie
        expected_calls = [
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input=StringSetMatcher(
                                 "%s,in_port=%d" % (cookie_spec, ofport))),
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input=StringSetMatcher(
                                 "%s,tun_id=%s" % (cookie_spec, lsw_id))),
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input=StringSetMatcher(
                                 "%s,dl_vlan=%s" % (cookie_spec, vid))),
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input="%s" % cookie_spec),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_delete_flows_cookie_nomask(self):
        self.br.delete_flows(cookie=42)
        self.execute.assert_has_calls([
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input="cookie=42/-1"),
        ])

    def test_do_action_flows_delete_flows(self):
        # test what the deferred bridge implementation calls, in the case of a
        # delete_flows(cookie=ovs_lib.COOKIE_ANY) among calls to
        # delete_flows(foo=bar)
        self.br.do_action_flows('del', [{'in_port': 5},
                                        {'cookie': ovs_lib.COOKIE_ANY}])
        expected_calls = [
            self._ofctl_mock("del-flows", self.BR_NAME,
                             process_input=None),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_delete_flows_any_cookie(self):
        self.br.delete_flows(in_port=5, cookie=ovs_lib.COOKIE_ANY)
        self.br.delete_flows(cookie=ovs_lib.COOKIE_ANY)
        expected_calls = [
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input="in_port=5"),
            self._ofctl_mock("del-flows", self.BR_NAME,
                             process_input=None),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_mod_delete_flows_strict(self):
        self.br.delete_flows(in_port=5, priority=1, strict=True)
        self.br.mod_flow(in_port=5, priority=1, strict=True, actions='drop')
        cookie_spec = "cookie=%s" % self.br._default_cookie
        expected_calls = [
            self._ofctl_mock("del-flows", self.BR_NAME, '--strict', '-',
                             process_input=StringSetMatcher(
                                 "%s/-1,in_port=5,priority=1" % cookie_spec)),
            self._ofctl_mock("mod-flows", self.BR_NAME, '--strict', '-',
                             process_input=StringSetMatcher(
                                 "%s,in_port=5,priority=1,actions=drop" %
                                 cookie_spec)),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_mod_delete_flows_priority_without_strict(self):
        self.assertRaises(exceptions.InvalidInput,
                          self.br.delete_flows,
                          in_port=5, priority=1)

    def test_mod_delete_flows_mixed_strict(self):
        deferred_br = self.br.deferred()
        deferred_br.delete_flows(in_port=5)
        deferred_br.delete_flows(in_port=5, priority=1, strict=True)
        self.assertRaises(exceptions.InvalidInput,
                          deferred_br.apply_flows)

    def test_dump_flows(self):
        table = 23
        nxst_flow = "NXST_FLOW reply (xid=0x4):"
        flows = "\n".join([" cookie=0x0, duration=18042.514s, table=0, "
                           "n_packets=6, n_bytes=468, "
                           "priority=2,in_port=1 actions=drop",
                           " cookie=0x0, duration=18027.562s, table=0, "
                           "n_packets=0, n_bytes=0, "
                           "priority=3,in_port=1,dl_vlan=100 "
                           "actions=mod_vlan_vid:1,NORMAL",
                           " cookie=0x0, duration=18044.351s, table=0, "
                           "n_packets=9, n_bytes=594, priority=1 "
                           "actions=NORMAL", " cookie=0x0, "
                           "duration=18044.211s, table=23, n_packets=0, "
                           "n_bytes=0, priority=0 actions=drop"])
        flow_args = '\n'.join([nxst_flow, flows])
        run_ofctl = mock.patch.object(self.br, 'run_ofctl').start()
        run_ofctl.side_effect = [flow_args]
        retflows = self.br.dump_flows_for_table(table)
        self.assertEqual(flows, retflows)

    def test_dump_flows_ovs_dead(self):
        table = 23
        run_ofctl = mock.patch.object(self.br, 'run_ofctl').start()
        run_ofctl.side_effect = ['']
        retflows = self.br.dump_flows_for_table(table)
        self.assertIsNone(retflows)

    def test_mod_flow_with_priority_set(self):
        params = {'in_port': '1',
                  'priority': '1'}

        self.assertRaises(exceptions.InvalidInput,
                          self.br.mod_flow,
                          **params)

    def test_mod_flow_no_actions_set(self):
        params = {'in_port': '1'}

        self.assertRaises(exceptions.InvalidInput,
                          self.br.mod_flow,
                          **params)

    def test_ofctl_of_version_use_highest(self):
        self.br.add_flow(in_port=1, actions="drop")
        self.execute.assert_has_calls([
            mock.call(['ovs-ofctl', 'add-flows', '-O', p_const.OPENFLOW10,
                       mock.ANY, '-'], process_input=mock.ANY,
                      run_as_root=mock.ANY)
        ])
        self.br.use_at_least_protocol(p_const.OPENFLOW12)
        self.execute.reset_mock()
        self.br.add_flow(in_port=1, actions="drop")
        self.execute.assert_has_calls([
            mock.call(['ovs-ofctl', 'add-flows', '-O', p_const.OPENFLOW12,
                       mock.ANY, '-'], process_input=mock.ANY,
                      run_as_root=mock.ANY),
        ])

    def test_ofctl_of_version_keep_highest(self):
        self.br.use_at_least_protocol(p_const.OPENFLOW13)
        self.br.use_at_least_protocol(p_const.OPENFLOW12)
        self.execute.reset_mock()
        self.br.add_flow(in_port=1, actions="drop")
        self.execute.assert_has_calls([
            mock.call(['ovs-ofctl', 'add-flows', '-O', p_const.OPENFLOW13,
                       mock.ANY, '-'], process_input=mock.ANY,
                      run_as_root=mock.ANY),
        ])

    def test_ofctl_of_version_use_unknown(self):
        with testtools.ExpectedException(Exception):
            self.br.use_at_least_protocol("OpenFlow42")

    def test_run_ofctl_retry_on_socket_error(self):
        err = RuntimeError('failed to connect to socket')
        self.execute.side_effect = [err] * 5
        with mock.patch('time.sleep') as sleep:
            self.br.run_ofctl('add-flows', [])
        self.assertEqual(5, sleep.call_count)
        self.assertEqual(6, self.execute.call_count)
        # a regular exception fails right away
        self.execute.side_effect = RuntimeError('garbage')
        self.execute.reset_mock()
        with mock.patch('time.sleep') as sleep:
            self.br.run_ofctl('add-flows', [])
        self.assertEqual(0, sleep.call_count)
        self.assertEqual(1, self.execute.call_count)

    def test_add_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = 6
        command = ["--may-exist", "add-port",
                   self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=gre", "options:df_default=true",
                        "options:remote_ip=" + remote_ip,
                        "options:local_ip=" + local_ip,
                        "options:in_key=flow",
                        "options:out_key=flow"])
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock(*command), None),
            (self._vsctl_mock("--columns=ofport", "list", "Interface", pname),
             self._encode_ovs_json(['ofport'], [[ofport]])),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip),
            ofport)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_add_vxlan_fragmented_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = 6
        vxlan_udp_port = "9999"
        dont_fragment = False
        command = ["--may-exist", "add-port", self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=" + constants.TYPE_VXLAN,
                        "options:dst_port=" + vxlan_udp_port,
                        "options:df_default=false",
                        "options:remote_ip=" + remote_ip,
                        "options:local_ip=" + local_ip,
                        "options:in_key=flow",
                        "options:out_key=flow"])
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock(*command), None),
            (self._vsctl_mock("--columns=ofport", "list", "Interface", pname),
             self._encode_ovs_json(['ofport'], [[ofport]])),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip,
                                    constants.TYPE_VXLAN, vxlan_udp_port,
                                    dont_fragment),
            ofport)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_add_vxlan_csum_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = 6
        vxlan_udp_port = "9999"
        dont_fragment = True
        tunnel_csum = True
        command = ["--may-exist", "add-port", self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=" + constants.TYPE_VXLAN,
                        "options:dst_port=" + vxlan_udp_port,
                        "options:df_default=true",
                        "options:remote_ip=" + remote_ip,
                        "options:local_ip=" + local_ip,
                        "options:in_key=flow",
                        "options:out_key=flow",
                        "options:csum=true"])
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock(*command), None),
            (self._vsctl_mock("--columns=ofport", "list", "Interface", pname),
             self._encode_ovs_json(['ofport'], [[ofport]])),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip,
                                    constants.TYPE_VXLAN, vxlan_udp_port,
                                    dont_fragment, tunnel_csum),
            ofport)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_add_vxlan_tos_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = 6
        vxlan_udp_port = "9999"
        dont_fragment = True
        tunnel_csum = False
        tos = 8
        command = ["--may-exist", "add-port", self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=" + constants.TYPE_VXLAN,
                        "options:dst_port=" + vxlan_udp_port,
                        "options:df_default=true",
                        "options:remote_ip=" + remote_ip,
                        "options:local_ip=" + local_ip,
                        "options:in_key=flow",
                        "options:out_key=flow",
                        "options:tos=" + str(tos)])
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock(*command), None),
            (self._vsctl_mock("--columns=ofport", "list", "Interface", pname),
             self._encode_ovs_json(['ofport'], [[ofport]])),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip,
                                    constants.TYPE_VXLAN, vxlan_udp_port,
                                    dont_fragment, tunnel_csum, tos),
            ofport)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def _encode_ovs_json(self, headings, data):
        # See man ovs-vsctl(8) for the encoding details.
        r = {"data": [],
             "headings": headings}
        for row in data:
            ovs_row = []
            r["data"].append(ovs_row)
            for cell in row:
                if isinstance(cell, (str, int, list)):
                    ovs_row.append(cell)
                elif isinstance(cell, dict):
                    ovs_row.append(["map", cell.items()])
                elif isinstance(cell, set):
                    ovs_row.append(["set", cell])
                else:
                    raise TypeError('%r not int, str, list, set or dict' %
                                    type(cell))
        return jsonutils.dumps(r)

    def test_get_vif_port_to_ofport_map(self):
        self.execute.return_value = OVSLIST_WITH_UNSET_PORT
        results = self.br.get_vif_port_to_ofport_map()
        expected = {'2ab72a72-4407-4ef3-806a-b2172f3e4dc7': 2, 'patch-tun': 1}
        self.assertEqual(expected, results)

    def test_get_vif_ports(self):
        pname = "tap99"
        ofport = 6
        vif_id = uuidutils.generate_uuid()
        mac = "ca:fe:de:ad:be:ef"
        id_field = 'iface-id'
        external_ids = {"attached-mac": mac, id_field: vif_id}
        self.br.get_ports_attributes = mock.Mock(return_value=[{
            'name': pname, 'ofport': ofport, 'external_ids': external_ids}])

        ports = self.br.get_vif_ports()
        self.assertEqual(1, len(ports))
        self.assertEqual(ports[0].port_name, pname)
        self.assertEqual(ports[0].ofport, ofport)
        self.assertEqual(ports[0].vif_id, vif_id)
        self.assertEqual(ports[0].vif_mac, mac)
        self.assertEqual(ports[0].switch.br_name, self.BR_NAME)
        self.br.get_ports_attributes.assert_called_once_with(
            'Interface',
            columns=['name', 'external_ids', 'ofport'],
            if_exists=True)

    def test_get_vif_port_set(self):
        id_key = 'iface-id'
        headings = ['name', 'external_ids', 'ofport']
        data = [
            # A vif port on this bridge:
            ['tap99', {id_key: 'tap99id', 'attached-mac': 'tap99mac'}, 1],
            # A vif port on this bridge not yet configured
            ['tap98', {id_key: 'tap98id', 'attached-mac': 'tap98mac'}, []],
            # Another vif port on this bridge not yet configured
            ['tap97', {id_key: 'tap97id', 'attached-mac': 'tap97mac'},
             ['set', []]],

            # Non-vif port on this bridge:
            ['bogus', {}, 2],
        ]

        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME), 'tap99\\ntun22'),
            (self._vsctl_mock("--if-exists",
                              "--columns=name,external_ids,ofport",
                              "list", "Interface", 'tap99', 'tun22'),
             self._encode_ovs_json(headings, data)),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        port_set = self.br.get_vif_port_set()
        self.assertEqual(set(['tap99id']), port_set)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_vif_ports_list_ports_error(self):
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME), RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.get_vif_ports)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_vif_port_set_list_ports_error(self):
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME), RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.get_vif_port_set)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_vif_port_set_list_interface_error(self):
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME), 'tap99\n'),
            (self._vsctl_mock("--if-exists",
                              "--columns=name,external_ids,ofport",
                              "list", "Interface", "tap99"), RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.get_vif_port_set)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_port_tag_dict(self):
        headings = ['name', 'tag']
        data = [
            ['int-br-eth2', set()],
            ['patch-tun', set()],
            ['qr-76d9e6b6-21', 1],
            ['tapce5318ff-78', 1],
            ['tape1400310-e6', 1],
        ]

        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME),
             '\\n'.join((iface for iface, tag in data))),
            (self._vsctl_mock("--columns=name,tag", "list", "Port"),
             self._encode_ovs_json(headings, data)),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        port_tags = self.br.get_port_tag_dict()
        self.assertEqual(
            port_tags,
            {u'int-br-eth2': [],
             u'patch-tun': [],
             u'qr-76d9e6b6-21': 1,
             u'tapce5318ff-78': 1,
             u'tape1400310-e6': 1}
        )

    def test_clear_db_attribute(self):
        pname = "tap77"
        self.br.clear_db_attribute("Port", pname, "tag")
        self._verify_vsctl_mock("clear", "Port", pname, "tag")

    def _test_iface_to_br(self, exp_timeout=None):
        iface = 'tap0'
        br = 'br-int'
        if exp_timeout:
            self.br.vsctl_timeout = exp_timeout
        self.execute.return_value = 'br-int'
        self.assertEqual(self.br.get_bridge_for_iface(iface), br)
        self._verify_vsctl_mock("iface-to-br", iface)

    def test_iface_to_br(self):
        self._test_iface_to_br()

    def test_iface_to_br_non_default_timeout(self):
        new_timeout = 5
        self._test_iface_to_br(new_timeout)

    def test_iface_to_br_handles_ovs_vsctl_exception(self):
        iface = 'tap0'
        self.execute.side_effect = Exception

        self.assertIsNone(self.br.get_bridge_for_iface(iface))
        self._verify_vsctl_mock("iface-to-br", iface)

    def test_delete_all_ports(self):
        with mock.patch.object(self.br, 'get_port_name_list',
                               return_value=['port1']) as get_port:
            with mock.patch.object(self.br, 'delete_port') as delete_port:
                self.br.delete_ports(all_ports=True)
        get_port.assert_called_once_with()
        delete_port.assert_called_once_with('port1')

    def test_delete_neutron_ports(self):
        port1 = ovs_lib.VifPort('tap1234', 1, uuidutils.generate_uuid(),
                                'ca:fe:de:ad:be:ef', 'br')
        port2 = ovs_lib.VifPort('tap5678', 2, uuidutils.generate_uuid(),
                                'ca:ee:de:ad:be:ef', 'br')
        with mock.patch.object(self.br, 'get_vif_ports',
                               return_value=[port1, port2]) as get_ports:
            with mock.patch.object(self.br, 'delete_port') as delete_port:
                self.br.delete_ports(all_ports=False)
        get_ports.assert_called_once_with()
        delete_port.assert_has_calls([
            mock.call('tap1234'),
            mock.call('tap5678')
        ])

    def test_delete_neutron_ports_list_error(self):
        expected_calls_and_values = [
            (self._vsctl_mock("list-ports", self.BR_NAME), RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.delete_ports, all_ports=False)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_bridges_not_default_timeout(self):
        bridges = ['br-int', 'br-ex']
        self.br.vsctl_timeout = 5
        self.execute.return_value = 'br-int\\nbr-ex\n'
        self.assertEqual(self.br.get_bridges(), bridges)
        self._verify_vsctl_mock("list-br")

    def test_get_local_port_mac_succeeds(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address='foo')):
            self.assertEqual('foo', self.br.get_local_port_mac())

    def test_get_local_port_mac_raises_exception_for_missing_mac(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address=None)):
            with testtools.ExpectedException(Exception):
                self.br.get_local_port_mac()

    def test_delete_egress_bw_limit_for_port(self):
        with mock.patch.object(
            self.br, "_set_egress_bw_limit_for_port"
        ) as set_egress_mock, mock.patch.object(
            self.br, "port_exists", return_value=True
        ) as port_exists_mock:
            self.br.delete_egress_bw_limit_for_port("test_port")
            port_exists_mock.assert_called_once_with("test_port")
            set_egress_mock.assert_called_once_with("test_port", 0, 0)

    def test_delete_egress_bw_limit_for_port_port_not_exists(self):
        with mock.patch.object(
            self.br, "_set_egress_bw_limit_for_port"
        ) as set_egress_mock, mock.patch.object(
            self.br, "port_exists", return_value=False
        ) as port_exists_mock:
            self.br.delete_egress_bw_limit_for_port("test_port")
            port_exists_mock.assert_called_once_with("test_port")
            set_egress_mock.assert_not_called()

    def test_get_vifs_by_ids(self):
        db_list_res = [
            {'name': 'qvo1', 'ofport': 1,
             'external_ids': {'iface-id': 'pid1', 'attached-mac': '11'}},
            {'name': 'qvo2', 'ofport': 2,
             'external_ids': {'iface-id': 'pid2', 'attached-mac': '22'}},
            {'name': 'qvo4', 'ofport': -1,
             'external_ids': {'iface-id': 'pid4', 'attached-mac': '44'}},
        ]
        self.br.get_ports_attributes = mock.Mock(return_value=db_list_res)
        self.br.ovsdb = mock.Mock()
        self.br.ovsdb.list_ports.return_value.execute.return_value = [
            'qvo1', 'qvo2', 'qvo4']
        by_id = self.br.get_vifs_by_ids(['pid1', 'pid2', 'pid3', 'pid4'])
        # pid3 isn't on bridge and pid4 doesn't have a valid ofport
        self.assertIsNone(by_id['pid3'])
        self.assertIsNone(by_id['pid4'])
        self.assertEqual('pid1', by_id['pid1'].vif_id)
        self.assertEqual('qvo1', by_id['pid1'].port_name)
        self.assertEqual(1, by_id['pid1'].ofport)
        self.assertEqual('pid2', by_id['pid2'].vif_id)
        self.assertEqual('qvo2', by_id['pid2'].port_name)
        self.assertEqual(2, by_id['pid2'].ofport)
        self.br.get_ports_attributes.assert_has_calls(
            [mock.call('Interface', columns=['name', 'external_ids', 'ofport'],
                       if_exists=True)])

    def _test_get_vif_port_by_id(self, iface_id, data, br_name=None,
                                 extra_calls_and_values=None):
        headings = ['external_ids', 'name', 'ofport']

        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (self._vsctl_mock("--columns=external_ids,name,ofport", "find",
                              "Interface",
                              'external_ids:iface-id=%s' % iface_id,
                              'external_ids:attached-mac!=""'),
             self._encode_ovs_json(headings, data))]
        if data:
            if not br_name:
                br_name = self.BR_NAME

            # Only the last information list in 'data' is used, so if more
            # than one vif is described in data, the rest must be declared
            # in the argument 'expected_calls_and_values'.
            if extra_calls_and_values:
                expected_calls_and_values.extend(extra_calls_and_values)

            expected_calls_and_values.append(
                (self._vsctl_mock("iface-to-br",
                                  data[-1][headings.index('name')]), br_name))
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        vif_port = self.br.get_vif_port_by_id(iface_id)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)
        return vif_port

    def _assert_vif_port(self, vif_port, ofport=None, mac=None):
        if not ofport or ofport == -1 or not mac:
            self.assertIsNone(vif_port, "Got %s" % vif_port)
            return
        self.assertEqual('tap99id', vif_port.vif_id)
        self.assertEqual(mac, vif_port.vif_mac)
        self.assertEqual('tap99', vif_port.port_name)
        self.assertEqual(ofport, vif_port.ofport)

    def _test_get_vif_port_by_id_with_data(self, ofport=None, mac=None):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"],
                        ["attached-mac", mac]]
        data = [[["map", external_ids], "tap99",
                 ofport if ofport else ["set", []]]]
        vif_port = self._test_get_vif_port_by_id('tap99id', data)
        self._assert_vif_port(vif_port, ofport, mac)

    def test_get_vif_by_port_id_with_ofport(self):
        self._test_get_vif_port_by_id_with_data(
            ofport=1, mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_without_ofport(self):
        self._test_get_vif_port_by_id_with_data(mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_with_invalid_ofport(self):
        self._test_get_vif_port_by_id_with_data(
            ofport=-1, mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_with_no_data(self):
        self.assertIsNone(self._test_get_vif_port_by_id('whatever', []))

    def test_get_vif_by_port_id_different_bridge(self):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"]]
        data = [[["map", external_ids], "tap99", 1]]
        self.assertIsNone(self._test_get_vif_port_by_id('tap99id', data,
                                                        "br-ext"))

    def test_get_vif_by_port_id_multiple_vifs(self):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"],
                        ["attached-mac", "de:ad:be:ef:13:37"]]
        data = [[["map", external_ids], "dummytap", 1],
                [["map", external_ids], "tap99", 1337]]
        extra_calls_and_values = [
            (self._vsctl_mock("iface-to-br", "dummytap"), "br-ext")]

        vif_port = self._test_get_vif_port_by_id(
            'tap99id', data, extra_calls_and_values=extra_calls_and_values)
        self._assert_vif_port(vif_port, ofport=1337, mac="de:ad:be:ef:13:37")

    def test_get_port_ofport_retry(self):
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[], [], [], [], 1]):
            self.assertEqual(1, self.br._get_port_val('1', 'ofport'))

    def test_get_port_ofport_retry_fails(self):
        # reduce timeout for faster execution
        self.br.vsctl_timeout = 1
        # after 7 calls the retry will timeout and raise
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[] for _ in range(7)]):
            self.assertRaises(tenacity.RetryError,
                              self.br._get_port_val, '1', 'ofport')

    def test_get_port_external_ids_retry(self):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"],
                        ["attached-mac", "de:ad:be:ef:13:37"]]
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[], [], [], [], external_ids]):
            self.assertEqual(external_ids,
                             self.br._get_port_val('1', 'external_ids'))

    def test_get_port_external_ids_retry_fails(self):
        # reduce timeout for faster execution
        self.br.vsctl_timeout = 1
        # after 7 calls the retry will timeout and raise
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[] for _ in range(7)]):
            self.assertRaises(tenacity.RetryError,
                              self.br._get_port_val, '1', 'external_ids')

    def test_set_controller_rate_limit(self):
        with mock.patch.object(
                self.br, "set_controller_field"
        ) as set_ctrl_field_mock:
            self.br.set_controller_rate_limit(200)
            set_ctrl_field_mock.assert_called_once_with(
                'controller_rate_limit', 200)

    def test_set_controller_rate_limit_with_value_less_than_min(self):
        with mock.patch.object(
                self.br, "set_controller_field"
        ) as set_ctrl_field_mock:
            self.br.set_controller_rate_limit(50)
            set_ctrl_field_mock.assert_called_once_with(
                'controller_rate_limit', ovs_lib.CTRL_RATE_LIMIT_MIN)

    def test_set_controller_burst_limit(self):
        with mock.patch.object(
                self.br, "set_controller_field"
        ) as set_ctrl_field_mock:
            self.br.set_controller_burst_limit(100)
            set_ctrl_field_mock.assert_called_once_with(
                'controller_burst_limit', 100)

    def test_set_controller_burst_limit_with_value_less_than_min(self):
        with mock.patch.object(
                self.br, "set_controller_field"
        ) as set_ctrl_field_mock:
            self.br.set_controller_burst_limit(10)
            set_ctrl_field_mock.assert_called_once_with(
                'controller_burst_limit', ovs_lib.CTRL_BURST_LIMIT_MIN)


class TestDeferredOVSBridge(base.BaseTestCase):

    def setUp(self):
        super(TestDeferredOVSBridge, self).setUp()

        self.br = mock.Mock()
        self.mocked_do_action_flows = mock.patch.object(
            self.br, 'do_action_flows').start()

        self.add_flow_dict1 = dict(in_port=11, actions='drop')
        self.add_flow_dict2 = dict(in_port=12, actions='drop')
        self.mod_flow_dict1 = dict(in_port=21, actions='drop')
        self.mod_flow_dict2 = dict(in_port=22, actions='drop')
        self.del_flow_dict1 = dict(in_port=31)
        self.del_flow_dict2 = dict(in_port=32)

    def test_right_allowed_passthroughs(self):
        expected_passthroughs = ('add_port', 'add_tunnel_port', 'delete_port')
        self.assertEqual(expected_passthroughs,
                         ovs_lib.DeferredOVSBridge.ALLOWED_PASSTHROUGHS)

    def _verify_mock_call(self, expected_calls):
        self.mocked_do_action_flows.assert_has_calls(expected_calls)
        self.assertEqual(len(expected_calls),
                         len(self.mocked_do_action_flows.mock_calls))

    def test_apply_on_exit(self):
        expected_calls = [
            mock.call('add', [self.add_flow_dict1], False),
            mock.call('mod', [self.mod_flow_dict1], False),
            mock.call('del', [self.del_flow_dict1], False),
        ]

        with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
            deferred_br.add_flow(**self.add_flow_dict1)
            deferred_br.mod_flow(**self.mod_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict1)
            self._verify_mock_call([])
        self._verify_mock_call(expected_calls)

    def test_apply_on_exit_with_errors(self):
        try:
            with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
                deferred_br.add_flow(**self.add_flow_dict1)
                deferred_br.mod_flow(**self.mod_flow_dict1)
                deferred_br.delete_flows(**self.del_flow_dict1)
                raise Exception()
        except Exception:
            self._verify_mock_call([])
        else:
            self.fail('Exception would be reraised')

    def test_apply(self):
        expected_calls = [
            mock.call('add', [self.add_flow_dict1], False),
            mock.call('mod', [self.mod_flow_dict1], False),
            mock.call('del', [self.del_flow_dict1], False),
        ]

        with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
            deferred_br.add_flow(**self.add_flow_dict1)
            deferred_br.mod_flow(**self.mod_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict1)
            self._verify_mock_call([])
            deferred_br.apply_flows()
            self._verify_mock_call(expected_calls)
        self._verify_mock_call(expected_calls)

    def test_apply_order(self):
        expected_calls = [
            mock.call(
                'del', [self.del_flow_dict1, self.del_flow_dict2], False),
            mock.call(
                'mod', [self.mod_flow_dict1, self.mod_flow_dict2], False),
            mock.call(
                'add', [self.add_flow_dict1, self.add_flow_dict2], False),
        ]

        order = 'del', 'mod', 'add'
        with ovs_lib.DeferredOVSBridge(self.br, order=order) as deferred_br:
            deferred_br.add_flow(**self.add_flow_dict1)
            deferred_br.mod_flow(**self.mod_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict2)
            deferred_br.add_flow(**self.add_flow_dict2)
            deferred_br.mod_flow(**self.mod_flow_dict2)
        self._verify_mock_call(expected_calls)

    def test_apply_full_ordered(self):
        expected_calls = [
            mock.call('add', [self.add_flow_dict1], False),
            mock.call('mod', [self.mod_flow_dict1], False),
            mock.call(
                'del', [self.del_flow_dict1, self.del_flow_dict2], False),
            mock.call('add', [self.add_flow_dict2], False),
            mock.call('mod', [self.mod_flow_dict2], False),
        ]

        with ovs_lib.DeferredOVSBridge(self.br,
                                       full_ordered=True) as deferred_br:
            deferred_br.add_flow(**self.add_flow_dict1)
            deferred_br.mod_flow(**self.mod_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict2)
            deferred_br.add_flow(**self.add_flow_dict2)
            deferred_br.mod_flow(**self.mod_flow_dict2)
        self._verify_mock_call(expected_calls)

    def test_getattr_unallowed_attr(self):
        with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
            self.assertEqual(self.br.add_port, deferred_br.add_port)

    def test_getattr_unallowed_attr_failure(self):
        with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
            self.assertRaises(AttributeError, getattr, deferred_br, 'failure')

    @vsctl_only
    def test_default_cookie(self):
        self.br = ovs_lib.OVSBridge("br-tun")
        uuid_stamp1 = self.br.default_cookie
        self.assertEqual(uuid_stamp1, self.br.default_cookie)

    @vsctl_only
    def test_cookie_passed_to_addmod(self):
        self.br = ovs_lib.OVSBridge("br-tun")
        stamp = str(self.br.default_cookie)
        expected_calls = [
            mock.call('add-flows', ['-'],
                      'hard_timeout=0,idle_timeout=0,priority=1,'
                      'cookie=' + stamp + ',actions=drop'),
            mock.call('mod-flows', ['-'],
                      'cookie=' + stamp + ',actions=drop')
        ]
        with mock.patch.object(self.br, 'run_ofctl') as f:
            with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
                deferred_br.add_flow(actions='drop')
                deferred_br.mod_flow(actions='drop')
            f.assert_has_calls(expected_calls)

    @vsctl_only
    def test_add_flow_with_bundle(self):
        br = ovs_lib.OVSBridge("foo")
        deferred = br.deferred(use_bundle=True)
        with mock.patch.object(utils, "execute", spec=utils.execute) as mexec:
            deferred.add_flow(in_port=1, actions='drop')
            deferred.apply_flows()
        self.assertIn('--bundle', mexec.call_args[0][0])
