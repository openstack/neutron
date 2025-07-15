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
from unittest import mock

from neutron_lib import constants as lib_const
from neutron_lib import exceptions
from neutron_lib.plugins.ml2 import ovs_constants as p_const
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import tenacity
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import exceptions as ovs_exc
from neutron.tests import base


class OFCTLParamListMatcher:

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


class StringSetMatcher:
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
        return f'<comma-separated string for {self.set}{sep}>'


class OVS_Lib_Test_Common(base.BaseTestCase):
    """A test suite to exercise the OVS libraries common functions"""

    def test_get_gre_tunnel_port_type(self):
        ptype = ovs_lib.get_gre_tunnel_port_type('192.168.1.2', '192.168.1.1')
        self.assertEqual(lib_const.TYPE_GRE, ptype)

    def test_get_gre_tunnel_port_type_ipv6(self):
        ptype = ovs_lib.get_gre_tunnel_port_type('2001:db8::1:2',
                                                 '2001:db8::1:1')
        self.assertEqual(lib_const.TYPE_GRE_IP6, ptype)

    def test_version_from_protocol(self):
        ofproto = ovs_lib.version_from_protocol(p_const.OPENFLOW10)
        self.assertEqual(1, ofproto)


class OVS_Lib_Test(base.BaseTestCase):
    """A test suite to exercise the OVS libraries shared by Neutron agents.

    Note: these tests do not actually execute ovs-* utilities, and thus
    can run on any system.  That does, however, limit their scope.
    """

    def setUp(self):
        super().setUp()
        self.BR_NAME = "br-int"

        # Don't attempt to connect to ovsdb
        mock.patch('neutron.agent.ovsdb.impl_idl.api_factory').start()
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        self.execute = mock.patch.object(
            utils, "execute", spec=utils.execute).start()

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
            ('actions', f"mod_vlan_vid:{vid},output:{ofport}")])
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
        return mock.call(cmd, run_as_root=True, privsep_exec=True, **kwargs)

    def _verify_ofctl_mock(self, cmd, *args, **kwargs):
        cmd = self._ofctl_args(cmd, *args)
        return self.execute.assert_called_once_with(
            cmd, run_as_root=True, privsep_exec=True, **kwargs)

    def test_add_protocols_all_already_set(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        with mock.patch.object(self.br, 'db_get_val') as db_get_val, \
                mock.patch.object(self.br.ovsdb, 'db_add') as db_add:
            db_get_val.return_value = [p_const.OPENFLOW10,
                                       p_const.OPENFLOW13]
            self.br.add_protocols(p_const.OPENFLOW10, p_const.OPENFLOW13)
            db_get_val.assert_called_once_with(
                'Bridge', self.BR_NAME, 'protocols')
            db_add.assert_not_called()

    def test_add_protocols_some_already_set(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        with mock.patch.object(self.br, 'db_get_val') as db_get_val, \
                mock.patch.object(self.br.ovsdb, 'db_add') as db_add:
            db_get_val.return_value = [p_const.OPENFLOW10]
            self.br.add_protocols(p_const.OPENFLOW10, p_const.OPENFLOW13)
            db_get_val.assert_called_once_with(
                'Bridge', self.BR_NAME, 'protocols')
            db_add.assert_has_calls([
                mock.call('Bridge', self.BR_NAME,
                          'protocols', p_const.OPENFLOW13)])

    def test_get_port_tag_by_name(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        port_name = "fake-port"
        with mock.patch.object(self.br, 'db_get_val') as db_get_val:
            self.br.get_port_tag_by_name(port_name)
            db_get_val.assert_called_once_with(
                'Port', port_name, 'other_config')

    def test_get_value_from_other_config(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        value = "test_value"
        other_config = {"test_key": value}
        port_name = "fake-port"
        with mock.patch.object(self.br, 'db_get_val') as db_get_val:
            db_get_val.return_value = other_config
            v = self.br.get_value_from_other_config(port_name, "test_key")
            self.assertEqual(value, v)

    def test_get_value_from_other_config_value_error(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        value = "test_value"
        other_config = {"test_key": value}
        port_name = "fake-port"
        with mock.patch.object(self.br, 'db_get_val') as db_get_val:
            db_get_val.return_value = other_config
            self.assertRaises(ovs_exc.OVSDBPortError,
                              self.br.get_value_from_other_config,
                              port_name, "test_key", int)

    def test_get_value_from_other_config_not_found(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        value = "test_value"
        other_config = {"test_key": value}
        port_name = "fake-port"
        with mock.patch.object(self.br, 'db_get_val') as db_get_val:
            db_get_val.return_value = other_config
            self.assertIsNone(
                self.br.get_value_from_other_config(
                    port_name, "key_not_exist"))

    def test_set_value_to_other_config(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        value = "test_value"
        other_config = {"test_key": value}
        port_name = "fake-port"
        with mock.patch.object(self.br, 'db_get_val') as db_get_val, \
                mock.patch.object(self.br.ovsdb, 'db_set') as set_db:
            new_key = "new_key"
            new_value = "new_value"
            db_get_val.return_value = other_config
            self.br.set_value_to_other_config(port_name, key=new_key,
                                              value=new_value)

            db_get_val.assert_called_once_with('Port', port_name,
                                               'other_config')
            other_config.update({new_key: new_value})
            set_db.assert_called_once_with(
                'Port', port_name, ('other_config', other_config))

    def test_remove_value_from_other_config(self):
        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        old_key = "old_key"
        old_value = "old_value"
        other_config = {old_key: old_value}
        port_name = "fake-port"

        with mock.patch.object(self.br, 'db_get_val') as db_get_val, \
                mock.patch.object(self.br.ovsdb, 'db_clear') as db_clear, \
                mock.patch.object(self.br.ovsdb, 'db_set') as set_db:
            db_get_val.return_value = other_config
            self.br.remove_value_from_other_config(port_name, key=old_key)

            db_get_val.assert_called_once_with('Port', port_name,
                                               'other_config')
            db_clear.assert_called_once_with(
                'Port', port_name, "other_config")
            set_db.assert_called_once_with(
                'Port', port_name, ('other_config', {}))

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
                                 f"{cookie_spec},tun_id={lsw_id}")),
            self._ofctl_mock("del-flows", self.BR_NAME, '-',
                             process_input=StringSetMatcher(
                                 f"{cookie_spec},dl_vlan={vid}")),
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

    def _encode_ovs_json(self, headings, data):
        # See man ovs-vsctl(8) for the encoding details.
        r = {"data": [],
             "headings": headings}
        for row in data:
            ovs_row = []
            r["data"].append(ovs_row)
            for cell in row:
                if isinstance(cell, str | int | list):
                    ovs_row.append(cell)
                elif isinstance(cell, dict):
                    ovs_row.append(["map", cell.items()])
                elif isinstance(cell, set):
                    ovs_row.append(["set", cell])
                else:
                    raise TypeError('%r not int, str, list, set or dict' %
                                    type(cell))
        return jsonutils.dumps(r)

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
            set_egress_mock.assert_called_once_with("test_port", 0, 0,
                                                    check_error=False)

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
        # pid3 isn't on bridge
        self.assertIsNone(by_id['pid3'])
        self.assertEqual(-1, by_id['pid4'].ofport)
        self.assertEqual('pid1', by_id['pid1'].vif_id)
        self.assertEqual('qvo1', by_id['pid1'].port_name)
        self.assertEqual(1, by_id['pid1'].ofport)
        self.assertEqual('pid2', by_id['pid2'].vif_id)
        self.assertEqual('qvo2', by_id['pid2'].port_name)
        self.assertEqual(2, by_id['pid2'].ofport)
        self.br.get_ports_attributes.assert_has_calls(
            [mock.call('Interface', columns=['name', 'external_ids', 'ofport'],
                       if_exists=True)])

    def test_get_port_ofport_retry(self):
        # Increase this value to avoid a timeout during the test execution
        self.br.ovsdb.ovsdb_connection.timeout = 10
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[], [], [], [], 1]):
            self.assertEqual(1, self.br._get_port_val('1', 'ofport'))

    def test_get_port_ofport_retry_fails(self):
        # reduce timeout for faster execution
        self.br.ovsdb.ovsdb_connection.timeout = 1
        # after 7 calls the retry will timeout and raise
        with mock.patch.object(
                self.br, 'db_get_val',
                side_effect=[[] for _ in range(7)]):
            self.assertRaises(tenacity.RetryError,
                              self.br._get_port_val, '1', 'ofport')

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

    def test_hw_offload_enabled_false(self):
        config_mock1 = mock.PropertyMock(return_value={"other_config": {}})
        config_mock2 = mock.PropertyMock(
            return_value={"other_config": {"hw-offload": "false"}})
        config_mock3 = mock.PropertyMock(
            return_value={"other_config": {"hw-offload": "False"}})
        for config_mock in (config_mock1, config_mock2, config_mock3):
            with mock.patch("neutron.agent.common.ovs_lib.OVSBridge.config",
                            new_callable=config_mock):
                self.assertFalse(self.br.is_hw_offload_enabled)

    def test_hw_offload_enabled_true(self):
        config_mock1 = mock.PropertyMock(
            return_value={"other_config": {"hw-offload": "true"}})
        config_mock2 = mock.PropertyMock(
            return_value={"other_config": {"hw-offload": "True"}})
        for config_mock in (config_mock1, config_mock2):
            with mock.patch("neutron.agent.common.ovs_lib.OVSBridge.config",
                            new_callable=config_mock):
                self.assertTrue(self.br.is_hw_offload_enabled)


class TestDeferredOVSBridge(base.BaseTestCase):

    def setUp(self):
        super().setUp()

        self.br = mock.Mock()
        self.mock_do_action_flows_by_group_id = mock.patch.object(
            self.br, 'do_action_flows_by_group_id').start()

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
        self.mock_do_action_flows_by_group_id.assert_has_calls(expected_calls)
        self.assertEqual(len(expected_calls),
                         len(self.mock_do_action_flows_by_group_id.mock_calls))

    def test_apply_on_exit(self):
        expected_calls = [
            mock.call('add', {None: [self.add_flow_dict1]}, False),
            mock.call('mod', {None: [self.mod_flow_dict1]}, False),
            mock.call('del', {None: [self.del_flow_dict1]}, False),
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

    def test_apply(self):
        expected_calls = [
            mock.call('add',
                      {11: [self.add_flow_dict1], 12: [self.add_flow_dict2]},
                      False),
            mock.call('mod', {None: [self.mod_flow_dict1]}, False),
            mock.call('del', {None: [self.del_flow_dict1]}, False),
        ]

        with ovs_lib.DeferredOVSBridge(self.br) as deferred_br:
            deferred_br.add_flow(flow_group_id=11, **self.add_flow_dict1)
            deferred_br.add_flow(flow_group_id=12, **self.add_flow_dict2)
            deferred_br.mod_flow(**self.mod_flow_dict1)
            deferred_br.delete_flows(**self.del_flow_dict1)
            self._verify_mock_call([])
            deferred_br.apply_flows()
            self._verify_mock_call(expected_calls)
        self._verify_mock_call(expected_calls)

    def test_apply_order(self):
        expected_calls = [
            mock.call('del',
                      {None: [self.del_flow_dict1, self.del_flow_dict2]},
                      False),
            mock.call('mod',
                      {None: [self.mod_flow_dict1, self.mod_flow_dict2]},
                      False),
            mock.call('add',
                      {None: [self.add_flow_dict1, self.add_flow_dict2]},
                      False),
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
            mock.call('add', {None: [self.add_flow_dict1]}, False),
            mock.call('mod', {None: [self.mod_flow_dict1]}, False),
            mock.call('del',
                      {None: [self.del_flow_dict1, self.del_flow_dict2]},
                      False),
            mock.call('add', {None: [self.add_flow_dict2]}, False),
            mock.call('mod', {None: [self.mod_flow_dict2]}, False),
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
