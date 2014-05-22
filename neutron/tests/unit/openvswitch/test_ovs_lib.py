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

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
import mock
from oslo.config import cfg
import testtools

from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common import jsonutils
from neutron.openstack.common import uuidutils
from neutron.plugins.openvswitch.common import constants
from neutron.tests import base
from neutron.tests import tools

OVS_LINUX_KERN_VERS_WITHOUT_VXLAN = "3.12.0"


class TestBaseOVS(base.BaseTestCase):

    def setUp(self):
        super(TestBaseOVS, self).setUp()
        self.root_helper = 'sudo'
        self.ovs = ovs_lib.BaseOVS(self.root_helper)
        self.br_name = 'bridge1'

    def test_add_bridge(self):
        with mock.patch.object(self.ovs, 'run_vsctl') as mock_vsctl:
            self.ovs.add_bridge(self.br_name)
        mock_vsctl.assert_called_with(["--", "--may-exist",
                                       "add-br", self.br_name])

    def test_delete_bridge(self):
        with mock.patch.object(self.ovs, 'run_vsctl') as mock_vsctl:
            self.ovs.delete_bridge(self.br_name)
        mock_vsctl.assert_called_with(["--", "--if-exists", "del-br",
                                       self.br_name])

    def test_bridge_exists_returns_true(self):
        with mock.patch.object(self.ovs, 'run_vsctl') as mock_vsctl:
            self.assertTrue(self.ovs.bridge_exists(self.br_name))
        mock_vsctl.assert_called_with(['br-exists', self.br_name],
                                      check_error=True)

    def test_bridge_exists_returns_false_for_exit_code_2(self):
        with mock.patch.object(self.ovs, 'run_vsctl',
                               side_effect=RuntimeError('Exit code: 2\n')):
            self.assertFalse(self.ovs.bridge_exists('bridge1'))

    def test_bridge_exists_raises_unknown_exception(self):
        with mock.patch.object(self.ovs, 'run_vsctl',
                               side_effect=RuntimeError()):
            with testtools.ExpectedException(RuntimeError):
                self.ovs.bridge_exists('bridge1')

    def test_get_bridge_name_for_port_name_returns_bridge_for_valid_port(self):
        port_name = 'bar'
        with mock.patch.object(self.ovs, 'run_vsctl',
                               return_value=self.br_name) as mock_vsctl:
            bridge = self.ovs.get_bridge_name_for_port_name(port_name)
        self.assertEqual(bridge, self.br_name)
        mock_vsctl.assert_called_with(['port-to-br', port_name],
                                      check_error=True)

    def test_get_bridge_name_for_port_name_returns_none_for_exit_code_1(self):
        with mock.patch.object(self.ovs, 'run_vsctl',
                               side_effect=RuntimeError('Exit code: 1\n')):
            self.assertFalse(self.ovs.get_bridge_name_for_port_name('bridge1'))

    def test_get_bridge_name_for_port_name_raises_unknown_exception(self):
        with mock.patch.object(self.ovs, 'run_vsctl',
                               side_effect=RuntimeError()):
            with testtools.ExpectedException(RuntimeError):
                self.ovs.get_bridge_name_for_port_name('bridge1')

    def _test_port_exists(self, br_name, result):
        with mock.patch.object(self.ovs,
                               'get_bridge_name_for_port_name',
                               return_value=br_name):
            self.assertEqual(self.ovs.port_exists('bar'), result)

    def test_port_exists_returns_true_for_bridge_name(self):
        self._test_port_exists(self.br_name, True)

    def test_port_exists_returns_false_for_none(self):
        self._test_port_exists(None, False)


class OVS_Lib_Test(base.BaseTestCase):
    """A test suite to exercise the OVS libraries shared by Neutron agents.

    Note: these tests do not actually execute ovs-* utilities, and thus
    can run on any system.  That does, however, limit their scope.
    """

    def setUp(self):
        super(OVS_Lib_Test, self).setUp()
        self.BR_NAME = "br-int"
        self.TO = "--timeout=10"

        self.root_helper = 'sudo'
        self.br = ovs_lib.OVSBridge(self.BR_NAME, self.root_helper)
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

    def test_set_controller(self):
        controller_names = ['tcp:127.0.0.1:6633', 'tcp:172.17.16.10:5555']
        self.br.set_controller(controller_names)
        self.execute.assert_called_once_with(
            ['ovs-vsctl', self.TO, '--', 'set-controller', self.BR_NAME,
             'tcp:127.0.0.1:6633', 'tcp:172.17.16.10:5555'],
            root_helper=self.root_helper)

    def test_del_controller(self):
        self.br.del_controller()
        self.execute.assert_called_once_with(
            ['ovs-vsctl', self.TO, '--', 'del-controller', self.BR_NAME],
            root_helper=self.root_helper)

    def test_get_controller(self):
        self.execute.return_value = 'tcp:127.0.0.1:6633\ntcp:172.17.16.10:5555'
        names = self.br.get_controller()
        self.assertEqual(names,
                         ['tcp:127.0.0.1:6633', 'tcp:172.17.16.10:5555'])
        self.execute.assert_called_once_with(
            ['ovs-vsctl', self.TO, '--', 'get-controller', self.BR_NAME],
            root_helper=self.root_helper)

    def test_set_protocols(self):
        protocols = 'OpenFlow13'
        self.br.set_protocols(protocols)
        self.execute.assert_called_once_with(
            ['ovs-vsctl', self.TO, '--', 'set', 'bridge', self.BR_NAME,
             "protocols=%s" % protocols],
            root_helper=self.root_helper)

    def test_create(self):
        self.br.add_bridge(self.BR_NAME)

        self.br.create()

    def test_destroy(self):
        self.br.delete_bridge(self.BR_NAME)

        self.br.destroy()

    def test_reset_bridge(self):
        self.br.destroy()
        self.br.create()

        self.br.reset_bridge()

    def _build_timeout_opt(self, exp_timeout):
        return "--timeout=%d" % exp_timeout if exp_timeout else self.TO

    def _test_delete_port(self, exp_timeout=None):
        exp_timeout_str = self._build_timeout_opt(exp_timeout)
        pname = "tap5"
        self.br.delete_port(pname)
        self.execute.assert_called_once_with(
            ["ovs-vsctl", exp_timeout_str, "--", "--if-exists",
             "del-port", self.BR_NAME, pname],
            root_helper=self.root_helper)

    def test_delete_port(self):
        self._test_delete_port()

    def test_call_command_non_default_timeput(self):
        # This test is only for verifying a non-default timeout
        # is correctly applied. Does not need to be repeated for
        # every ovs_lib method
        new_timeout = 5
        self.br.vsctl_timeout = new_timeout
        self._test_delete_port(new_timeout)

    def test_add_flow(self):
        ofport = "99"
        vid = 4000
        lsw_id = 18
        cidr = '192.168.1.0/24'

        flow_dict_1 = OrderedDict([('priority', 2),
                                   ('dl_src', 'ca:fe:de:ad:be:ef'),
                                   ('actions', 'strip_vlan,output:0')])
        flow_dict_2 = OrderedDict([('priority', 1),
                                   ('actions', 'normal')])
        flow_dict_3 = OrderedDict([('priority', 2),
                                   ('actions', 'drop')])
        flow_dict_4 = OrderedDict([('priority', 2),
                                   ('in_port', ofport),
                                   ('actions', 'drop')])
        flow_dict_5 = OrderedDict([
            ('priority', 4),
            ('in_port', ofport),
            ('dl_vlan', vid),
            ('actions', "strip_vlan,set_tunnel:%s,normal" % (lsw_id))])
        flow_dict_6 = OrderedDict([
            ('priority', 3),
            ('tun_id', lsw_id),
            ('actions', "mod_vlan_vid:%s,output:%s" % (vid, ofport))])
        flow_dict_7 = OrderedDict([
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
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,dl_src=ca:fe:de:ad:be:ef"
                       ",actions=strip_vlan,output:0"],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=1,actions=normal"],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,actions=drop"],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,in_port=%s,actions=drop" % ofport],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=4,dl_vlan=%s,in_port=%s,"
                       "actions=strip_vlan,set_tunnel:%s,normal"
                       % (vid, ofport, lsw_id)],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=3,tun_id=%s,actions="
                       "mod_vlan_vid:%s,output:%s"
                       % (lsw_id, vid, ofport)],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=4,nw_src=%s,arp,actions=drop" % cidr],
                      process_input=None, root_helper=self.root_helper),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_add_flow_timeout_set(self):
        flow_dict = OrderedDict([('priority', 1),
                                 ('hard_timeout', 1000),
                                 ('idle_timeout', 2000),
                                 ('actions', 'normal')])

        self.br.add_flow(**flow_dict)
        self.execute.assert_called_once_with(
            ["ovs-ofctl", "add-flow", self.BR_NAME,
             "hard_timeout=1000,idle_timeout=2000,priority=1,actions=normal"],
            process_input=None,
            root_helper=self.root_helper)

    def test_add_flow_default_priority(self):
        flow_dict = OrderedDict([('actions', 'normal')])

        self.br.add_flow(**flow_dict)
        self.execute.assert_called_once_with(
            ["ovs-ofctl", "add-flow", self.BR_NAME,
             "hard_timeout=0,idle_timeout=0,priority=1,actions=normal"],
            process_input=None,
            root_helper=self.root_helper)

    def test_get_port_ofport(self):
        pname = "tap99"
        ofport = "6"
        self.execute.return_value = ofport
        self.assertEqual(self.br.get_port_ofport(pname), ofport)
        self.execute.assert_called_once_with(
            ["ovs-vsctl", self.TO, "get", "Interface", pname, "ofport"],
            root_helper=self.root_helper)

    def test_get_datapath_id(self):
        datapath_id = '"0000b67f4fbcc149"'
        self.execute.return_value = datapath_id
        self.assertEqual(self.br.get_datapath_id(), datapath_id.strip('"'))
        self.execute.assert_called_once_with(
            ["ovs-vsctl", self.TO, "get",
             "Bridge", self.BR_NAME, "datapath_id"],
            root_helper=self.root_helper)

    def test_count_flows(self):
        self.execute.return_value = 'ignore\nflow-1\n'
        # counts the number of flows as total lines of output - 2
        self.assertEqual(self.br.count_flows(), 1)
        self.execute.assert_called_once_with(
            ["ovs-ofctl", "dump-flows", self.BR_NAME],
            root_helper=self.root_helper,
            process_input=None)

    def test_delete_flow(self):
        ofport = "5"
        lsw_id = 40
        vid = 39
        self.br.delete_flows(in_port=ofport)
        self.br.delete_flows(tun_id=lsw_id)
        self.br.delete_flows(dl_vlan=vid)
        expected_calls = [
            mock.call(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "in_port=" + ofport],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "tun_id=%s" % lsw_id],
                      process_input=None, root_helper=self.root_helper),
            mock.call(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "dl_vlan=%s" % vid],
                      process_input=None, root_helper=self.root_helper),
        ]
        self.execute.assert_has_calls(expected_calls)

    def test_delete_flow_with_priority_set(self):
        params = {'in_port': '1',
                  'priority': '1'}

        self.assertRaises(exceptions.InvalidInput,
                          self.br.delete_flows,
                          **params)

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

    def test_defer_apply_flows(self):

        flow_expr = mock.patch.object(ovs_lib, '_build_flow_expr_str').start()
        flow_expr.side_effect = ['added_flow_1', 'added_flow_2',
                                 'deleted_flow_1']
        run_ofctl = mock.patch.object(self.br, 'run_ofctl').start()

        self.br.defer_apply_on()
        self.br.add_flow(flow='add_flow_1')
        self.br.defer_apply_on()
        self.br.add_flow(flow='add_flow_2')
        self.br.delete_flows(flow='delete_flow_1')
        self.br.defer_apply_off()

        flow_expr.assert_has_calls([
            mock.call({'flow': 'add_flow_1'}, 'add'),
            mock.call({'flow': 'add_flow_2'}, 'add'),
            mock.call({'flow': 'delete_flow_1'}, 'del')
        ])

        run_ofctl.assert_has_calls([
            mock.call('add-flows', ['-'], 'added_flow_1\nadded_flow_2\n'),
            mock.call('del-flows', ['-'], 'deleted_flow_1\n')
        ])

    def test_defer_apply_flows_concurrently(self):
        flow_expr = mock.patch.object(ovs_lib, '_build_flow_expr_str').start()
        flow_expr.side_effect = ['added_flow_1', 'deleted_flow_1',
                                 'modified_flow_1', 'added_flow_2',
                                 'deleted_flow_2', 'modified_flow_2']

        run_ofctl = mock.patch.object(self.br, 'run_ofctl').start()

        def run_ofctl_fake(cmd, args, process_input=None):
            self.br.defer_apply_on()
            if cmd == 'add-flows':
                self.br.add_flow(flow='added_flow_2')
            elif cmd == 'del-flows':
                self.br.delete_flows(flow='deleted_flow_2')
            elif cmd == 'mod-flows':
                self.br.mod_flow(flow='modified_flow_2')
        run_ofctl.side_effect = run_ofctl_fake

        self.br.defer_apply_on()
        self.br.add_flow(flow='added_flow_1')
        self.br.delete_flows(flow='deleted_flow_1')
        self.br.mod_flow(flow='modified_flow_1')
        self.br.defer_apply_off()

        run_ofctl.side_effect = None
        self.br.defer_apply_off()

        flow_expr.assert_has_calls([
            mock.call({'flow': 'added_flow_1'}, 'add'),
            mock.call({'flow': 'deleted_flow_1'}, 'del'),
            mock.call({'flow': 'modified_flow_1'}, 'mod'),
            mock.call({'flow': 'added_flow_2'}, 'add'),
            mock.call({'flow': 'deleted_flow_2'}, 'del'),
            mock.call({'flow': 'modified_flow_2'}, 'mod')
        ])
        run_ofctl.assert_has_calls([
            mock.call('add-flows', ['-'], 'added_flow_1\n'),
            mock.call('del-flows', ['-'], 'deleted_flow_1\n'),
            mock.call('mod-flows', ['-'], 'modified_flow_1\n'),
            mock.call('add-flows', ['-'], 'added_flow_2\n'),
            mock.call('del-flows', ['-'], 'deleted_flow_2\n'),
            mock.call('mod-flows', ['-'], 'modified_flow_2\n')
        ])

    def test_add_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = "6"
        command = ["ovs-vsctl", self.TO, '--', "--may-exist", "add-port",
                   self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=gre", "options:remote_ip=" + remote_ip,
                        "options:local_ip=" + local_ip,
                        "options:in_key=flow",
                        "options:out_key=flow"])
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (mock.call(command, root_helper=self.root_helper), None),
            (mock.call(["ovs-vsctl", self.TO, "get",
                        "Interface", pname, "ofport"],
                       root_helper=self.root_helper),
             ofport),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip),
            ofport)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_add_patch_port(self):
        pname = "tap99"
        peer = "bar10"
        ofport = "6"

        # Each element is a tuple of (expected mock call, return_value)
        command = ["ovs-vsctl", self.TO, "add-port", self.BR_NAME, pname]
        command.extend(["--", "set", "Interface", pname])
        command.extend(["type=patch", "options:peer=" + peer])
        expected_calls_and_values = [
            (mock.call(command, root_helper=self.root_helper),
             None),
            (mock.call(["ovs-vsctl", self.TO, "get",
                        "Interface", pname, "ofport"],
                       root_helper=self.root_helper),
             ofport)
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        self.assertEqual(self.br.add_patch_port(pname, peer), ofport)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def _test_get_vif_ports(self, is_xen=False):
        pname = "tap99"
        ofport = "6"
        vif_id = uuidutils.generate_uuid()
        mac = "ca:fe:de:ad:be:ef"

        if is_xen:
            external_ids = ('{xs-vif-uuid="%s", attached-mac="%s"}'
                            % (vif_id, mac))
        else:
            external_ids = ('{iface-id="%s", attached-mac="%s"}'
                            % (vif_id, mac))

        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             "%s\n" % pname),
            (mock.call(["ovs-vsctl", self.TO, "get",
                        "Interface", pname, "external_ids"],
                       root_helper=self.root_helper),
             external_ids),
            (mock.call(["ovs-vsctl", self.TO, "get",
                        "Interface", pname, "ofport"],
                       root_helper=self.root_helper),
             ofport),
        ]
        if is_xen:
            expected_calls_and_values.append(
                (mock.call(["xe", "vif-param-get", "param-name=other-config",
                            "param-key=nicira-iface-id", "uuid=" + vif_id],
                           root_helper=self.root_helper),
                 vif_id)
            )
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        ports = self.br.get_vif_ports()
        self.assertEqual(1, len(ports))
        self.assertEqual(ports[0].port_name, pname)
        self.assertEqual(ports[0].ofport, ofport)
        self.assertEqual(ports[0].vif_id, vif_id)
        self.assertEqual(ports[0].vif_mac, mac)
        self.assertEqual(ports[0].switch.br_name, self.BR_NAME)
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

    def _test_get_vif_port_set(self, is_xen):
        if is_xen:
            id_key = 'xs-vif-uuid'
        else:
            id_key = 'iface-id'

        headings = ['name', 'external_ids']
        data = [
            # A vif port on this bridge:
            ['tap99', {id_key: 'tap99id', 'attached-mac': 'tap99mac'}, 1],
            # A vif port on this bridge not yet configured
            ['tap98', {id_key: 'tap98id', 'attached-mac': 'tap98mac'}, []],
            # Another vif port on this bridge not yet configured
            ['tap97', {id_key: 'tap97id', 'attached-mac': 'tap97mac'},
             ['set', []]],

            # A vif port on another bridge:
            ['tap88', {id_key: 'tap88id', 'attached-mac': 'tap88id'}, 1],
            # Non-vif port on this bridge:
            ['tun22', {}, 2],
        ]

        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             'tap99\ntun22'),
            (mock.call(["ovs-vsctl", self.TO, "--format=json",
                        "--", "--columns=name,external_ids,ofport",
                        "list", "Interface"],
                       root_helper=self.root_helper),
             self._encode_ovs_json(headings, data)),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)

        if is_xen:
            get_xapi_iface_id = mock.patch.object(self.br,
                                                  'get_xapi_iface_id').start()
            get_xapi_iface_id.return_value = 'tap99id'

        port_set = self.br.get_vif_port_set()
        self.assertEqual(set(['tap99id']), port_set)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)
        if is_xen:
            get_xapi_iface_id.assert_called_once_with('tap99id')

    def test_get_vif_ports_nonxen(self):
        self._test_get_vif_ports(is_xen=False)

    def test_get_vif_ports_xen(self):
        self._test_get_vif_ports(is_xen=True)

    def test_get_vif_port_set_nonxen(self):
        self._test_get_vif_port_set(False)

    def test_get_vif_port_set_xen(self):
        self._test_get_vif_port_set(True)

    def test_get_vif_ports_list_ports_error(self):
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.get_vif_ports)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_vif_port_set_list_ports_error(self):
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.get_vif_port_set)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def test_get_vif_port_set_list_interface_error(self):
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             'tap99\n'),
            (mock.call(["ovs-vsctl", self.TO, "--format=json",
                        "--", "--columns=name,external_ids,ofport",
                        "list", "Interface"],
                       root_helper=self.root_helper),
             RuntimeError()),
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
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             '\n'.join((iface for iface, tag in data))),
            (mock.call(["ovs-vsctl", self.TO, "--format=json",
                        "--", "--columns=name,tag",
                        "list", "Port"],
                       root_helper=self.root_helper),
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
        self.execute.assert_called_once_with(
            ["ovs-vsctl", self.TO, "clear", "Port", pname, "tag"],
            root_helper=self.root_helper)

    def _test_iface_to_br(self, exp_timeout=None):
        iface = 'tap0'
        br = 'br-int'
        root_helper = 'sudo'
        self.execute.return_value = 'br-int'
        exp_timeout_str = self._build_timeout_opt(exp_timeout)
        self.assertEqual(ovs_lib.get_bridge_for_iface(root_helper, iface), br)
        self.execute.assert_called_once_with(
            ["ovs-vsctl", exp_timeout_str, "iface-to-br", iface],
            root_helper=root_helper)

    def test_iface_to_br(self):
        self._test_iface_to_br()

    def test_iface_to_br_non_default_timeout(self):
        new_timeout = 5
        cfg.CONF.set_override('ovs_vsctl_timeout', new_timeout)
        self._test_iface_to_br(new_timeout)

    def test_iface_to_br_handles_ovs_vsctl_exception(self):
        iface = 'tap0'
        root_helper = 'sudo'
        self.execute.side_effect = Exception

        self.assertIsNone(ovs_lib.get_bridge_for_iface(root_helper, iface))
        self.execute.assert_called_once_with(
            ["ovs-vsctl", self.TO, "iface-to-br", iface],
            root_helper=root_helper)

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
            (mock.call(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                       root_helper=self.root_helper),
             RuntimeError()),
        ]
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        self.assertRaises(RuntimeError, self.br.delete_ports, all_ports=False)
        tools.verify_mock_calls(self.execute, expected_calls_and_values)

    def _test_get_bridges(self, exp_timeout=None):
        bridges = ['br-int', 'br-ex']
        root_helper = 'sudo'
        self.execute.return_value = 'br-int\nbr-ex\n'
        timeout_str = self._build_timeout_opt(exp_timeout)
        self.assertEqual(ovs_lib.get_bridges(root_helper), bridges)
        self.execute.assert_called_once_with(
            ["ovs-vsctl", timeout_str, "list-br"],
            root_helper=root_helper)

    def test_get_bridges(self):
        self._test_get_bridges()

    def test_get_bridges_not_default_timeout(self):
        new_timeout = 5
        cfg.CONF.set_override('ovs_vsctl_timeout', new_timeout)
        self._test_get_bridges(new_timeout)

    def test_get_local_port_mac_succeeds(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address='foo')):
            self.assertEqual('foo', self.br.get_local_port_mac())

    def test_get_local_port_mac_raises_exception_for_missing_mac(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address=None)):
            with testtools.ExpectedException(Exception):
                self.br.get_local_port_mac()

    def _test_get_vif_port_by_id(self, iface_id, data, br_name=None):
        headings = ['external_ids', 'name', 'ofport']
        # Each element is a tuple of (expected mock call, return_value)
        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, "--format=json",
                        "--", "--columns=external_ids,name,ofport",
                        "find", "Interface",
                        'external_ids:iface-id="%s"' % iface_id],
                       root_helper=self.root_helper),
             self._encode_ovs_json(headings, data))]
        if data:
            if not br_name:
                br_name = self.BR_NAME

            expected_calls_and_values.append(
                (mock.call(["ovs-vsctl", self.TO,
                            "iface-to-br", data[0][headings.index('name')]],
                           root_helper=self.root_helper),
                 br_name))
        tools.setup_mock_calls(self.execute, expected_calls_and_values)
        vif_port = self.br.get_vif_port_by_id(iface_id)

        tools.verify_mock_calls(self.execute, expected_calls_and_values)
        return vif_port

    def _test_get_vif_port_by_id_with_data(self, ofport=None, mac=None):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"]]
        if mac:
            external_ids.append(["attached-mac", mac])
        data = [[["map", external_ids], "tap99",
                 ofport if ofport else '["set",[]]']]
        vif_port = self._test_get_vif_port_by_id('tap99id', data)
        if not ofport or ofport == -1 or not mac:
            self.assertIsNone(vif_port)
            return
        self.assertEqual(vif_port.vif_id, 'tap99id')
        self.assertEqual(vif_port.vif_mac, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(vif_port.port_name, 'tap99')
        self.assertEqual(vif_port.ofport, ofport)

    def test_get_vif_by_port_id_with_ofport(self):
        self._test_get_vif_port_by_id_with_data(
            ofport=1, mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_without_ofport(self):
        self._test_get_vif_port_by_id_with_data(mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_with_invalid_ofport(self):
        self._test_get_vif_port_by_id_with_data(
            ofport=-1, mac="aa:bb:cc:dd:ee:ff")

    def test_get_vif_by_port_id_without_mac(self):
        self._test_get_vif_port_by_id_with_data(ofport=1)

    def test_get_vif_by_port_id_with_no_data(self):
        self.assertIsNone(self._test_get_vif_port_by_id('whatever', []))

    def test_get_vif_by_port_id_different_bridge(self):
        external_ids = [["iface-id", "tap99id"],
                        ["iface-status", "active"]]
        data = [[["map", external_ids], "tap99", 1]]
        self.assertIsNone(self._test_get_vif_port_by_id('tap99id', data,
                                                        "br-ext"))

    def _check_ovs_vxlan_version(self, installed_usr_version,
                                 installed_klm_version,
                                 installed_kernel_version,
                                 expecting_ok):
        with mock.patch(
                'neutron.agent.linux.ovs_lib.get_installed_ovs_klm_version'
        ) as klm_cmd:
            with mock.patch(
                'neutron.agent.linux.ovs_lib.get_installed_ovs_usr_version'
            ) as usr_cmd:
                with mock.patch(
                    'neutron.agent.linux.ovs_lib.get_installed_kernel_version'
                ) as kernel_cmd:
                    try:
                        klm_cmd.return_value = installed_klm_version
                        usr_cmd.return_value = installed_usr_version
                        kernel_cmd.return_value = installed_kernel_version
                        ovs_lib.check_ovs_vxlan_version(root_helper='sudo')
                        version_ok = True
                    except SystemError:
                        version_ok = False
                self.assertEqual(version_ok, expecting_ok)

    def test_check_minimum_version(self):
        min_vxlan_ver = constants.MINIMUM_OVS_VXLAN_VERSION
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(min_vxlan_ver, min_vxlan_ver,
                                      min_kernel_ver, expecting_ok=True)

    def test_check_future_version(self):
        install_ver = str(float(constants.MINIMUM_OVS_VXLAN_VERSION) + 0.01)
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(install_ver, install_ver,
                                      min_kernel_ver, expecting_ok=True)

    def test_check_fail_version(self):
        install_ver = str(float(constants.MINIMUM_OVS_VXLAN_VERSION) - 0.01)
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(install_ver, install_ver,
                                      min_kernel_ver, expecting_ok=False)

    def test_check_fail_no_version(self):
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(None, None,
                                      min_kernel_ver,
                                      expecting_ok=False)

    def test_check_fail_klm_version(self):
        min_vxlan_ver = constants.MINIMUM_OVS_VXLAN_VERSION
        min_kernel_ver = OVS_LINUX_KERN_VERS_WITHOUT_VXLAN
        install_ver = str(float(min_vxlan_ver) - 0.01)
        self._check_ovs_vxlan_version(min_vxlan_ver,
                                      install_ver,
                                      min_kernel_ver,
                                      expecting_ok=False)

    def test_check_pass_kernel_version(self):
        min_vxlan_ver = constants.MINIMUM_OVS_VXLAN_VERSION
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(min_vxlan_ver, min_vxlan_ver,
                                      min_kernel_ver, expecting_ok=True)
