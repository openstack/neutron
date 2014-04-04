# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Nicira, Inc.
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
# @author: Dan Wendlandt, Nicira, Inc.

import mock
import mox
import testtools

from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import uuidutils
from neutron.tests import base


class TestBaseOVS(base.BaseTestCase):

    def setUp(self):
        super(TestBaseOVS, self).setUp()
        self.root_helper = 'sudo'
        self.ovs = ovs_lib.BaseOVS(self.root_helper)
        self.br_name = 'bridge1'

    def test_add_bridge(self):
        with mock.patch.object(self.ovs, 'run_vsctl') as mock_vsctl:
            bridge = self.ovs.add_bridge(self.br_name)

        mock_vsctl.assert_called_with(["--", "--may-exist",
                                       "add-br", self.br_name])
        self.assertEqual(bridge.br_name, self.br_name)
        self.assertEqual(bridge.root_helper, self.ovs.root_helper)

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
    """A test suite to excercise the OVS libraries shared by Neutron agents.

    Note: these tests do not actually execute ovs-* utilities, and thus
    can run on any system.  That does, however, limit their scope.
    """

    def setUp(self):
        super(OVS_Lib_Test, self).setUp()
        self.BR_NAME = "br-int"
        self.TO = "--timeout=2"

        self.mox = mox.Mox()
        self.root_helper = 'sudo'
        self.br = ovs_lib.OVSBridge(self.BR_NAME, self.root_helper)
        self.mox.StubOutWithMock(utils, "execute")
        self.addCleanup(self.mox.UnsetStubs)

    def test_vifport(self):
        """Create and stringify vif port, confirm no exceptions."""
        self.mox.ReplayAll()

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

        self.mox.VerifyAll()

    def test_create(self):
        self.br.add_bridge(self.BR_NAME)
        self.mox.ReplayAll()

        self.br.create()
        self.mox.VerifyAll()

    def test_destroy(self):
        self.br.delete_bridge(self.BR_NAME)
        self.mox.ReplayAll()

        self.br.destroy()
        self.mox.VerifyAll()

    def test_reset_bridge(self):
        self.br.destroy()
        self.br.create()
        self.mox.ReplayAll()

        self.br.reset_bridge()
        self.mox.VerifyAll()

    def test_delete_port(self):
        pname = "tap5"
        utils.execute(["ovs-vsctl", self.TO, "--", "--if-exists",
                       "del-port", self.BR_NAME, pname],
                      root_helper=self.root_helper)

        self.mox.ReplayAll()
        self.br.delete_port(pname)
        self.mox.VerifyAll()

    def test_add_flow(self):
        ofport = "99"
        vid = 4000
        lsw_id = 18
        cidr = '192.168.1.0/24'
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,dl_src=ca:fe:de:ad:be:ef"
                       ",actions=strip_vlan,output:0"],
                      root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=1,actions=normal"],
                      root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,actions=drop"],
                      root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=2,in_port=%s,actions=drop" % ofport],
                      root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=4,in_port=%s,dl_vlan=%s,"
                       "actions=strip_vlan,set_tunnel:%s,normal"
                       % (ofport, vid, lsw_id)],
                      root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=3,tun_id=%s,actions="
                       "mod_vlan_vid:%s,output:%s"
                       % (lsw_id, vid, ofport)], root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "add-flow", self.BR_NAME,
                       "hard_timeout=0,idle_timeout=0,"
                       "priority=4,arp,nw_src=%s,actions=drop" % cidr],
                      root_helper=self.root_helper)
        self.mox.ReplayAll()

        self.br.add_flow(priority=2, dl_src="ca:fe:de:ad:be:ef",
                         actions="strip_vlan,output:0")
        self.br.add_flow(priority=1, actions="normal")
        self.br.add_flow(priority=2, actions="drop")
        self.br.add_flow(priority=2, in_port=ofport, actions="drop")

        self.br.add_flow(priority=4, in_port=ofport, dl_vlan=vid,
                         actions="strip_vlan,set_tunnel:%s,normal" %
                         (lsw_id))
        self.br.add_flow(priority=3, tun_id=lsw_id,
                         actions="mod_vlan_vid:%s,output:%s" %
                         (vid, ofport))
        self.br.add_flow(priority=4, proto='arp', nw_src=cidr, actions='drop')
        self.mox.VerifyAll()

    def test_get_port_ofport(self):
        pname = "tap99"
        ofport = "6"
        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Interface", pname, "ofport"],
                      root_helper=self.root_helper).AndReturn(ofport)
        self.mox.ReplayAll()

        self.assertEqual(self.br.get_port_ofport(pname), ofport)
        self.mox.VerifyAll()

    def test_get_datapath_id(self):
        datapath_id = '"0000b67f4fbcc149"'
        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Bridge", self.BR_NAME, "datapath_id"],
                      root_helper=self.root_helper).AndReturn(datapath_id)
        self.mox.ReplayAll()

        self.assertEqual(self.br.get_datapath_id(), datapath_id.strip('"'))
        self.mox.VerifyAll()

    def test_count_flows(self):
        utils.execute(["ovs-ofctl", "dump-flows", self.BR_NAME],
                      root_helper=self.root_helper,
                      process_input=None).AndReturn('ignore\nflow-1\n')
        self.mox.ReplayAll()

        # counts the number of flows as total lines of output - 2
        self.assertEqual(self.br.count_flows(), 1)
        self.mox.VerifyAll()

    def test_delete_flow(self):
        ofport = "5"
        lsw_id = 40
        vid = 39
        utils.execute(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "in_port=" + ofport], root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "tun_id=%s" % lsw_id], root_helper=self.root_helper)
        utils.execute(["ovs-ofctl", "del-flows", self.BR_NAME,
                       "dl_vlan=%s" % vid], root_helper=self.root_helper)
        self.mox.ReplayAll()

        self.br.delete_flows(in_port=ofport)
        self.br.delete_flows(tun_id=lsw_id)
        self.br.delete_flows(dl_vlan=vid)
        self.mox.VerifyAll()

    def test_defer_apply_flows(self):
        self.mox.StubOutWithMock(self.br, 'add_or_mod_flow_str')
        self.br.add_or_mod_flow_str(
            flow='added_flow_1').AndReturn('added_flow_1')
        self.br.add_or_mod_flow_str(
            flow='added_flow_2').AndReturn('added_flow_2')

        self.mox.StubOutWithMock(self.br, '_build_flow_expr_arr')
        self.br._build_flow_expr_arr(delete=True,
                                     flow='deleted_flow_1'
                                     ).AndReturn(['deleted_flow_1'])
        self.mox.StubOutWithMock(self.br, 'run_ofctl')
        self.br.run_ofctl('add-flows', ['-'], 'added_flow_1\nadded_flow_2\n')
        self.br.run_ofctl('del-flows', ['-'], 'deleted_flow_1\n')
        self.mox.ReplayAll()

        self.br.defer_apply_on()
        self.br.add_flow(flow='added_flow_1')
        self.br.defer_apply_on()
        self.br.add_flow(flow='added_flow_2')
        self.br.delete_flows(flow='deleted_flow_1')
        self.br.defer_apply_off()
        self.mox.VerifyAll()

    def test_add_tunnel_port(self):
        pname = "tap99"
        local_ip = "1.1.1.1"
        remote_ip = "9.9.9.9"
        ofport = "6"

        utils.execute(["ovs-vsctl", self.TO, '--', "--may-exist", "add-port",
                       self.BR_NAME, pname], root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "type=gre"], root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "options:remote_ip=" + remote_ip],
                      root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "options:local_ip=" + local_ip],
                      root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "options:in_key=flow"],
                      root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "options:out_key=flow"],
                      root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Interface", pname, "ofport"],
                      root_helper=self.root_helper).AndReturn(ofport)
        self.mox.ReplayAll()

        self.assertEqual(
            self.br.add_tunnel_port(pname, remote_ip, local_ip),
            ofport)
        self.mox.VerifyAll()

    def test_add_patch_port(self):
        pname = "tap99"
        peer = "bar10"
        ofport = "6"

        utils.execute(["ovs-vsctl", self.TO, "add-port",
                       self.BR_NAME, pname], root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set", "Interface",
                       pname, "type=patch"], root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "set",
                       "Interface", pname, "options:peer=" + peer],
                      root_helper=self.root_helper)
        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Interface", pname, "ofport"],
                      root_helper=self.root_helper).AndReturn(ofport)
        self.mox.ReplayAll()

        self.assertEqual(self.br.add_patch_port(pname, peer), ofport)
        self.mox.VerifyAll()

    def _test_get_vif_ports(self, is_xen=False):
        pname = "tap99"
        ofport = "6"
        vif_id = uuidutils.generate_uuid()
        mac = "ca:fe:de:ad:be:ef"

        utils.execute(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                      root_helper=self.root_helper).AndReturn("%s\n" % pname)

        if is_xen:
            external_ids = ('{xs-vif-uuid="%s", attached-mac="%s"}'
                            % (vif_id, mac))
        else:
            external_ids = ('{iface-id="%s", attached-mac="%s"}'
                            % (vif_id, mac))

        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Interface", pname, "external_ids"],
                      root_helper=self.root_helper).AndReturn(external_ids)
        utils.execute(["ovs-vsctl", self.TO, "get",
                       "Interface", pname, "ofport"],
                      root_helper=self.root_helper).AndReturn(ofport)
        if is_xen:
            utils.execute(["xe", "vif-param-get", "param-name=other-config",
                           "param-key=nicira-iface-id", "uuid=" + vif_id],
                          root_helper=self.root_helper).AndReturn(vif_id)
        self.mox.ReplayAll()

        ports = self.br.get_vif_ports()
        self.assertEqual(1, len(ports))
        self.assertEqual(ports[0].port_name, pname)
        self.assertEqual(ports[0].ofport, ofport)
        self.assertEqual(ports[0].vif_id, vif_id)
        self.assertEqual(ports[0].vif_mac, mac)
        self.assertEqual(ports[0].switch.br_name, self.BR_NAME)
        self.mox.VerifyAll()

    def _encode_ovs_json(self, headings, data):
        # See man ovs-vsctl(8) for the encoding details.
        r = {"data": [],
             "headings": headings}
        for row in data:
            ovs_row = []
            r["data"].append(ovs_row)
            for cell in row:
                if isinstance(cell, str):
                    ovs_row.append(cell)
                elif isinstance(cell, dict):
                    ovs_row.append(["map", cell.items()])
                else:
                    raise TypeError('%r not str or dict' % type(cell))
        return jsonutils.dumps(r)

    def _test_get_vif_port_set(self, is_xen):
        utils.execute(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                      root_helper=self.root_helper).AndReturn('tap99\ntun22')

        if is_xen:
            id_key = 'xs-vif-uuid'
        else:
            id_key = 'iface-id'

        headings = ['name', 'external_ids']
        data = [
            # A vif port on this bridge:
            ['tap99', {id_key: 'tap99id', 'attached-mac': 'tap99mac'}],
            # A vif port on another bridge:
            ['tap88', {id_key: 'tap88id', 'attached-mac': 'tap88id'}],
            # Non-vif port on this bridge:
            ['tun22', {}],
        ]

        utils.execute(["ovs-vsctl", self.TO, "--format=json",
                       "--", "--columns=name,external_ids",
                       "list", "Interface"],
                      root_helper=self.root_helper).AndReturn(
                          self._encode_ovs_json(headings, data))

        if is_xen:
            self.mox.StubOutWithMock(self.br, 'get_xapi_iface_id')
            self.br.get_xapi_iface_id('tap99id').AndReturn('tap99id')

        self.mox.ReplayAll()

        port_set = self.br.get_vif_port_set()
        self.assertEqual(set(['tap99id']), port_set)
        self.mox.VerifyAll()

    def test_get_vif_ports_nonxen(self):
        self._test_get_vif_ports(False)

    def test_get_vif_ports_xen(self):
        self._test_get_vif_ports(True)

    def test_get_vif_port_set_nonxen(self):
        self._test_get_vif_port_set(False)

    def test_get_vif_port_set_xen(self):
        self._test_get_vif_port_set(True)

    def test_get_vif_port_set_list_ports_error(self):
        utils.execute(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                      root_helper=self.root_helper).AndRaise(RuntimeError())
        utils.execute(["ovs-vsctl", self.TO, "--format=json",
                       "--", "--columns=name,external_ids",
                       "list", "Interface"],
                      root_helper=self.root_helper).AndReturn(
                          self._encode_ovs_json(['name', 'external_ids'], []))
        self.mox.ReplayAll()
        self.assertEqual(set(), self.br.get_vif_port_set())
        self.mox.VerifyAll()

    def test_get_vif_port_set_list_interface_error(self):
        utils.execute(["ovs-vsctl", self.TO, "list-ports", self.BR_NAME],
                      root_helper=self.root_helper).AndRaise('tap99\n')
        utils.execute(["ovs-vsctl", self.TO, "--format=json",
                       "--", "--columns=name,external_ids",
                       "list", "Interface"],
                      root_helper=self.root_helper).AndRaise(RuntimeError())
        self.mox.ReplayAll()
        self.assertEqual(set(), self.br.get_vif_port_set())
        self.mox.VerifyAll()

    def test_clear_db_attribute(self):
        pname = "tap77"
        utils.execute(["ovs-vsctl", self.TO, "clear", "Port",
                       pname, "tag"], root_helper=self.root_helper)
        self.mox.ReplayAll()
        self.br.clear_db_attribute("Port", pname, "tag")
        self.mox.VerifyAll()

    def test_port_id_regex(self):
        result = ('external_ids        : {attached-mac="fa:16:3e:23:5b:f2",'
                  ' iface-id="5c1321a7-c73f-4a77-95e6-9f86402e5c8f",'
                  ' iface-status=active}\nname                :'
                  ' "dhc5c1321a7-c7"\nofport              : 2\n')
        match = self.br.re_id.search(result)
        vif_mac = match.group('vif_mac')
        vif_id = match.group('vif_id')
        port_name = match.group('port_name')
        ofport = int(match.group('ofport'))
        self.assertEqual(vif_mac, 'fa:16:3e:23:5b:f2')
        self.assertEqual(vif_id, '5c1321a7-c73f-4a77-95e6-9f86402e5c8f')
        self.assertEqual(port_name, 'dhc5c1321a7-c7')
        self.assertEqual(ofport, 2)

    def test_iface_to_br(self):
        iface = 'tap0'
        br = 'br-int'
        root_helper = 'sudo'
        utils.execute(["ovs-vsctl", self.TO, "iface-to-br", iface],
                      root_helper=root_helper).AndReturn('br-int')

        self.mox.ReplayAll()
        self.assertEqual(ovs_lib.get_bridge_for_iface(root_helper, iface), br)
        self.mox.VerifyAll()

    def test_iface_to_br_handles_ovs_vsctl_exception(self):
        iface = 'tap0'
        root_helper = 'sudo'
        utils.execute(["ovs-vsctl", self.TO, "iface-to-br", iface],
                      root_helper=root_helper).AndRaise(Exception)

        self.mox.ReplayAll()
        self.assertIsNone(ovs_lib.get_bridge_for_iface(root_helper, iface))
        self.mox.VerifyAll()

    def test_delete_all_ports(self):
        self.mox.StubOutWithMock(self.br, 'get_port_name_list')
        self.br.get_port_name_list().AndReturn(['port1'])
        self.mox.StubOutWithMock(self.br, 'delete_port')
        self.br.delete_port('port1')
        self.mox.ReplayAll()
        self.br.delete_ports(all_ports=True)
        self.mox.VerifyAll()

    def test_delete_neutron_ports(self):
        port1 = ovs_lib.VifPort('tap1234', 1, uuidutils.generate_uuid(),
                                'ca:fe:de:ad:be:ef', 'br')
        port2 = ovs_lib.VifPort('tap5678', 2, uuidutils.generate_uuid(),
                                'ca:ee:de:ad:be:ef', 'br')
        self.mox.StubOutWithMock(self.br, 'get_vif_ports')
        self.br.get_vif_ports().AndReturn([port1, port2])
        self.mox.StubOutWithMock(self.br, 'delete_port')
        self.br.delete_port('tap1234')
        self.br.delete_port('tap5678')
        self.mox.ReplayAll()
        self.br.delete_ports(all_ports=False)
        self.mox.VerifyAll()

    def test_get_bridges(self):
        bridges = ['br-int', 'br-ex']
        root_helper = 'sudo'
        utils.execute(["ovs-vsctl", self.TO, "list-br"],
                      root_helper=root_helper).AndReturn('br-int\nbr-ex\n')

        self.mox.ReplayAll()
        self.assertEqual(ovs_lib.get_bridges(root_helper), bridges)
        self.mox.VerifyAll()

    def test_get_local_port_mac_succeeds(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address='foo')):
            self.assertEqual('foo', self.br.get_local_port_mac())

    def test_get_local_port_mac_raises_exception_for_missing_mac(self):
        with mock.patch('neutron.agent.linux.ip_lib.IpLinkCommand',
                        return_value=mock.Mock(address=None)):
            with testtools.ExpectedException(Exception):
                self.br.get_local_port_mac()
