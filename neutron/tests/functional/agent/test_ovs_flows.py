# Copyright (c) 2015 Mirantis, Inc.
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

import eventlet
import fixtures
import mock
import testscenarios

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import importutils
from testtools.content import text_content

from neutron.agent.common import utils
from neutron.agent.linux import ip_lib
from neutron.cmd.sanity import checks
from neutron.common import constants as n_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_neutron_agent as ovsagt
from neutron.tests import base as tests_base
from neutron.tests.common import base as common_base
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent import test_ovs_lib
from neutron.tests.functional import base
from neutron.tests import tools


OVS_TRACE_FINAL_FLOW = 'Final flow'
OVS_TRACE_DATAPATH_ACTIONS = 'Datapath actions'

cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                      'common.config')


class OVSAgentTestBase(test_ovs_lib.OVSBridgeTestBase,
                       base.BaseSudoTestCase):
    scenarios = testscenarios.multiply_scenarios([
        ('ofctl', {'main_module': ('neutron.plugins.ml2.drivers.openvswitch.'
                                  'agent.openflow.ovs_ofctl.main')}),
        ('native', {'main_module': ('neutron.plugins.ml2.drivers.openvswitch.'
                                  'agent.openflow.native.main')})],
        test_ovs_lib.OVSBridgeTestBase.scenarios)

    def setUp(self):
        super(OVSAgentTestBase, self).setUp()
        self.br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.of_interface_mod = importutils.import_module(self.main_module)
        self.br_int_cls = None
        self.br_tun_cls = None
        self.br_phys_cls = None
        self.br_int = None
        self.init_done = False
        self.init_done_ev = eventlet.event.Event()
        self.main_ev = eventlet.event.Event()
        self.addCleanup(self._kill_main)
        retry_count = 3
        while True:
            cfg.CONF.set_override('of_listen_port',
                                  net_helpers.get_free_namespace_port(
                                      n_const.PROTO_NAME_TCP),
                                  group='OVS')
            self.of_interface_mod.init_config()
            self._main_thread = eventlet.spawn(self._kick_main)

            # Wait for _kick_main -> of_interface main -> _agent_main
            # NOTE(yamamoto): This complexity came from how "native"
            # of_interface runs its openflow controller.  "native"
            # of_interface's main routine blocks while running the
            # embedded openflow controller.  In that case, the agent
            # rpc_loop runs in another thread.  However, for FT we
            # need to run setUp() and test_xxx() in the same thread.
            # So I made this run of_interface's main in a separate
            # thread instead.
            try:
                while not self.init_done:
                    self.init_done_ev.wait()
                break
            except fixtures.TimeoutException:
                self._kill_main()
            retry_count -= 1
            if retry_count < 0:
                raise Exception('port allocation failed')

    def _run_trace(self, brname, spec):
        required_keys = [OVS_TRACE_FINAL_FLOW, OVS_TRACE_DATAPATH_ACTIONS]
        t = utils.execute(["ovs-appctl", "ofproto/trace", brname, spec],
                          run_as_root=True)
        trace = {}
        trace_lines = t.splitlines()
        for line in trace_lines:
            (l, sep, r) = line.partition(':')
            if not sep:
                continue
            elif l in required_keys:
                trace[l] = r
        for k in required_keys:
            if k not in trace:
                self.fail("%s not found in trace %s" % (k, trace_lines))

        return trace

    def _kick_main(self):
        with mock.patch.object(ovsagt, 'main', self._agent_main):
            self.of_interface_mod.main()

    def _kill_main(self):
        self.main_ev.send()
        self._main_thread.wait()

    def _agent_main(self, bridge_classes):
        self.br_int_cls = bridge_classes['br_int']
        self.br_phys_cls = bridge_classes['br_phys']
        self.br_tun_cls = bridge_classes['br_tun']
        self.br_int = self.br_int_cls(self.br.br_name)
        self.br_int.set_secure_mode()
        self.br_int.setup_controllers(cfg.CONF)
        self.br_int.setup_default_table()

        # signal to setUp()
        self.init_done = True
        self.init_done_ev.send()

        self.main_ev.wait()


class ARPSpoofTestCase(OVSAgentTestBase):
    def setUp(self):
        # NOTE(kevinbenton): it would be way cooler to use scapy for
        # these but scapy requires the python process to be running as
        # root to bind to the ports.
        self.addOnException(self.collect_flows_and_ports)
        super(ARPSpoofTestCase, self).setUp()
        self.skip_without_arp_support()
        self.src_addr = '192.168.0.1'
        self.dst_addr = '192.168.0.2'
        self.src_namespace = self.useFixture(
            net_helpers.NamespaceFixture()).name
        self.dst_namespace = self.useFixture(
            net_helpers.NamespaceFixture()).name
        self.src_p = self.useFixture(
            net_helpers.OVSPortFixture(self.br, self.src_namespace)).port
        self.dst_p = self.useFixture(
            net_helpers.OVSPortFixture(self.br, self.dst_namespace)).port
        # wait to add IPs until after anti-spoof rules to ensure ARP doesn't
        # happen before

    def collect_flows_and_ports(self, exc_info):
        nicevif = lambda x: ['%s=%s' % (k, getattr(x, k))
                             for k in ['ofport', 'port_name', 'switch',
                                       'vif_id', 'vif_mac']]
        nicedev = lambda x: ['%s=%s' % (k, getattr(x, k))
                             for k in ['name', 'namespace']] + x.addr.list()
        details = {'flows': self.br.dump_all_flows(),
                   'vifs': map(nicevif, self.br.get_vif_ports()),
                   'src_ip': self.src_addr,
                   'dest_ip': self.dst_addr,
                   'sourt_port': nicedev(self.src_p),
                   'dest_port': nicedev(self.dst_p)}
        self.addDetail('arp-test-state',
                       text_content(jsonutils.dumps(details, indent=5)))

    @common_base.no_skip_on_missing_deps
    def skip_without_arp_support(self):
        if not checks.arp_header_match_supported():
            self.skipTest("ARP header matching not supported")

    def test_arp_spoof_doesnt_block_normal_traffic(self):
        self._setup_arp_spoof_for_port(self.src_p.name, [self.src_addr])
        self._setup_arp_spoof_for_port(self.dst_p.name, [self.dst_addr])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_mac_spoof_blocks_wrong_mac(self):
        self._setup_arp_spoof_for_port(self.src_p.name, [self.src_addr])
        self._setup_arp_spoof_for_port(self.dst_p.name, [self.dst_addr])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)
        # changing the allowed mac should stop the port from working
        self._setup_arp_spoof_for_port(self.src_p.name, [self.src_addr],
                                       mac='00:11:22:33:44:55')
        net_helpers.assert_no_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_doesnt_block_ipv6(self):
        self.src_addr = '2000::1'
        self.dst_addr = '2000::2'
        self._setup_arp_spoof_for_port(self.src_p.name, [self.src_addr])
        self._setup_arp_spoof_for_port(self.dst_p.name, [self.dst_addr])
        self.src_p.addr.add('%s/64' % self.src_addr)
        self.dst_p.addr.add('%s/64' % self.dst_addr)
        # make sure the IPv6 addresses are ready before pinging
        self.src_p.addr.wait_until_address_ready(self.src_addr)
        self.dst_p.addr.wait_until_address_ready(self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_blocks_response(self):
        # this will prevent the destination from responding to the ARP
        # request for it's own address
        self._setup_arp_spoof_for_port(self.dst_p.name, ['192.168.0.3'])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_no_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_blocks_icmpv6_neigh_advt(self):
        self.src_addr = '2000::1'
        self.dst_addr = '2000::2'
        # this will prevent the destination from responding (i.e., icmpv6
        # neighbour advertisement) to the icmpv6 neighbour solicitation
        # request for it's own address (2000::2) as spoofing rules added
        # below only allow '2000::3'.
        self._setup_arp_spoof_for_port(self.dst_p.name, ['2000::3'])
        self.src_p.addr.add('%s/64' % self.src_addr)
        self.dst_p.addr.add('%s/64' % self.dst_addr)
        # make sure the IPv6 addresses are ready before pinging
        self.src_p.addr.wait_until_address_ready(self.src_addr)
        self.dst_p.addr.wait_until_address_ready(self.dst_addr)
        net_helpers.assert_no_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_blocks_request(self):
        # this will prevent the source from sending an ARP
        # request with its own address
        self._setup_arp_spoof_for_port(self.src_p.name, ['192.168.0.3'])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        ns_ip_wrapper = ip_lib.IPWrapper(self.src_namespace)
        try:
            ns_ip_wrapper.netns.execute(['arping', '-I', self.src_p.name,
                                         '-c1', self.dst_addr])
            tools.fail("arping should have failed. The arp request should "
                       "have been blocked.")
        except RuntimeError:
            pass

    def test_arp_spoof_allowed_address_pairs(self):
        self._setup_arp_spoof_for_port(self.dst_p.name, ['192.168.0.3',
                                                         self.dst_addr])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_icmpv6_neigh_advt_allowed_address_pairs(self):
        self.src_addr = '2000::1'
        self.dst_addr = '2000::2'
        self._setup_arp_spoof_for_port(self.dst_p.name, ['2000::3',
                                                         self.dst_addr])
        self.src_p.addr.add('%s/64' % self.src_addr)
        self.dst_p.addr.add('%s/64' % self.dst_addr)
        # make sure the IPv6 addresses are ready before pinging
        self.src_p.addr.wait_until_address_ready(self.src_addr)
        self.dst_p.addr.wait_until_address_ready(self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_allowed_address_pairs_0cidr(self):
        self._setup_arp_spoof_for_port(self.dst_p.name, ['9.9.9.9/0',
                                                         '1.2.3.4'])
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_disable_port_security(self):
        # block first and then disable port security to make sure old rules
        # are cleared
        self._setup_arp_spoof_for_port(self.dst_p.name, ['192.168.0.3'])
        self._setup_arp_spoof_for_port(self.dst_p.name, ['192.168.0.3'],
                                       psec=False)
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def test_arp_spoof_disable_network_port(self):
        # block first and then disable port security to make sure old rules
        # are cleared
        self._setup_arp_spoof_for_port(self.dst_p.name, ['192.168.0.3'])
        self._setup_arp_spoof_for_port(
            self.dst_p.name, ['192.168.0.3'],
            device_owner=n_const.DEVICE_OWNER_ROUTER_GW)
        self.src_p.addr.add('%s/24' % self.src_addr)
        self.dst_p.addr.add('%s/24' % self.dst_addr)
        net_helpers.assert_ping(self.src_namespace, self.dst_addr, count=2)

    def _setup_arp_spoof_for_port(self, port, addrs, psec=True,
                                  device_owner='nobody', mac=None):
        vif = next(
            vif for vif in self.br.get_vif_ports() if vif.port_name == port)
        ip_addr = addrs.pop()
        details = {'port_security_enabled': psec,
                   'fixed_ips': [{'ip_address': ip_addr}],
                   'device_owner': device_owner,
                   'allowed_address_pairs': [
                        dict(ip_address=ip) for ip in addrs]}
        if mac:
            vif.vif_mac = mac
        ovsagt.OVSNeutronAgent.setup_arp_spoofing_protection(
            self.br_int, vif, details)


class CanaryTableTestCase(OVSAgentTestBase):
    def test_canary_table(self):
        self.br_int.delete_flows()
        self.assertEqual(constants.OVS_RESTARTED,
                         self.br_int.check_canary_table())
        self.br_int.setup_canary_table()
        self.assertEqual(constants.OVS_NORMAL,
                         self.br_int.check_canary_table())


class OVSFlowTestCase(OVSAgentTestBase):
    """Tests defined in this class use ovs-appctl ofproto/trace commands,
    which simulate processing of imaginary packets, to check desired actions
    are correctly set up by OVS flows.  In this way, subtle variations in
    flows between of_interface drivers are absorbed and the same tests work
    against those drivers.
    """

    def setUp(self):
        cfg.CONF.set_override('enable_distributed_routing',
                              True,
                              group='AGENT')
        super(OVSFlowTestCase, self).setUp()
        self.phys_br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.br_phys = self.br_phys_cls(self.phys_br.br_name)
        self.br_phys.set_secure_mode()
        self.br_phys.setup_controllers(cfg.CONF)
        self.router_addr = '192.168.0.1/24'
        self.namespace = self.useFixture(
            net_helpers.NamespaceFixture()).name
        self.phys_p = self.useFixture(
            net_helpers.OVSPortFixture(self.br_phys, self.namespace)).port

        self.tun_br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.br_tun = self.br_tun_cls(self.tun_br.br_name)
        self.br_tun.set_secure_mode()
        self.br_tun.setup_controllers(cfg.CONF)
        self.tun_p = self.br_tun.add_patch_port(
            cfg.CONF.OVS.tun_peer_patch_port,
            cfg.CONF.OVS.int_peer_patch_port)
        self.br_tun.setup_default_table(self.tun_p, True)

    def test_provision_local_vlan(self):
        kwargs = {'port': 123, 'lvid': 888, 'segmentation_id': 777}
        self.br_phys.provision_local_vlan(distributed=False, **kwargs)
        trace = self._run_trace(self.phys_br.br_name,
                                "in_port=%(port)d,dl_src=12:34:56:78:aa:bb,"
                                "dl_dst=24:12:56:78:aa:bb,dl_type=0x0800,"
                                "nw_src=192.168.0.1,nw_dst=192.168.0.2,"
                                "nw_proto=1,nw_tos=0,nw_ttl=128,"
                                "icmp_type=8,icmp_code=0,dl_vlan=%(lvid)d"
                                % kwargs)
        self.assertTrue(("dl_vlan=%(segmentation_id)d" % kwargs) in
                        trace["Final flow"])

    def test_install_dvr_to_src_mac(self):
        other_dvr_mac = 'fa:16:3f:01:de:ad'
        other_dvr_port = 333
        kwargs = {'vlan_tag': 888,
                  'gateway_mac': '12:34:56:78:aa:bb',
                  'dst_mac': '12:34:56:78:cc:dd',
                  'dst_port': 123}
        self.br_int.install_dvr_to_src_mac(network_type='vlan', **kwargs)
        self.br_int.add_dvr_mac_vlan(mac=other_dvr_mac, port=other_dvr_port)

        trace = self._run_trace(self.br.br_name,
                                "in_port=%d," % other_dvr_port +
                                "dl_src=" + other_dvr_mac + "," +
                                "dl_dst=%(dst_mac)s,dl_type=0x0800,"
                                "nw_src=192.168.0.1,nw_dst=192.168.0.2,"
                                "nw_proto=1,nw_tos=0,nw_ttl=128,"
                                "icmp_type=8,icmp_code=0,"
                                "dl_vlan=%(vlan_tag)d" % kwargs)
        self.assertTrue("vlan_tci=0x0000" in trace["Final flow"])
        self.assertTrue(("dl_src=%(gateway_mac)s" % kwargs) in
                        trace["Final flow"])

    def test_install_flood_to_tun(self):
        attrs = {
            'remote_ip': '192.0.2.1',  # RFC 5737 TEST-NET-1
            'local_ip': '198.51.100.1',  # RFC 5737 TEST-NET-2
        }
        kwargs = {'vlan': 777, 'tun_id': 888}
        port_name = tests_base.get_rand_device_name(net_helpers.PORT_PREFIX)
        ofport = self.br_tun.add_tunnel_port(port_name, attrs['remote_ip'],
                                             attrs['local_ip'])
        self.br_tun.install_flood_to_tun(ports=[ofport], **kwargs)
        test_packet = ("icmp,in_port=%d," % self.tun_p +
                       "dl_src=12:34:56:ab:cd:ef,dl_dst=12:34:56:78:cc:dd,"
                       "nw_src=192.168.0.1,nw_dst=192.168.0.2,nw_ecn=0,"
                       "nw_tos=0,nw_ttl=128,icmp_type=8,icmp_code=0,"
                       "dl_vlan=%(vlan)d,dl_vlan_pcp=0" % kwargs)
        trace = self._run_trace(self.tun_br.br_name, test_packet)
        self.assertTrue(("tun_id=0x%(tun_id)x" % kwargs) in
                        trace["Final flow"])
        self.assertTrue("vlan_tci=0x0000," in trace["Final flow"])

        self.br_tun.delete_flood_to_tun(kwargs['vlan'])

        trace = self._run_trace(self.tun_br.br_name, test_packet)
        self.assertEqual(" unchanged", trace["Final flow"])
        self.assertTrue("drop" in trace["Datapath actions"])
