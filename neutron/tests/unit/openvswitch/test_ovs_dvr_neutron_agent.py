# Copyright (c) 2012 OpenStack Foundation.
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

import mock
from oslo_config import cfg
import oslo_messaging

from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_neutron_agent
from neutron.plugins.openvswitch.common import constants
from neutron.tests import base


NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
OVS_LINUX_KERN_VERS_WITHOUT_VXLAN = "3.12.0"

FAKE_MAC = '00:11:22:33:44:55'
FAKE_IP1 = '10.0.0.1'
FAKE_IP2 = '10.0.0.2'


class CreateAgentConfigMapDvr(base.BaseTestCase):

    def test_create_agent_config_map_enable_distributed_routing(self):
        self.addCleanup(cfg.CONF.reset)
        # Verify setting only enable_tunneling will default tunnel_type to GRE
        cfg.CONF.set_override('enable_distributed_routing', True,
                              group='AGENT')
        cfgmap = ovs_neutron_agent.create_agent_config_map(cfg.CONF)
        self.assertEqual(cfgmap['enable_distributed_routing'], True)


class TestOvsDvrNeutronAgent(base.BaseTestCase):

    def setUp(self):
        super(TestOvsDvrNeutronAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        kwargs = ovs_neutron_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('neutron.plugins.openvswitch.agent.ovs_neutron_agent.'
                       'OVSNeutronAgent.setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('neutron.plugins.openvswitch.agent.ovs_neutron_agent.'
                       'OVSNeutronAgent.setup_ancillary_bridges',
                       return_value=[]),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.ovs_lib.BaseOVS.get_bridges'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            self.agent = ovs_neutron_agent.OVSNeutronAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            self.agent.use_call = True
            self.agent.tun_br = mock.Mock()
        self.agent.sg_agent = mock.Mock()

    def _setup_for_dvr_test(self, ofport=10):
        self._port = mock.Mock()
        self._port.ofport = ofport
        self._port.vif_id = "1234-5678-90"
        self._physical_network = 'physeth1'
        self._old_local_vlan = None
        self._segmentation_id = 2001
        self.agent.enable_distributed_routing = True
        self.agent.enable_tunneling = True
        self.agent.patch_tun_ofport = 1
        self.agent.patch_int_ofport = 2
        self.agent.dvr_agent.local_ports = {}
        self.agent.local_vlan_map = {}
        self.agent.dvr_agent.enable_distributed_routing = True
        self.agent.dvr_agent.enable_tunneling = True
        self.agent.dvr_agent.patch_tun_ofport = 1
        self.agent.dvr_agent.patch_int_ofport = 2
        self.agent.dvr_agent.tun_br = mock.Mock()
        self.agent.dvr_agent.phys_brs[self._physical_network] = mock.Mock()
        self.agent.dvr_agent.bridge_mappings = {self._physical_network:
                                                'br-eth1'}
        self.agent.dvr_agent.int_ofports[self._physical_network] = 30
        self.agent.dvr_agent.phys_ofports[self._physical_network] = 40
        self.agent.dvr_agent.local_dvr_map = {}
        self.agent.dvr_agent.registered_dvr_macs = set()
        self.agent.dvr_agent.dvr_mac_address = 'aa:22:33:44:55:66'
        self._net_uuid = 'my-net-uuid'
        self._fixed_ips = [{'subnet_id': 'my-subnet-uuid',
                            'ip_address': '1.1.1.1'}]
        self._compute_port = mock.Mock()
        self._compute_port.ofport = 20
        self._compute_port.vif_id = "1234-5678-91"
        self._compute_fixed_ips = [{'subnet_id': 'my-subnet-uuid',
                                    'ip_address': '1.1.1.3'}]

    def _test_port_bound_for_dvr_on_vlan_network(self, device_owner,
                                                 ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        self._port.vif_mac = gateway_mac = 'aa:bb:cc:11:22:33'
        self._compute_port.vif_mac = '77:88:99:00:11:22'
        physical_network = self._physical_network
        segmentation_id = self._segmentation_id
        network_type = p_const.TYPE_VLAN
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=str(self._old_local_vlan)),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_subnet_for_dvr',
                                  return_value={
                                      'gateway_ip': gateway_ip,
                                      'cidr': cidr,
                                      'ip_version': ip_version,
                                      'gateway_mac': gateway_mac}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows'),
                mock.patch.object(
                    self.agent.dvr_agent.phys_brs[physical_network],
                    'add_flow'),
                mock.patch.object(
                    self.agent.dvr_agent.phys_brs[physical_network],
                    'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn, add_flow_phys_fn,
                  delete_flows_phys_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, network_type,
                    physical_network, segmentation_id, self._fixed_ips,
                    n_const.DEVICE_OWNER_DVR_INTERFACE, False)
                lvm = self.agent.local_vlan_map[self._net_uuid]
                phy_ofp = self.agent.dvr_agent.phys_ofports[physical_network]
                int_ofp = self.agent.dvr_agent.int_ofports[physical_network]
                expected_on_phys_br = [
                    mock.call(table=constants.LOCAL_VLAN_TRANSLATION,
                              priority=4,
                              in_port=phy_ofp,
                              dl_vlan=lvm.vlan,
                              actions="mod_vlan_vid:%s,normal" %
                              (lvm.segmentation_id)),
                    mock.call(table=constants.DVR_PROCESS_VLAN,
                              priority=2,
                              dl_vlan=lvm.vlan,
                              dl_dst=self._port.vif_mac,
                              actions="drop"),
                    mock.call(table=constants.DVR_PROCESS_VLAN,
                              priority=1,
                              dl_vlan=lvm.vlan,
                              dl_src=self._port.vif_mac,
                              actions="mod_dl_src:%s,resubmit(,%s)" %
                              (self.agent.dvr_agent.dvr_mac_address,
                               constants.LOCAL_VLAN_TRANSLATION))
                            ]
                if ip_version == 4:
                    expected_on_phys_br.insert(1, mock.call(
                        proto='arp',
                        nw_dst=gateway_ip, actions='drop',
                        priority=3, table=constants.DVR_PROCESS_VLAN,
                        dl_vlan=lvm.vlan))
                else:
                    expected_on_phys_br.insert(1, mock.call(
                        icmp_type=n_const.ICMPV6_TYPE_RA, proto='icmp6',
                        dl_src=self._port.vif_mac, actions='drop',
                        priority=3, table=constants.DVR_PROCESS_VLAN,
                        dl_vlan=lvm.vlan))
                self.assertEqual(expected_on_phys_br,
                                 add_flow_phys_fn.call_args_list)
                self.agent.port_bound(self._compute_port, self._net_uuid,
                                      network_type, physical_network,
                                      segmentation_id,
                                      self._compute_fixed_ips,
                                      device_owner, False)
                expected_on_int_br = [
                    mock.call(priority=3,
                              in_port=int_ofp,
                              dl_vlan=lvm.segmentation_id,
                              actions="mod_vlan_vid:%s,normal" % lvm.vlan),
                    mock.call(table=constants.DVR_TO_SRC_MAC_VLAN,
                              priority=4,
                              dl_dst=self._compute_port.vif_mac,
                              dl_vlan=lvm.segmentation_id,
                              actions="strip_vlan,mod_dl_src:%s,"
                              "output:%s" %
                              (gateway_mac,
                               self._compute_port.ofport))
                                      ]
                self.assertEqual(expected_on_int_br,
                                 add_flow_int_fn.call_args_list)
                expected_on_int_br = [
                    mock.call(in_port=self._port.ofport),
                    mock.call(in_port=self._compute_port.ofport)
                                      ]
                self.assertEqual(expected_on_int_br,
                                 delete_flows_int_fn.call_args_list)
                self.assertFalse(add_flow_tun_fn.called)
                self.assertFalse(delete_flows_tun_fn.called)
                self.assertFalse(delete_flows_phys_fn.called)

    def _test_port_bound_for_dvr_on_vxlan_network(self, device_owner,
                                                  ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        network_type = p_const.TYPE_VXLAN
        self._port.vif_mac = gateway_mac = 'aa:bb:cc:11:22:33'
        self._compute_port.vif_mac = '77:88:99:00:11:22'
        physical_network = self._physical_network
        segmentation_id = self._segmentation_id
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=self._old_local_vlan),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                  'get_subnet_for_dvr',
                                  return_value={
                                      'gateway_ip': gateway_ip,
                                      'cidr': cidr,
                                      'ip_version': ip_version,
                                      'gateway_mac': gateway_mac}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows'),
                mock.patch.object(
                    self.agent.dvr_agent.phys_brs[physical_network],
                    'add_flow'),
                mock.patch.object(
                    self.agent.dvr_agent.phys_brs[physical_network],
                    'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn,
                  add_flow_phys_fn, delete_flows_phys_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, network_type,
                    physical_network, segmentation_id, self._fixed_ips,
                    n_const.DEVICE_OWNER_DVR_INTERFACE, False)
                lvm = self.agent.local_vlan_map[self._net_uuid]
                expected_in_tun_br = [
                    mock.call(
                        table=constants.TUN_TABLE['vxlan'],
                        priority=1, tun_id=lvm.segmentation_id,
                        actions="mod_vlan_vid:%s,"
                        "resubmit(,%s)" %
                        (lvm.vlan, constants.DVR_NOT_LEARN)),
                    mock.call(
                        table=constants.DVR_PROCESS, priority=2,
                        dl_vlan=lvm.vlan,
                        dl_dst=self._port.vif_mac,
                        actions='drop'),
                    mock.call(
                        table=constants.DVR_PROCESS, priority=1,
                        dl_vlan=lvm.vlan,
                        dl_src=self._port.vif_mac,
                        actions="mod_dl_src:%s,resubmit(,%s)" % (
                            self.agent.dvr_agent.dvr_mac_address,
                            constants.PATCH_LV_TO_TUN))]
                if ip_version == 4:
                    expected_in_tun_br.insert(1, mock.call(
                        proto='arp',
                        nw_dst=gateway_ip, actions='drop',
                        priority=3, table=constants.DVR_PROCESS,
                        dl_vlan=lvm.vlan))
                else:
                    expected_in_tun_br.insert(1, mock.call(
                        icmp_type=n_const.ICMPV6_TYPE_RA,
                        proto='icmp6',
                        dl_src=self._port.vif_mac,
                        actions='drop',
                        priority=3, table=constants.DVR_PROCESS,
                        dl_vlan=lvm.vlan))
                self.assertEqual(expected_in_tun_br,
                                 add_flow_tun_fn.call_args_list)
                self.agent.port_bound(self._compute_port, self._net_uuid,
                                      network_type, physical_network,
                                      segmentation_id,
                                      self._compute_fixed_ips,
                                      device_owner, False)
                expected_in_int_br = [
                    mock.call(table=constants.DVR_TO_SRC_MAC, priority=4,
                        dl_dst=self._compute_port.vif_mac,
                        dl_vlan=lvm.vlan,
                        actions="strip_vlan,mod_dl_src:%s,"
                        "output:%s" %
                        (gateway_mac, self._compute_port.ofport))
                                ]
                self.assertEqual(expected_in_int_br,
                                 add_flow_int_fn.call_args_list)
                self.assertFalse(add_flow_phys_fn.called)
                expected_in_int_br = [
                    mock.call(in_port=self._port.ofport),
                    mock.call(in_port=self._compute_port.ofport)
                                      ]
                self.assertEqual(expected_in_int_br,
                                 delete_flows_int_fn.call_args_list)
                self.assertFalse(add_flow_phys_fn.called)
                self.assertFalse(delete_flows_tun_fn.called)
                self.assertFalse(delete_flows_phys_fn.called)

    def test_port_bound_for_dvr_with_compute_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner="compute:None")
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner="compute:None", ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner="compute:None")
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner="compute:None", ip_version=6)

    def test_port_bound_for_dvr_with_lbaas_vip_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)

    def test_port_bound_for_dvr_with_dhcp_ports(self):
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_port_bound_for_dvr_on_vlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_port_bound_for_dvr_on_vxlan_network(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)

    def test_port_bound_for_dvr_with_csnat_ports(self, ofport=10):
        self._setup_for_dvr_test()
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=self._old_local_vlan),
                mock.patch.object(
                    self.agent.dvr_agent.plugin_rpc, 'get_subnet_for_dvr',
                    return_value={'gateway_ip': '1.1.1.1',
                                  'cidr': '1.1.1.0/24',
                                  'ip_version': 4,
                                  'gateway_mac': 'aa:bb:cc:11:22:33'}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, 'vxlan',
                    None, None, self._fixed_ips,
                    n_const.DEVICE_OWNER_ROUTER_SNAT,
                    False)
                self.assertTrue(add_flow_int_fn.called)
                self.assertTrue(delete_flows_int_fn.called)

    def test_treat_devices_removed_for_dvr_interface(self, ofport=10):
        self._test_treat_devices_removed_for_dvr_interface(ofport)
        self._test_treat_devices_removed_for_dvr_interface(
            ofport, ip_version=6)

    def _test_treat_devices_removed_for_dvr_interface(self, ofport=10,
                                                      ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=self._old_local_vlan),
                mock.patch.object(
                    self.agent.dvr_agent.plugin_rpc, 'get_subnet_for_dvr',
                    return_value={'gateway_ip': gateway_ip,
                                  'cidr': cidr,
                                  'ip_version': ip_version,
                                  'gateway_mac': 'aa:bb:cc:11:22:33'}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, 'vxlan',
                    None, None, self._fixed_ips,
                    n_const.DEVICE_OWNER_DVR_INTERFACE,
                    False)
                self.assertTrue(add_flow_tun_fn.called)
                self.assertTrue(delete_flows_int_fn.called)

        with contextlib.nested(
            mock.patch.object(self.agent, 'reclaim_local_vlan'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                              return_value=None),
            mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
            mock.patch.object(self.agent.dvr_agent.tun_br,
                              'delete_flows')) as (reclaim_vlan_fn,
                                                   update_dev_down_fn,
                                                   delete_flows_int_fn,
                                                   delete_flows_tun_fn):
                self.agent.treat_devices_removed([self._port.vif_id])
                if ip_version == 4:
                    expected = [mock.call(
                        proto='arp',
                        nw_dst=gateway_ip,
                        table=constants.DVR_PROCESS,
                        dl_vlan=(
                            self.agent.local_vlan_map[self._net_uuid].vlan))]
                else:
                    expected = [mock.call(
                        icmp_type=n_const.ICMPV6_TYPE_RA, proto='icmp6',
                        dl_src='aa:bb:cc:11:22:33',
                        table=constants.DVR_PROCESS,
                        dl_vlan=(
                            self.agent.local_vlan_map[self._net_uuid].vlan))]
                expected.extend([
                    mock.call(
                        table=constants.DVR_PROCESS,
                        dl_dst=self._port.vif_mac,
                        dl_vlan=(
                            self.agent.local_vlan_map[self._net_uuid].vlan)),
                    mock.call(
                        table=constants.DVR_PROCESS,
                        dl_vlan=(
                            self.agent.local_vlan_map[self._net_uuid].vlan),
                        dl_src=self._port.vif_mac)
                ])
                self.assertEqual(expected, delete_flows_tun_fn.call_args_list)

    def _test_treat_devices_removed_for_dvr(self, device_owner, ip_version=4):
        self._setup_for_dvr_test()
        if ip_version == 4:
            gateway_ip = '1.1.1.1'
            cidr = '1.1.1.0/24'
        else:
            gateway_ip = '2001:100::1'
            cidr = '2001:100::0/64'
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=self._old_local_vlan),
                mock.patch.object(
                    self.agent.dvr_agent.plugin_rpc, 'get_subnet_for_dvr',
                    return_value={'gateway_ip': gateway_ip,
                                  'cidr': cidr,
                                  'ip_version': ip_version,
                                  'gateway_mac': 'aa:bb:cc:11:22:33'}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, 'vxlan',
                    None, None, self._fixed_ips,
                    n_const.DEVICE_OWNER_DVR_INTERFACE,
                    False)
                self.agent.port_bound(self._compute_port,
                                      self._net_uuid, 'vxlan',
                                      None, None,
                                      self._compute_fixed_ips,
                                      device_owner, False)
                self.assertTrue(add_flow_tun_fn.called)
                self.assertTrue(add_flow_int_fn.called)
                self.assertTrue(delete_flows_int_fn.called)

        with contextlib.nested(
            mock.patch.object(self.agent, 'reclaim_local_vlan'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                              return_value=None),
            mock.patch.object(self.agent.dvr_agent.int_br,
                              'delete_flows')) as (reclaim_vlan_fn,
                                                   update_dev_down_fn,
                                                   delete_flows_int_fn):
                self.agent.treat_devices_removed([self._compute_port.vif_id])
                expected = [
                    mock.call(
                        table=constants.DVR_TO_SRC_MAC,
                        dl_dst=self._compute_port.vif_mac,
                        dl_vlan=(
                            self.agent.local_vlan_map[self._net_uuid].vlan))]
                self.assertEqual(expected, delete_flows_int_fn.call_args_list)

    def test_treat_devices_removed_for_dvr_with_compute_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner="compute:None")
        self._test_treat_devices_removed_for_dvr(
            device_owner="compute:None", ip_version=6)

    def test_treat_devices_removed_for_dvr_with_lbaas_vip_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER)
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_LOADBALANCER, ip_version=6)

    def test_treat_devices_removed_for_dvr_with_dhcp_ports(self):
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_DHCP)
        self._test_treat_devices_removed_for_dvr(
            device_owner=n_const.DEVICE_OWNER_DHCP, ip_version=6)

    def test_treat_devices_removed_for_dvr_csnat_port(self, ofport=10):
        self._setup_for_dvr_test()
        with mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                        'set_db_attribute',
                        return_value=True):
            with contextlib.nested(
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'db_get_val',
                           return_value=self._old_local_vlan),
                mock.patch.object(
                    self.agent.dvr_agent.plugin_rpc, 'get_subnet_for_dvr',
                    return_value={'gateway_ip': '1.1.1.1',
                                  'cidr': '1.1.1.0/24',
                                  'ip_version': 4,
                                  'gateway_mac': 'aa:bb:cc:11:22:33'}),
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                    'get_ports_on_host_by_subnet',
                    return_value=[]),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'get_vif_port_by_id',
                                  return_value=self._port),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows')
            ) as (get_ovs_db_func, get_subnet_fn, get_cphost_fn,
                  get_vif_fn, add_flow_int_fn, delete_flows_int_fn,
                  add_flow_tun_fn, delete_flows_tun_fn):
                self.agent.port_bound(
                    self._port, self._net_uuid, 'vxlan',
                    None, None, self._fixed_ips,
                    n_const.DEVICE_OWNER_ROUTER_SNAT,
                    False)
                self.assertTrue(add_flow_int_fn.called)
                self.assertTrue(delete_flows_int_fn.called)

        with contextlib.nested(
            mock.patch.object(self.agent, 'reclaim_local_vlan'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                              return_value=None),
            mock.patch.object(self.agent.dvr_agent.int_br,
                              'delete_flows')) as (reclaim_vlan_fn,
                                                   update_dev_down_fn,
                                                   delete_flows_int_fn):
                self.agent.treat_devices_removed([self._port.vif_id])
                self.assertTrue(delete_flows_int_fn.called)

    def test_setup_dvr_flows_on_int_br(self):
        self._setup_for_dvr_test()
        with contextlib.nested(
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'remove_all_flows'),
                mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
                mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
                mock.patch.object(
                    self.agent.dvr_agent.plugin_rpc,
                    'get_dvr_mac_address_list',
                    return_value=[{'host': 'cn1',
                                   'mac_address': 'aa:bb:cc:dd:ee:ff'},
                                  {'host': 'cn2',
                                   'mac_address': '11:22:33:44:55:66'}])) as \
            (remove_flows_fn, add_int_flow_fn, add_tun_flow_fn,
             get_mac_list_fn):
            self.agent.dvr_agent.setup_dvr_flows_on_integ_br()
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())
            physical_networks = self.agent.dvr_agent.bridge_mappings.keys()
            ioport = self.agent.dvr_agent.int_ofports[physical_networks[0]]
            expected = [
                    mock.call(table=constants.CANARY_TABLE,
                              priority=0,
                              actions="drop"),
                    mock.call(table=constants.DVR_TO_SRC_MAC,
                             priority=1,
                             actions="drop"),
                    mock.call(table=constants.DVR_TO_SRC_MAC_VLAN,
                             priority=1,
                             actions="drop"),
                    mock.call(table=constants.LOCAL_SWITCHING,
                             priority=1,
                             actions="normal"),
                    mock.call(
                        table=constants.LOCAL_SWITCHING, priority=2,
                        actions="drop",
                        in_port=ioport)]
            self.assertTrue(remove_flows_fn.called)
            self.assertEqual(expected, add_int_flow_fn.call_args_list)
            self.assertEqual(add_int_flow_fn.call_count, 5)

    def test_get_dvr_mac_address(self):
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               return_value={'host': 'cn1',
                                  'mac_address': 'aa:22:33:44:55:66'}):
            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertEqual('aa:22:33:44:55:66',
                             self.agent.dvr_agent.dvr_mac_address)
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())

    def test_get_dvr_mac_address_exception(self):
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with contextlib.nested(
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               side_effect=oslo_messaging.RemoteError),
                mock.patch.object(self.agent.dvr_agent.int_br,
                                  'add_flow')) as (gd_mac, add_int_flow_fn):

            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertIsNone(self.agent.dvr_agent.dvr_mac_address)
            self.assertFalse(self.agent.dvr_agent.in_distributed_mode())
            self.assertEqual(add_int_flow_fn.call_count, 1)

    def test_get_dvr_mac_address_retried(self):
        valid_entry = {'host': 'cn1', 'mac_address': 'aa:22:33:44:55:66'}
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout the first 2 times it calls get_dvr_mac_address()
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                               'get_dvr_mac_address_by_host',
                               side_effect=(raise_timeout, raise_timeout,
                                            valid_entry)):
            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertEqual('aa:22:33:44:55:66',
                             self.agent.dvr_agent.dvr_mac_address)
            self.assertTrue(self.agent.dvr_agent.in_distributed_mode())
            self.assertEqual(self.agent.dvr_agent.plugin_rpc.
                             get_dvr_mac_address_by_host.call_count, 3)

    def test_get_dvr_mac_address_retried_max(self):
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout every time until we give up, currently 5 tries
        self._setup_for_dvr_test()
        self.agent.dvr_agent.dvr_mac_address = None
        with contextlib.nested(
                mock.patch.object(self.agent.dvr_agent.plugin_rpc,
                                 'get_dvr_mac_address_by_host',
                                 side_effect=raise_timeout),
                mock.patch.object(utils, "execute"),
        ) as (rpc_mock, execute_mock):
            self.agent.dvr_agent.get_dvr_mac_address()
            self.assertIsNone(self.agent.dvr_agent.dvr_mac_address)
            self.assertFalse(self.agent.dvr_agent.in_distributed_mode())
            self.assertEqual(self.agent.dvr_agent.plugin_rpc.
                             get_dvr_mac_address_by_host.call_count, 5)

    def test_dvr_mac_address_update(self):
        self._setup_for_dvr_test()
        newhost = 'cn2'
        newmac = 'aa:bb:cc:dd:ee:ff'
        int_ofport = self.agent.dvr_agent.int_ofports['physeth1']
        patch_int_ofport = self.agent.dvr_agent.patch_int_ofport
        patch_tun_ofport = self.agent.dvr_agent.patch_tun_ofport
        with contextlib.nested(
            mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
            mock.patch.object(self.agent.dvr_agent.tun_br, 'add_flow'),
            mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
            mock.patch.object(self.agent.dvr_agent.phys_brs['physeth1'],
                              'add_flow')
        ) as (add_flow_fn, add_flow_tn_fn, del_flows_fn, add_flow_phys_fn):
            self.agent.dvr_agent.\
                dvr_mac_address_update(
                    dvr_macs=[{'host': newhost,
                               'mac_address': newmac}])
            expected = [
                    mock.call(table=constants.LOCAL_SWITCHING,
                              priority=4,
                              in_port=int_ofport,
                              dl_src=newmac,
                              actions="resubmit(,%s)" %
                              constants.DVR_TO_SRC_MAC_VLAN),
                    mock.call(table=constants.LOCAL_SWITCHING,
                              priority=2,
                              in_port=patch_tun_ofport,
                              dl_src=newmac,
                              actions="resubmit(,%s)" %
                              constants.DVR_TO_SRC_MAC)]
            self.assertEqual(expected, add_flow_fn.call_args_list)
            add_flow_phys_fn.assert_called_with(
                    table=constants.DVR_NOT_LEARN_VLAN,
                    priority=2,
                    dl_src=newmac,
                    actions="output:%s" %
                    self.agent.dvr_agent.phys_ofports['physeth1'])
            add_flow_tn_fn.assert_called_with(table=constants.DVR_NOT_LEARN,
                                              priority=1,
                                              dl_src=newmac,
                                              actions="output:%s"
                                              % patch_int_ofport)
            self.assertFalse(del_flows_fn.called)
        with contextlib.nested(
            mock.patch.object(self.agent.dvr_agent.int_br, 'add_flow'),
            mock.patch.object(self.agent.dvr_agent.tun_br, 'delete_flows'),
            mock.patch.object(self.agent.dvr_agent.int_br, 'delete_flows'),
            mock.patch.object(self.agent.dvr_agent.phys_brs['physeth1'],
                              'delete_flows'),
        ) as (add_flow_fn, del_flows_tn_fn, del_flows_fn, del_flows_phys_fn):
            self.agent.dvr_agent.dvr_mac_address_update(dvr_macs=[])
            ioport = self.agent.dvr_agent.int_ofports['physeth1']
            expected = [
                 mock.call(table=constants.LOCAL_SWITCHING,
                           in_port=ioport,
                           dl_src=newmac),
                 mock.call(table=constants.LOCAL_SWITCHING,
                           in_port=patch_tun_ofport,
                           dl_src=newmac)]
            self.assertEqual(expected, del_flows_fn.call_args_list)
            del_flows_phys_fn.asert_called_with(
                    table=constants.DVR_NOT_LEARN_VLAN,
                    dl_src=newmac)
            del_flows_tn_fn.assert_called_with(table=constants.DVR_NOT_LEARN,
                                               dl_src=newmac)
            self.assertFalse(add_flow_fn.called)
