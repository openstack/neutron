# Copyright (c) 2015 Red Hat, Inc.
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

import copy
import os.path
from unittest import mock

import eventlet
import fixtures
import netaddr
from neutron_lib.api import converters
from neutron_lib import constants as lib_const
from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.agent.dhcp import agent
from neutron.agent import dhcp_agent
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import utils as common_utils
from neutron.conf.agent import common as config
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional import base


class DHCPAgentOVSTestFramework(base.BaseSudoTestCase):

    _DHCP_PORT_MAC_ADDRESS = converters.convert_to_sanitized_mac_address(
        '24:77:03:7d:00:4c')
    _TENANT_PORT_MAC_ADDRESS = converters.convert_to_sanitized_mac_address(
        '24:77:03:7d:00:3a')

    _IP_ADDRS = {
        4: {'addr': '192.168.10.11',
            'cidr': '192.168.10.0/24',
            'gateway': '192.168.10.1'},
        6: {'addr': '2001:db8:0:1::c0a8:a0b',
            'cidr': '2001:db8:0:1::c0a8:a00/120',
            'gateway': '2001:db8:0:1::c0a8:a01'}, }

    def setUp(self):
        super(DHCPAgentOVSTestFramework, self).setUp()
        config.setup_logging()
        self.conf_fixture = self.useFixture(fixture_config.Config())
        self.conf = self.conf_fixture.conf
        dhcp_agent.register_options(self.conf)

        # NOTE(cbrandily): TempDir fixture creates a folder with 0o700
        # permissions but agent dir must be readable by dnsmasq user (nobody)
        agent_config_dir = self.useFixture(fixtures.TempDir()).path
        self.useFixture(
            helpers.RecursivePermDirFixture(agent_config_dir, 0o555))

        self.conf.set_override("dhcp_confs", agent_config_dir)
        self.conf.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        self.conf.set_override('report_interval', 0, 'AGENT')
        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.conf.set_override('integration_bridge', br_int.br_name, 'OVS')

        self.mock_plugin_api = mock.patch(
            'neutron.agent.dhcp.agent.DhcpPluginApi').start().return_value
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        self.agent = agent.DhcpAgentWithStateReport('localhost')

        self.ovs_driver = interface.OVSInterfaceDriver(self.conf)

        self.conf.set_override('check_child_processes_interval', 1, 'AGENT')

        mock.patch('neutron.agent.common.ovs_lib.'
                   'OVSBridge._set_port_dead').start()

    def network_dict_for_dhcp(self, dhcp_enabled=True,
                              ip_version=lib_const.IP_VERSION_4,
                              prefix_override=None):
        net_id = uuidutils.generate_uuid()
        subnet_dict = self.create_subnet_dict(
            net_id, dhcp_enabled, ip_version, prefix_override)
        port_dict = self.create_port_dict(
            net_id, subnet_dict.id,
            mac_address=str(self._DHCP_PORT_MAC_ADDRESS),
            ip_version=ip_version)
        port_dict.device_id = common_utils.get_dhcp_agent_device_id(
            net_id, self.conf.host)
        net_dict = self.create_network_dict(
            net_id, [subnet_dict], [port_dict])
        return net_dict

    def create_subnet_dict(self, net_id, dhcp_enabled=True,
                           ip_version=lib_const.IP_VERSION_4,
                           prefix_override=None):
        cidr = self._IP_ADDRS[ip_version]['cidr']
        spool_id = uuidutils.generate_uuid()
        if prefix_override is not None:
            cidr = '/'.join((cidr.split('/')[0], str(prefix_override)))
        sn_dict = dhcp.DictModel(
            id=uuidutils.generate_uuid(),
            network_id=net_id,
            ip_version=ip_version,
            cidr=cidr,
            subnetpool_id=spool_id,
            gateway_ip=self._IP_ADDRS[ip_version]['gateway'],
            enable_dhcp=dhcp_enabled,
            dns_nameservers=[],
            host_routes=[],
            ipv6_ra_mode=None,
            ipv6_address_mode=None)
        if ip_version == lib_const.IP_VERSION_6:
            sn_dict['ipv6_address_mode'] = lib_const.DHCPV6_STATEFUL
        return sn_dict

    def create_port_dict(self, network_id, subnet_id, mac_address,
                         ip_version=lib_const.IP_VERSION_4, ip_address=None):
        ip_address = (self._IP_ADDRS[ip_version]['addr']
            if not ip_address else ip_address)
        port_dict = dhcp.DictModel(id=uuidutils.generate_uuid(),
                                   name="foo",
                                   mac_address=mac_address,
                                   network_id=network_id,
                                   admin_state_up=True,
                                   device_id=uuidutils.generate_uuid(),
                                   device_owner="foo",
                                   fixed_ips=[{"subnet_id": subnet_id,
                                               "ip_address": ip_address}])
        return port_dict

    def create_network_dict(self, net_id, subnets=None, ports=None,
                            non_local_subnets=None):
        subnets = [] if not subnets else subnets
        ports = [] if not ports else ports
        non_local_subnets = [] if not non_local_subnets else non_local_subnets
        net_dict = dhcp.NetModel(id=net_id,
                                 subnets=subnets,
                                 non_local_subnets=non_local_subnets,
                                 ports=ports,
                                 admin_state_up=True,
                                 project_id=uuidutils.generate_uuid())
        return net_dict

    def get_interface_name(self, network, port):
        device_manager = dhcp.DeviceManager(conf=self.conf, plugin=mock.Mock())
        return device_manager.get_interface_name(network, port)

    def configure_dhcp_for_network(self, network, dhcp_enabled=True):
        self.agent.configure_dhcp_for_network(network)
        self.addCleanup(self._cleanup_network, network, dhcp_enabled)

    def _cleanup_network(self, network, dhcp_enabled):
        self.mock_plugin_api.release_dhcp_port.return_value = None
        if dhcp_enabled:
            self.agent.call_driver('disable', network)

    def assert_dhcp_resources(self, network, dhcp_enabled):
        ovs = ovs_lib.BaseOVS()
        port = network.ports[0]
        iface_name = self.get_interface_name(network, port)
        self.assertEqual(dhcp_enabled, ovs.port_exists(iface_name))
        self.assert_dhcp_namespace(network.namespace, dhcp_enabled)
        self.assert_accept_ra_disabled(network.namespace)
        self.assert_dhcp_device(network.namespace, iface_name, dhcp_enabled)

    def assert_dhcp_namespace(self, namespace, dhcp_enabled):
        self.assertEqual(dhcp_enabled,
                         ip_lib.network_namespace_exists(namespace))

    def assert_accept_ra_disabled(self, namespace):
        actual = ip_lib.IPWrapper(namespace=namespace).netns.execute(
            ['sysctl', '-b', 'net.ipv6.conf.default.accept_ra'],
            privsep_exec=True)
        self.assertEqual('0', actual)

    def assert_dhcp_device(self, namespace, dhcp_iface_name, dhcp_enabled):
        dev = ip_lib.IPDevice(dhcp_iface_name, namespace)
        self.assertEqual(dhcp_enabled, ip_lib.device_exists(
            dhcp_iface_name, namespace))
        if dhcp_enabled:
            self.assertEqual(self._DHCP_PORT_MAC_ADDRESS, dev.link.address)

    def _plug_port_for_dhcp_request(self, network, port):
        namespace = network.namespace
        vif_name = self.get_interface_name(network.id, port)

        self.ovs_driver.plug(network.id, port.id, vif_name, port.mac_address,
                             self.conf.OVS.integration_bridge,
                             namespace=namespace)

    def _ip_list_for_vif(self, vif_name, namespace):
        ip_device = ip_lib.IPDevice(vif_name, namespace)
        return ip_device.addr.list(ip_version=lib_const.IP_VERSION_4)

    def _get_network_port_for_allocation_test(self):
        network = self.network_dict_for_dhcp()
        ip_addr = netaddr.IPNetwork(network.subnets[0].cidr)[1]
        port = self.create_port_dict(
            network.id, network.subnets[0].id,
            mac_address=str(self._TENANT_PORT_MAC_ADDRESS),
            ip_address=str(ip_addr))
        return network, port

    def assert_good_allocation_for_port(self, network, port):
        vif_name = self.get_interface_name(network.id, port)
        self._run_dhclient(vif_name, network)

        predicate = lambda: len(
            self._ip_list_for_vif(vif_name, network.namespace))
        common_utils.wait_until_true(predicate, 10)

        ip_list = self._ip_list_for_vif(vif_name, network.namespace)
        cidr = ip_list[0].get('cidr')
        ip_addr = str(netaddr.IPNetwork(cidr).ip)
        self.assertEqual(port.fixed_ips[0].ip_address, ip_addr)

    def assert_bad_allocation_for_port(self, network, port):
        vif_name = self.get_interface_name(network.id, port)
        self._run_dhclient(vif_name, network)
        # we need wait some time (10 seconds is enough) and check
        # that dhclient not configured ip-address for interface
        eventlet.sleep(10)

        ip_list = self._ip_list_for_vif(vif_name, network.namespace)
        self.assertEqual([], ip_list)

    def _run_dhclient(self, vif_name, network):
        # NOTE: Before run dhclient we should create resolv.conf file
        # in namespace,  where we will run dhclient for testing address
        # allocation for port, otherwise, dhclient will override
        # system /etc/resolv.conf
        # By default, folder for dhcp-agent's namespace doesn't exist
        # that's why we use AdminDirFixture for create directory
        # with admin permissions in /etc/netns/ and touch resolv.conf in it.
        etc_dir = '/etc/netns/%s' % network.namespace
        self.useFixture(helpers.AdminDirFixture(etc_dir))
        cmd = ['touch', os.path.join(etc_dir, 'resolv.conf')]
        utils.execute(cmd, run_as_root=True)
        dhclient_cmd = ['dhclient', '--no-pid', '-d', '-1', vif_name]
        proc = net_helpers.RootHelperProcess(
            cmd=dhclient_cmd, namespace=network.namespace)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)

    def _get_metadata_proxy_process(self, network):
        return external_process.ProcessManager(
            self.conf,
            network.id,
            network.namespace,
            service=metadata_driver.HAPROXY_SERVICE)


class DHCPAgentOVSTestCase(DHCPAgentOVSTestFramework):

    def test_create_subnet_with_dhcp(self):
        dhcp_enabled = True
        for version in [4, 6]:
            network = self.network_dict_for_dhcp(
                dhcp_enabled, ip_version=version)
            self.configure_dhcp_for_network(network=network,
                                            dhcp_enabled=dhcp_enabled)
            self.assert_dhcp_resources(network, dhcp_enabled)

    def test_create_subnet_with_non64_ipv6_cidrs(self):
        # the agent should not throw exceptions on weird prefixes
        dhcp_enabled = True
        version = 6
        for i in (0, 1, 41, 81, 121, 127, 128):
            network = self.network_dict_for_dhcp(
                dhcp_enabled, ip_version=version, prefix_override=i)
            self.configure_dhcp_for_network(network=network,
                                            dhcp_enabled=dhcp_enabled)
            self.assertFalse(self.agent.needs_resync_reasons[network.id],
                             msg="prefix size of %s triggered resync" % i)

    def test_agent_mtu_set_on_interface_driver(self):
        network = self.network_dict_for_dhcp()
        network["mtu"] = 789
        self.configure_dhcp_for_network(network=network)
        port = network.ports[0]
        iface_name = self.get_interface_name(network, port)
        dev = ip_lib.IPDevice(iface_name, network.namespace)
        self.assertEqual(789, dev.link.mtu)

    def test_good_address_allocation(self):
        network, port = self._get_network_port_for_allocation_test()
        network.ports.append(port)
        self.configure_dhcp_for_network(network=network)
        self._plug_port_for_dhcp_request(network, port)
        self.assert_good_allocation_for_port(network, port)

    def test_bad_address_allocation(self):
        network, port = self._get_network_port_for_allocation_test()
        network.ports.append(port)
        self.configure_dhcp_for_network(network=network)
        port.mac_address = converters.convert_to_sanitized_mac_address(
            '24:77:03:7d:00:4d')
        self._plug_port_for_dhcp_request(network, port)
        self.assert_bad_allocation_for_port(network, port)

    def _spawn_network_metadata_proxy(self):
        network = self.network_dict_for_dhcp()
        self.conf.set_override('enable_isolated_metadata', True)
        self.addCleanup(self.agent.disable_isolated_metadata_proxy, network)
        self.configure_dhcp_for_network(network=network)
        pm = self._get_metadata_proxy_process(network)
        common_utils.wait_until_true(
            lambda: pm.active,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError("Metadata proxy didn't spawn"))
        return (pm, network)

    def test_metadata_proxy_respawned(self):
        pm, network = self._spawn_network_metadata_proxy()
        old_pid = pm.pid

        utils.execute(['kill', '-9', old_pid], run_as_root=True)
        common_utils.wait_until_true(
            lambda: pm.active and pm.pid != old_pid,
            timeout=5,
            sleep=0.1,
            exception=RuntimeError("Metadata proxy didn't respawn"))

    def test_stale_metadata_proxy_killed(self):
        pm, network = self._spawn_network_metadata_proxy()

        self.conf.set_override('enable_isolated_metadata', False)
        self.configure_dhcp_for_network(network=network)
        common_utils.wait_until_true(
            lambda: not pm.active,
            timeout=5,
            sleep=0.1,
            exception=RuntimeError("Stale metadata proxy didn't get killed"))

    def _test_metadata_proxy_spawn_kill_with_subnet_create_delete(self):
        network = self.network_dict_for_dhcp(
            ip_version=lib_const.IP_VERSION_6,
            dhcp_enabled=False)
        self.configure_dhcp_for_network(network=network)
        pm = self._get_metadata_proxy_process(network)

        self.assertFalse(pm.active)

        new_network = copy.deepcopy(network)
        dhcp_enabled_ipv4_subnet = self.create_subnet_dict(network.id)
        new_network.subnets.append(dhcp_enabled_ipv4_subnet)

        self.mock_plugin_api.get_network_info.return_value = new_network
        dhcp_port_mock = self.create_port_dict(
            network.id, dhcp_enabled_ipv4_subnet.id,
            mac_address=str(self._DHCP_PORT_MAC_ADDRESS))
        self.mock_plugin_api.create_dhcp_port.return_value = dhcp_port_mock
        network.ports = []
        new_network.ports = []

        self.agent.refresh_dhcp_helper(network.id)
        # Metadata proxy should be spawned for the newly added subnet
        common_utils.wait_until_true(
            lambda: pm.active,
            timeout=5,
            sleep=0.1,
            exception=RuntimeError("Metadata proxy didn't spawn"))

        self.mock_plugin_api.get_network_info.return_value = network
        self.agent.refresh_dhcp_helper(network.id)
        # Metadata proxy should be killed because network doesn't need it.
        common_utils.wait_until_true(
            lambda: not pm.active,
            timeout=5,
            sleep=0.1,
            exception=RuntimeError("Metadata proxy didn't get killed"))

    def test_enable_isolated_metadata_for_subnet_create_delete(self):
        self.conf.set_override('force_metadata', False)
        self.conf.set_override('enable_isolated_metadata', True)
        self._test_metadata_proxy_spawn_kill_with_subnet_create_delete()

    def test_force_metadata_for_subnet_create_delete(self):
        self.conf.set_override('force_metadata', True)
        self.conf.set_override('enable_isolated_metadata', False)
        self._test_metadata_proxy_spawn_kill_with_subnet_create_delete()

    def test_notify_port_ready_after_enable_dhcp(self):
        network = self.network_dict_for_dhcp()
        dhcp_port = self.create_port_dict(
            network.id, network.subnets[0].id,
            '24:77:03:7d:00:4d', ip_address='192.168.10.11')
        dhcp_port.device_owner = lib_const.DEVICE_OWNER_DHCP
        network.ports.append(dhcp_port)
        self.agent.start_ready_ports_loop()
        self.configure_dhcp_for_network(network)
        ports_to_send = {p.id for p in network.ports}
        common_utils.wait_until_true(
            lambda: self.mock_plugin_api.dhcp_ready_on_ports.called,
            timeout=1,
            sleep=0.1,
            exception=RuntimeError("'dhcp_ready_on_ports' not be called"))
        self.mock_plugin_api.dhcp_ready_on_ports.assert_called_with(
            ports_to_send)

    def test_dhcp_processing_pool_size(self):
        mock.patch.object(self.agent, 'call_driver').start().return_value = (
            True)
        self.agent.update_isolated_metadata_proxy = mock.Mock()
        self.agent.disable_isolated_metadata_proxy = mock.Mock()

        network_info_1 = self.network_dict_for_dhcp()
        self.configure_dhcp_for_network(network=network_info_1)
        self.assertEqual(agent.DHCP_PROCESS_GREENLET_MIN,
                         self.agent._pool.size)

        network_info_2 = self.network_dict_for_dhcp()
        self.configure_dhcp_for_network(network=network_info_2)
        self.assertEqual(agent.DHCP_PROCESS_GREENLET_MIN,
                         self.agent._pool.size)

        network_info_list = [network_info_1, network_info_2]
        for _i in range(agent.DHCP_PROCESS_GREENLET_MAX + 1):
            ni = self.network_dict_for_dhcp()
            self.configure_dhcp_for_network(network=ni)
            network_info_list.append(ni)

        self.assertEqual(agent.DHCP_PROCESS_GREENLET_MAX,
                         self.agent._pool.size)

        for network in network_info_list:
            self.agent.disable_dhcp_helper(network.id)

        agent_network_info_len = len(self.agent.cache.get_network_ids())
        if agent_network_info_len < agent.DHCP_PROCESS_GREENLET_MIN:
            self.assertEqual(agent.DHCP_PROCESS_GREENLET_MIN,
                             self.agent._pool.size)
        elif (agent.DHCP_PROCESS_GREENLET_MIN <= agent_network_info_len <=
              agent.DHCP_PROCESS_GREENLET_MAX):
            self.assertEqual(agent_network_info_len,
                             self.agent._pool.size)
        else:
            self.assertEqual(agent.DHCP_PROCESS_GREENLET_MAX,
                             self.agent._pool.size)
