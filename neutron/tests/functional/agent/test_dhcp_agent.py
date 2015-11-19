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

import os.path

import eventlet
import fixtures
import mock
import netaddr
from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron.agent.common import config
from neutron.agent.common import ovs_lib
from neutron.agent.dhcp import agent
from neutron.agent import dhcp_agent
from neutron.agent.linux import dhcp
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import utils as common_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional import base


class DHCPAgentOVSTestFramework(base.BaseSudoTestCase):

    _DHCP_PORT_MAC_ADDRESS = netaddr.EUI("24:77:03:7d:00:4c")
    _DHCP_PORT_MAC_ADDRESS.dialect = netaddr.mac_unix
    _TENANT_PORT_MAC_ADDRESS = netaddr.EUI("24:77:03:7d:00:3a")
    _TENANT_PORT_MAC_ADDRESS.dialect = netaddr.mac_unix

    _IP_ADDRS = {
        4: {'addr': '192.168.10.11',
            'cidr': '192.168.10.0/24',
            'gateway': '192.168.10.1'},
        6: {'addr': '0:0:0:0:0:ffff:c0a8:a0b',
            'cidr': '0:0:0:0:0:ffff:c0a8:a00/120',
            'gateway': '0:0:0:0:0:ffff:c0a8:a01'}, }

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
        self.conf.set_override('ovs_integration_bridge', br_int.br_name)

        self.mock_plugin_api = mock.patch(
            'neutron.agent.dhcp.agent.DhcpPluginApi').start().return_value
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        self.agent = agent.DhcpAgentWithStateReport('localhost')

        self.ovs_driver = interface.OVSInterfaceDriver(self.conf)

    def network_dict_for_dhcp(self, dhcp_enabled=True, ip_version=4):
        net_id = uuidutils.generate_uuid()
        subnet_dict = self.create_subnet_dict(
            net_id, dhcp_enabled, ip_version)
        port_dict = self.create_port_dict(
            net_id, subnet_dict.id,
            mac_address=str(self._DHCP_PORT_MAC_ADDRESS),
            ip_version=ip_version)
        port_dict.device_id = common_utils.get_dhcp_agent_device_id(
            net_id, self.conf.host)
        net_dict = self.create_network_dict(
            net_id, [subnet_dict], [port_dict])
        return net_dict

    def create_subnet_dict(self, net_id, dhcp_enabled=True, ip_version=4):
        sn_dict = dhcp.DictModel({
            "id": uuidutils.generate_uuid(),
            "network_id": net_id,
            "ip_version": ip_version,
            "cidr": self._IP_ADDRS[ip_version]['cidr'],
            "gateway_ip": (self.
                _IP_ADDRS[ip_version]['gateway']),
            "enable_dhcp": dhcp_enabled,
            "dns_nameservers": [],
            "host_routes": [],
            "ipv6_ra_mode": None,
            "ipv6_address_mode": None})
        if ip_version == 6:
            sn_dict['ipv6_address_mode'] = constants.DHCPV6_STATEFUL
        return sn_dict

    def create_port_dict(self, network_id, subnet_id, mac_address,
                         ip_version=4, ip_address=None):
        ip_address = (self._IP_ADDRS[ip_version]['addr']
            if not ip_address else ip_address)
        port_dict = dhcp.DictModel({
            "id": uuidutils.generate_uuid(),
            "name": "foo",
            "mac_address": mac_address,
            "network_id": network_id,
            "admin_state_up": True,
            "device_id": uuidutils.generate_uuid(),
            "device_owner": "foo",
            "fixed_ips": [{"subnet_id": subnet_id,
                           "ip_address": ip_address}], })
        return port_dict

    def create_network_dict(self, net_id, subnets=None, ports=None):
        subnets = [] if not subnets else subnets
        ports = [] if not ports else ports
        net_dict = dhcp.NetModel(d={
            "id": net_id,
            "subnets": subnets,
            "ports": ports,
            "admin_state_up": True,
            "tenant_id": uuidutils.generate_uuid(), })
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
        self.assert_dhcp_device(network.namespace, iface_name, dhcp_enabled)

    def assert_dhcp_namespace(self, namespace, dhcp_enabled):
        ip = ip_lib.IPWrapper()
        self.assertEqual(dhcp_enabled, ip.netns.exists(namespace))

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
                             self.conf['ovs_integration_bridge'],
                             namespace=namespace)

    def _ip_list_for_vif(self, vif_name, namespace):
        ip_device = ip_lib.IPDevice(vif_name, namespace)
        return ip_device.addr.list(ip_version=4)

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
        utils.wait_until_true(predicate, 10)

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


class DHCPAgentOVSTestCase(DHCPAgentOVSTestFramework):

    def test_create_subnet_with_dhcp(self):
        dhcp_enabled = True
        for version in [4, 6]:
            network = self.network_dict_for_dhcp(
                dhcp_enabled, ip_version=version)
            self.configure_dhcp_for_network(network=network,
                                            dhcp_enabled=dhcp_enabled)
            self.assert_dhcp_resources(network, dhcp_enabled)

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
        bad_mac_address = netaddr.EUI(self._TENANT_PORT_MAC_ADDRESS.value + 1)
        bad_mac_address.dialect = netaddr.mac_unix
        port.mac_address = str(bad_mac_address)
        self._plug_port_for_dhcp_request(network, port)
        self.assert_bad_allocation_for_port(network, port)
