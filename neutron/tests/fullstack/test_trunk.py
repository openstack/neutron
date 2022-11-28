# Copyright 2016 Red Hat, Inc.
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

import functools

import netaddr
from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.common import utils
from neutron.services.trunk.drivers.openvswitch.agent import ovsdb_handler
from neutron.services.trunk.drivers.openvswitch import utils as trunk_ovs_utils
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


def make_ip_network(port, network):
    """Make an IPNetwork object from port and network.

    Function returns IPNetwork object containing fixed IP address from port
    dictionary with prefixlen from network object.

    :param port: Port dictionary returned by Neutron API
    :param network: IPNetwork object in which the port's IP will be assigned.
    """
    ip_address = netaddr.IPAddress(
        port['fixed_ips'][0]['ip_address'])
    return netaddr.IPNetwork(
        (ip_address.value, network.prefixlen))


class TrunkTestException(Exception):
    pass


class Network(object):
    """A helper class to keep persistent info about assigned addresses."""
    def __init__(self, prefix, network_cidr, tag=None):
        self.prefix = prefix
        self.network = netaddr.IPNetwork(network_cidr)
        self.neutron_network = None
        self.neutron_subnet = None
        self.tag = tag
        # Currently, only vlan is supported. Pass via __init__ once more are
        # supported.
        self.segmentation_type = 'vlan'

    @property
    def cidr(self):
        return str(self.network.cidr)

    @property
    def gateway(self):
        """Return lowest possible IP in the given subnet."""
        return str(netaddr.IPAddress(self.network.first + 1))

    @property
    def id(self):
        return self.neutron_network['id']

    @property
    def name(self):
        return "%s-network" % self.prefix

    @property
    def subnet_name(self):
        return "%s-subnet" % self.prefix


class TestTrunkPlugin(base.BaseFullStackTestCase):
    def setUp(self):
        host_desc = [environment.HostDescription(
            l3_agent=False,
            l2_agent_type=constants.AGENT_TYPE_OVS)]
        env_desc = environment.EnvironmentDescription(service_plugins='trunk')
        env = environment.Environment(env_desc, host_desc)
        super(TestTrunkPlugin, self).setUp(env)

        self.tenant_id = uuidutils.generate_uuid()
        self.trunk_network = Network('trunk', '10.0.0.0/24')
        self.vlan1_network = Network('vlan1', '192.168.0.0/24', tag=10)
        self.vlan2_network = Network('vlan2', '192.168.1.0/24', tag=20)

        self.host = self.environment.hosts[0]

        for network in (
                self.trunk_network, self.vlan1_network, self.vlan2_network):
            self.create_network_and_subnet(network)

    def create_network_and_subnet(self, network):
        """Create network and subnet resources in Neutron based on network
           object.

        The resource names will be <prefix>-network and <prefix>-subnet, where
        prefix is taken from network object.

        :param network: Network object from this module.
        """
        network.neutron_network = self.safe_client.create_network(
            self.tenant_id, network.name)
        network.neutron_subnet = self.safe_client.create_subnet(
            self.tenant_id,
            network.id,
            cidr=network.cidr,
            gateway_ip=network.gateway,
            name=network.subnet_name,
            enable_dhcp=False)

    def create_vlan_aware_vm(self, trunk_network, vlan_networks):
        """Create a fake machine with one untagged port and subports
        according vlan_networks parameter.

        :param trunk_network: Instance of Network where trunk port should be
                              created.
        :param vlan_networks: List of Network instances where subports should
                              be created.
        """
        trunk_parent_port = self.safe_client.create_port(
            self.tenant_id, trunk_network.id)

        vlan_subports = [
            self.safe_client.create_port(self.tenant_id, vlan_network.id,
                mac_address=trunk_parent_port['mac_address'])
            for vlan_network in vlan_networks]

        trunk = self.safe_client.create_trunk(
            self.tenant_id,
            name='mytrunk',
            port_id=trunk_parent_port['id'],
            sub_ports=[
                {'port_id': vlan_subport['id'],
                 'segmentation_type': 'vlan',
                 'segmentation_id': vlan_network.tag}
                for vlan_subport, vlan_network in zip(vlan_subports,
                                                      vlan_networks)
            ],
        )

        vm = self.useFixture(
            machine.FakeFullstackTrunkMachine(
                trunk,
                self.host,
                trunk_network.id,
                self.tenant_id,
                self.safe_client,
                neutron_port=trunk_parent_port,
                bridge_name=trunk_ovs_utils.gen_trunk_br_name(trunk['id'])))

        for port, vlan_network in zip(vlan_subports, vlan_networks):
            ip_network = make_ip_network(port, vlan_network.network)
            vm.add_vlan_interface(
                port['mac_address'], ip_network, vlan_network.tag)
        vm.block_until_boot()

        return vm

    def create_vm_in_network(self, network):
        """Create a fake machine in given network."""
        return self.useFixture(
            machine.FakeFullstackMachine(
                self.host,
                network.id,
                self.tenant_id,
                self.safe_client
            )
        )

    def add_subport_to_vm(self, vm, subport_network):
        """Add subport from subport_network to given vm.

        :param vm: FakeFullstackMachine instance to with subport should be
                   added.
        :param subport_network: Network object representing network containing
                                port for subport.
        """
        subport = self.safe_client.create_port(
            self.tenant_id, subport_network.id,
            mac_address=vm.neutron_port['mac_address'])
        subport_spec = {
            'port_id': subport['id'],
            'segmentation_type': subport_network.segmentation_type,
            'segmentation_id': subport_network.tag
        }

        self.safe_client.trunk_add_subports(
            self.tenant_id, vm.trunk['id'], [subport_spec])
        ip_network = make_ip_network(subport, subport_network.network)
        vm.add_vlan_interface(
            subport['mac_address'], ip_network, subport_network.tag)

    # NOTE(slaweq): As is described in bug
    # https://bugs.launchpad.net/neutron/+bug/1687709 when more than one
    # different ovs-agent with enabled trunk driver is running at a time it
    # might lead to race conditions between them.
    # Because of that ovs_agent used for fullstack tests is monkeypatched and
    # loads trunk driver only if trunk service plugin is enabled.
    # That makes restriction that only a single set of tests with trunk-enabled
    # services will run at the same time.
    def test_trunk_lifecycle(self):
        """Test life-cycle of a fake VM with trunk port.

        This test uses 4 fake machines:
          - vlan_aware_vm (A) that is at the beginning connected to a trunk
            network and a vlan1 network.
          - trunk_network_vm (B) that is connected to the trunk network.
          - vlan1_network_vm (C) that is connected to the vlan1 network.
          - vlan2_network_vm (D) that is connected to a vlan2 network.

        Scenario steps:
          - all the vms from above are created
          - A can talk with B (over the trunk network)
          - A can talk with C (over the vlan1 network)
          - A can not talk with D (no leg on the vlan2 network)

          - subport from the vlan2 network is added to A
          - A can now talk with D (over the vlan2 network)

          - subport from the vlan1 network is removed from A
          - A can talk with B (over the trunk network)
          - A can not talk with C (no leg on the vlan1 network)
          - A can talk with D (over the vlan2 network)

          - A is deleted which leads to removal of trunk bridge
          - no leftovers like patch ports to the trunk bridge should remain on
            an integration bridge
        """

        vlan_aware_vm = self.create_vlan_aware_vm(
            self.trunk_network,
            [self.vlan1_network]
        )
        trunk_id = vlan_aware_vm.trunk['id']

        # Create helper vms with different networks
        trunk_network_vm = self.create_vm_in_network(self.trunk_network)
        vlan1_network_vm = self.create_vm_in_network(self.vlan1_network)
        vlan2_network_vm = self.create_vm_in_network(self.vlan2_network)

        for vm in trunk_network_vm, vlan1_network_vm, vlan2_network_vm:
            vm.block_until_boot()

        # Test connectivity to trunk and subport
        vlan_aware_vm.block_until_ping(trunk_network_vm.ip)
        vlan_aware_vm.block_until_ping(vlan1_network_vm.ip)

        # Subport for vlan2 hasn't been added yet
        vlan_aware_vm.block_until_no_ping(vlan2_network_vm.ip)

        # Add another subport and test
        self.add_subport_to_vm(vlan_aware_vm, self.vlan2_network)
        vlan_aware_vm.block_until_ping(vlan2_network_vm.ip)

        # Remove the first subport
        self.safe_client.trunk_remove_subports(
            self.tenant_id,
            trunk_id,
            [vlan_aware_vm.trunk['sub_ports'][0]])

        # vlan1_network_vm now shouldn't be able to talk to vlan_aware_vm
        vlan_aware_vm.block_until_no_ping(vlan1_network_vm.ip)

        # but trunk and vlan2 should be able to ping
        vlan_aware_vm.block_until_ping(trunk_network_vm.ip)
        vlan_aware_vm.block_until_ping(vlan2_network_vm.ip)

        # Delete vm and check that patch ports are gone
        vlan_aware_vm.destroy()

        integration_bridge = self.host.get_bridge(None)
        no_patch_ports_predicate = functools.partial(
            lambda bridge: not ovsdb_handler.bridge_has_service_port(bridge),
            integration_bridge,
        )
        try:
            utils.wait_until_true(no_patch_ports_predicate)
        except utils.WaitTimeout:
            # Create exception object after timeout to provide up-to-date list
            # of interfaces
            raise TrunkTestException(
                "Integration bridge %s still has following ports while some of"
                " them are patch ports for trunk that were supposed to be "
                "removed: %s" % (
                    integration_bridge.br_name,
                    integration_bridge.get_iface_name_list()
                )
            )
