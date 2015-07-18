# Copyright (c) 2015 Thales Services SAS
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
#

import fixtures

from neutron.agent.linux import ip_lib
from neutron.tests.common import net_helpers


class FakeMachine(fixtures.Fixture):
    """Create a fake machine.

    :ivar bridge: bridge on which the fake machine is bound
    :ivar ip_cidr: fake machine ip_cidr
    :type ip_cidr: str
    :ivar ip: fake machine ip
    :type ip: str
    :ivar gateway_ip: fake machine gateway ip
    :type gateway_ip: str

    :ivar namespace: namespace emulating the machine
    :type namespace: str
    :ivar port: port binding the namespace to the bridge
    :type port: IPDevice
    """

    def __init__(self, bridge, ip_cidr, gateway_ip=None):
        super(FakeMachine, self).__init__()
        self.bridge = bridge
        self._ip_cidr = ip_cidr
        self.gateway_ip = gateway_ip

    def _setUp(self):
        ns_fixture = self.useFixture(
            net_helpers.NamespaceFixture())
        self.namespace = ns_fixture.name

        self.port = self.useFixture(
            net_helpers.PortFixture.get(self.bridge, self.namespace)).port
        self.port.addr.add(self._ip_cidr)

        if self.gateway_ip:
            net_helpers.set_namespace_gateway(self.port, self.gateway_ip)

    @property
    def ip(self):
        return self._ip_cidr.partition('/')[0]

    @property
    def ip_cidr(self):
        return self._ip_cidr

    @ip_cidr.setter
    def ip_cidr(self, ip_cidr):
        self.port.addr.add(ip_cidr)
        self.port.addr.delete(self._ip_cidr)
        self._ip_cidr = ip_cidr

    @property
    def mac_address(self):
        return self.port.link.address

    @mac_address.setter
    def mac_address(self, mac_address):
        self.port.link.set_down()
        self.port.link.set_address(mac_address)
        self.port.link.set_up()

    def execute(self, *args, **kwargs):
        ns_ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ns_ip_wrapper.netns.execute(*args, **kwargs)

    def assert_ping(self, dst_ip):
        net_helpers.assert_ping(self.namespace, dst_ip)

    def assert_no_ping(self, dst_ip):
        net_helpers.assert_no_ping(self.namespace, dst_ip)


class PeerMachines(fixtures.Fixture):
    """Create 'amount' peered machines on an ip_cidr.

    :ivar bridge: bridge on which peer machines are bound
    :ivar ip_cidr: ip_cidr on which peer machines have ips
    :type ip_cidr: str
    :ivar machines: fake machines
    :type machines: FakeMachine list
    """

    CIDR = '192.168.0.1/24'

    def __init__(self, bridge, ip_cidr=None, gateway_ip=None, amount=2):
        super(PeerMachines, self).__init__()
        self.bridge = bridge
        self.ip_cidr = ip_cidr or self.CIDR
        self.gateway_ip = gateway_ip
        self.amount = amount

    def _setUp(self):
        self.machines = []

        for index in range(self.amount):
            ip_cidr = net_helpers.increment_ip_cidr(self.ip_cidr, index)
            self.machines.append(
                self.useFixture(
                    FakeMachine(self.bridge, ip_cidr, self.gateway_ip)))
