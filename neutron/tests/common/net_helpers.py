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
import netaddr

from neutron.agent.linux import ip_lib
from neutron.common import constants as n_const
from neutron.openstack.common import uuidutils
from neutron.tests.common import base
from neutron.tests import sub_base
from neutron.tests import tools

NS_PREFIX = 'func-'
BR_PREFIX = 'test-br'
PORT_PREFIX = 'test-port'
VETH0_PREFIX = 'test-veth0'
VETH1_PREFIX = 'test-veth1'


def get_rand_port_name():
    return sub_base.get_rand_name(max_length=n_const.DEVICE_NAME_MAX_LEN,
                                  prefix=PORT_PREFIX)


def increment_ip_cidr(ip_cidr, offset=1):
    """Increment ip_cidr offset times.

    example: increment_ip_cidr("1.2.3.4/24", 2) ==> "1.2.3.6/24"
    """
    net0 = netaddr.IPNetwork(ip_cidr)
    net = netaddr.IPNetwork(ip_cidr)
    net.value += offset
    if not net0.network < net.ip < net0.broadcast:
        tools.fail(
            'Incorrect ip_cidr,offset tuple (%s,%s): "incremented" ip_cidr is '
            'outside ip_cidr' % (ip_cidr, offset))
    return str(net)


def set_namespace_gateway(port_dev, gateway_ip):
    """Set gateway for the namespace associated to the port."""
    if not port_dev.namespace:
        tools.fail('tests should not change test machine gateway')
    port_dev.route.add_gateway(gateway_ip)


class NamespaceFixture(fixtures.Fixture):
    """Create a namespace.

    :ivar ip_wrapper: created namespace
    :type ip_wrapper: IPWrapper
    """

    def __init__(self, prefix=NS_PREFIX):
        super(NamespaceFixture, self).__init__()
        self.prefix = prefix

    def setUp(self):
        super(NamespaceFixture, self).setUp()
        ip = ip_lib.IPWrapper()
        self.name = self.prefix + uuidutils.generate_uuid()
        self.ip_wrapper = ip.ensure_namespace(self.name)
        self.addCleanup(self.destroy)

    def destroy(self):
        if self.ip_wrapper.netns.exists(self.name):
            self.ip_wrapper.netns.delete(self.name)


class VethFixture(fixtures.Fixture):
    """Create a veth.

    :ivar ports: created veth ports
    :type ports: IPDevice 2-uplet
    """

    def setUp(self):
        super(VethFixture, self).setUp()
        ip_wrapper = ip_lib.IPWrapper()

        def _create_veth(name0):
            name1 = name0.replace(VETH0_PREFIX, VETH1_PREFIX)
            return ip_wrapper.add_veth(name0, name1)

        self.ports = base.create_resource(VETH0_PREFIX, _create_veth)
        self.addCleanup(self.destroy)

    def destroy(self):
        for port in self.ports:
            ip_wrapper = ip_lib.IPWrapper(port.namespace)
            try:
                ip_wrapper.del_veth(port.name)
                break
            except RuntimeError:
                # NOTE(cbrandily): It seems a veth is automagically deleted
                # when a namespace owning a veth endpoint is deleted.
                pass
