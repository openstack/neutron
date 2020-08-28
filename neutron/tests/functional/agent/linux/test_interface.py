# Copyright (c) 2015 Red Hat, Inc.
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

from neutron_lib import exceptions
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base as linux_base
from neutron.tests.functional import base


class InterfaceDriverTestCaseMixin(object):
    def _test_mtu_set_after_action(self, device_name, br_name, namespace,
                                   action=None):
        mac_address = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))

        plug = functools.partial(
            self.interface.plug,
            network_id=uuidutils.generate_uuid(),
            port_id=uuidutils.generate_uuid(),
            device_name=device_name,
            mac_address=mac_address,
            bridge=self.bridge_name,
            namespace=namespace)
        plug(mtu=1500)
        self.assertTrue(ip_lib.device_exists(device_name, namespace))

        action = action or plug
        for mtu in (1450, 1500, 9000, 9000, 1450):
            action(mtu=mtu)
            self.assertEqual(
                mtu,
                ip_lib.IPDevice(device_name, namespace=namespace).link.mtu)

    def test_plug_multiple_calls_update_mtu(self):
        device_name = utils.get_rand_name()
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name

        self._test_mtu_set_after_action(
            device_name, self.bridge_name, namespace)

    def test_set_mtu(self):
        device_name = utils.get_rand_name()
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name

        self._test_mtu_set_after_action(
            device_name, self.bridge_name, namespace,
            functools.partial(
                self.interface.set_mtu,
                device_name=device_name, namespace=namespace))

    def test_ipv6_lla_create_and_get(self):
        lla_address = "fe80::f816:3eff:fe66:73bf/64"
        global_address = "2001::1/64"
        device_name = utils.get_rand_name()
        namespace = self.useFixture(net_helpers.NamespaceFixture())
        namespace.ip_wrapper.add_dummy(device_name)
        self.interface.add_ipv6_addr(
            device_name, lla_address, namespace.name, 'link')
        self.interface.add_ipv6_addr(
            device_name, global_address, namespace.name, 'global')
        existing_addresses = [
            a['cidr'] for a in self.interface.get_ipv6_llas(
                device_name, namespace.name)]
        self.assertIn(lla_address, existing_addresses)
        self.assertNotIn(global_address, existing_addresses)


class OVSInterfaceDriverTestCase(linux_base.BaseOVSLinuxTestCase,
                                 InterfaceDriverTestCaseMixin):
    def setUp(self):
        super(OVSInterfaceDriverTestCase, self).setUp()
        conf = cfg.ConfigOpts()
        config.register_interface_opts(conf)
        self.interface = interface.OVSInterfaceDriver(conf)
        self.bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

    @property
    def bridge_name(self):
        return self.bridge.br_name

    def test_plug_checks_if_bridge_exists(self):
        with testtools.ExpectedException(exceptions.BridgeDoesNotExist):
            self.interface.plug(network_id=42,
                                port_id=71,
                                device_name='not_a_device',
                                mac_address='',
                                bridge='not_a_bridge',
                                namespace='not_a_namespace')

    def test_plug_succeeds(self):
        device_name = utils.get_rand_name()
        mac_address = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name

        self.assertFalse(self.bridge.get_port_name_list())
        self.interface.plug(network_id=uuidutils.generate_uuid(),
                            port_id=uuidutils.generate_uuid(),
                            device_name=device_name,
                            mac_address=mac_address,
                            bridge=self.bridge.br_name,
                            namespace=namespace)
        self.assertIn(device_name, self.bridge.get_port_name_list())
        self.assertTrue(ip_lib.device_exists(device_name, namespace))

    def test_plug_with_namespace_sets_mtu_higher_than_bridge(self):
        # First, add a new linuxbridge port with reduced MTU to OVS bridge
        lb_bridge = self.useFixture(
            net_helpers.LinuxBridgeFixture()).bridge
        lb_bridge_port = self.useFixture(
            net_helpers.LinuxBridgePortFixture(lb_bridge))
        lb_bridge_port.port.link.set_mtu(1400)
        self.bridge.add_port(lb_bridge_port.port.name)

        device_name = utils.get_rand_name()
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name

        # Now plug a device with intended MTU that is higher than for the port
        # above and validate that its MTU is not reduced to the least MTU on
        # the bridge
        self._test_mtu_set_after_action(
            device_name, self.bridge_name, namespace)


class BridgeInterfaceDriverTestCase(base.BaseSudoTestCase,
                                    InterfaceDriverTestCaseMixin):
    def setUp(self):
        super(BridgeInterfaceDriverTestCase, self).setUp()
        conf = cfg.ConfigOpts()
        config.register_interface_opts(conf)
        self.interface = interface.BridgeInterfaceDriver(conf)
        self.bridge = self.useFixture(net_helpers.LinuxBridgeFixture()).bridge

    @property
    def bridge_name(self):
        return self.bridge.name
