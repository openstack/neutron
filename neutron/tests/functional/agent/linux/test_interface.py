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

from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import exceptions
from neutron.common import utils
from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base


class OVSInterfaceDriverTestCase(base.BaseOVSLinuxTestCase):
    def setUp(self):
        super(OVSInterfaceDriverTestCase, self).setUp()
        conf = cfg.ConfigOpts()
        conf.register_opts(interface.OPTS)
        self.interface = interface.OVSInterfaceDriver(conf)

    def test_plug_checks_if_bridge_exists(self):
        with testtools.ExpectedException(exceptions.BridgeDoesNotExist):
            self.interface.plug(network_id=42,
                                port_id=71,
                                device_name='not_a_device',
                                mac_address='',
                                bridge='not_a_bridge',
                                namespace='not_a_namespace')

    def test_plug_succeeds(self):
        device_name = tests_base.get_rand_name()
        mac_address = utils.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

        self.assertFalse(bridge.get_port_name_list())
        self.interface.plug(network_id=uuidutils.generate_uuid(),
                            port_id=uuidutils.generate_uuid(),
                            device_name=device_name,
                            mac_address=mac_address,
                            bridge=bridge.br_name,
                            namespace=namespace)
        self.assertIn(device_name, bridge.get_port_name_list())
        self.assertTrue(ip_lib.device_exists(device_name, namespace))

    def test_plug_with_namespace_sets_mtu_higher_than_bridge(self):
        device_mtu = 1450

        # Create a new OVS bridge
        ovs_bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.assertFalse(ovs_bridge.get_port_name_list())

        # Add a new linuxbridge port with reduced MTU to OVS bridge
        lb_bridge = self.useFixture(
            net_helpers.LinuxBridgeFixture()).bridge
        lb_bridge_port = self.useFixture(
            net_helpers.LinuxBridgePortFixture(lb_bridge))
        lb_bridge_port.port.link.set_mtu(device_mtu - 1)
        ovs_bridge.add_port(lb_bridge_port.port.name)

        # Now plug a device with intended MTU that is higher than for the port
        # above and validate that its MTU is not reduced to the least MTU on
        # the bridge
        device_name = tests_base.get_rand_name()
        mac_address = utils.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        self.interface.plug(network_id=uuidutils.generate_uuid(),
                            port_id=uuidutils.generate_uuid(),
                            device_name=device_name,
                            mac_address=mac_address,
                            bridge=ovs_bridge.br_name,
                            namespace=namespace,
                            mtu=device_mtu)

        self.assertIn(device_name, ovs_bridge.get_port_name_list())
        self.assertTrue(ip_lib.device_exists(device_name, namespace))
        self.assertEqual(
            device_mtu,
            ip_lib.IPDevice(device_name, namespace=namespace).link.mtu
        )
