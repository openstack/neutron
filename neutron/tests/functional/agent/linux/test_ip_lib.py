# Copyright (c) 2014 Red Hat, Inc.
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

import collections

import netaddr
from neutron_lib import constants
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
import testtools

from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base

LOG = logging.getLogger(__name__)
Device = collections.namedtuple('Device',
                                'name ip_cidrs mac_address namespace')

WRONG_IP = '0.0.0.0'
TEST_IP = '240.0.0.1'
TEST_IP_NEIGH = '240.0.0.2'
TEST_IP_SECONDARY = '240.0.0.3'


class IpLibTestFramework(functional_base.BaseSudoTestCase):
    def setUp(self):
        super(IpLibTestFramework, self).setUp()
        self._configure()

    def _configure(self):
        config.register_interface_driver_opts_helper(cfg.CONF)
        cfg.CONF.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        config.register_interface_opts()
        self.driver = importutils.import_object(cfg.CONF.interface_driver,
                                                cfg.CONF)

    def generate_device_details(self, name=None, ip_cidrs=None,
                                mac_address=None, namespace=None):
        return Device(name or utils.get_rand_name(),
                      ip_cidrs or ["%s/24" % TEST_IP],
                      mac_address or
                      net.get_random_mac('fa:16:3e:00:00:00'.split(':')),
                      namespace or utils.get_rand_name())

    def _safe_delete_device(self, device):
        try:
            device.link.delete()
        except RuntimeError:
            LOG.debug('Could not delete %s, was it already deleted?', device)

    def manage_device(self, attr):
        """Create a tuntap with the specified attributes.

        The device is cleaned up at the end of the test.

        :param attr: A Device namedtuple
        :return: A tuntap ip_lib.IPDevice
        """
        ip = ip_lib.IPWrapper(namespace=attr.namespace)
        if attr.namespace:
            ip.netns.add(attr.namespace)
            self.addCleanup(ip.netns.delete, attr.namespace)
        tap_device = ip.add_tuntap(attr.name)
        self.addCleanup(self._safe_delete_device, tap_device)
        tap_device.link.set_address(attr.mac_address)
        self.driver.init_l3(attr.name, attr.ip_cidrs,
                            namespace=attr.namespace)
        tap_device.link.set_up()
        return tap_device


class IpLibTestCase(IpLibTestFramework):
    def test_device_exists(self):
        attr = self.generate_device_details()

        self.assertFalse(
            ip_lib.device_exists(attr.name, namespace=attr.namespace))

        device = self.manage_device(attr)

        self.assertTrue(
            ip_lib.device_exists(device.name, namespace=attr.namespace))

        self.assertFalse(
            ip_lib.device_exists(attr.name, namespace='wrong_namespace'))

        device.link.delete()

        self.assertFalse(
            ip_lib.device_exists(attr.name, namespace=attr.namespace))

    def test_ipdevice_exists(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        self.assertTrue(device.exists())
        device.link.delete()
        self.assertFalse(device.exists())

    def test_vxlan_exists(self):
        attr = self.generate_device_details()
        ip = ip_lib.IPWrapper(namespace=attr.namespace)
        ip.netns.add(attr.namespace)
        self.addCleanup(ip.netns.delete, attr.namespace)
        self.assertFalse(ip_lib.vxlan_in_use(9999, namespace=attr.namespace))
        device = ip.add_vxlan(attr.name, 9999)
        self.addCleanup(self._safe_delete_device, device)
        self.assertTrue(ip_lib.vxlan_in_use(9999, namespace=attr.namespace))
        device.link.delete()
        self.assertFalse(ip_lib.vxlan_in_use(9999, namespace=attr.namespace))

    def test_ipwrapper_get_device_by_ip_None(self):
        ip_wrapper = ip_lib.IPWrapper(namespace=None)
        self.assertIsNone(ip_wrapper.get_device_by_ip(ip=None))

    def test_ipwrapper_get_device_by_ip(self):
        # We need to pass both IP and cidr values to get_device_by_ip()
        # to make sure it filters correctly.
        test_ip = "%s/24" % TEST_IP
        test_ip_secondary = "%s/24" % TEST_IP_SECONDARY
        attr = self.generate_device_details(
            ip_cidrs=[test_ip, test_ip_secondary]
        )
        self.manage_device(attr)
        ip_wrapper = ip_lib.IPWrapper(namespace=attr.namespace)
        self.assertEqual(attr.name, ip_wrapper.get_device_by_ip(TEST_IP).name)
        self.assertEqual(attr.name,
                         ip_wrapper.get_device_by_ip(TEST_IP_SECONDARY).name)
        self.assertIsNone(ip_wrapper.get_device_by_ip(TEST_IP_NEIGH))
        # this is in the same subnet, so will match if we pass as cidr
        test_ip_neigh = "%s/24" % TEST_IP_NEIGH
        self.assertEqual(attr.name,
                         ip_wrapper.get_device_by_ip(test_ip_neigh).name)
        self.assertIsNone(ip_wrapper.get_device_by_ip(WRONG_IP))

    def test_device_exists_with_ips_and_mac(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        self.assertTrue(
            ip_lib.device_exists_with_ips_and_mac(*attr))

        wrong_ip_cidr = '10.0.0.1/8'
        wrong_mac_address = 'aa:aa:aa:aa:aa:aa'

        attr = self.generate_device_details(name='wrong_name')
        self.assertFalse(
            ip_lib.device_exists_with_ips_and_mac(*attr))

        attr = self.generate_device_details(ip_cidrs=[wrong_ip_cidr])
        self.assertFalse(ip_lib.device_exists_with_ips_and_mac(*attr))

        attr = self.generate_device_details(mac_address=wrong_mac_address)
        self.assertFalse(ip_lib.device_exists_with_ips_and_mac(*attr))

        attr = self.generate_device_details(namespace='wrong_namespace')
        self.assertFalse(ip_lib.device_exists_with_ips_and_mac(*attr))

        device.link.delete()

    def test_get_device_mac(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)

        mac_address = ip_lib.get_device_mac(attr.name,
                                            namespace=attr.namespace)

        self.assertEqual(attr.mac_address, mac_address)

        device.link.delete()

    def test_get_device_mac_too_long_name(self):
        name = utils.get_rand_name(
            max_length=constants.DEVICE_NAME_MAX_LEN + 5)
        attr = self.generate_device_details(name=name)
        device = self.manage_device(attr)

        mac_address = ip_lib.get_device_mac(attr.name,
                                            namespace=attr.namespace)

        self.assertEqual(attr.mac_address, mac_address)

        device.link.delete()

    def test_get_routing_table(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        device = self.manage_device(attr)
        device_ip = attr.ip_cidrs[0].split('/')[0]
        destination = '8.8.8.0/24'
        device.route.add_route(destination, device_ip)

        destination6 = 'fd01::/64'
        device.route.add_route(destination6, "fd00::2")

        expected_routes = [{'nexthop': device_ip,
                            'device': attr.name,
                            'destination': destination,
                            'scope': 'universe'},
                           {'nexthop': None,
                            'device': attr.name,
                            'destination': str(
                                netaddr.IPNetwork(attr.ip_cidrs[0]).cidr),
                            'scope': 'link'}]

        routes = ip_lib.get_routing_table(4, namespace=attr.namespace)
        self.assertItemsEqual(expected_routes, routes)
        self.assertIsInstance(routes, list)

        expected_routes6 = [{'nexthop': "fd00::2",
                             'device': attr.name,
                             'destination': destination6,
                             'scope': 'universe'},
                            {'nexthop': None,
                             'device': attr.name,
                             'destination': str(
                                 netaddr.IPNetwork(attr.ip_cidrs[1]).cidr),
                             'scope': 'universe'}]
        routes6 = ip_lib.get_routing_table(6, namespace=attr.namespace)
        self.assertItemsEqual(expected_routes6, routes6)
        self.assertIsInstance(routes6, list)

    def test_get_routing_table_no_namespace(self):
        with testtools.ExpectedException(ip_lib.NetworkNamespaceNotFound):
            ip_lib.get_routing_table(4, namespace="nonexistent-netns")

    def test_get_neigh_entries(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        mac_address = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        device = self.manage_device(attr)
        device.neigh.add(TEST_IP_NEIGH, mac_address)

        expected_neighs = [{'dst': TEST_IP_NEIGH,
                            'lladdr': mac_address,
                            'device': attr.name}]

        neighs = device.neigh.dump(4)
        self.assertItemsEqual(expected_neighs, neighs)
        self.assertIsInstance(neighs, list)

        device.neigh.delete(TEST_IP_NEIGH, mac_address)
        neighs = device.neigh.dump(4, dst=TEST_IP_NEIGH, lladdr=mac_address)
        self.assertEqual([], neighs)

    def test_get_neigh_entries_no_namespace(self):
        with testtools.ExpectedException(ip_lib.NetworkNamespaceNotFound):
            ip_lib.dump_neigh_entries(4, namespace="nonexistent-netns")

    def test_get_neigh_entries_no_interface(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        self.manage_device(attr)
        with testtools.ExpectedException(ip_lib.NetworkInterfaceNotFound):
            ip_lib.dump_neigh_entries(4, device="nosuchdevice",
                                      namespace=attr.namespace)

    def test_delete_neigh_entries(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        mac_address = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        device = self.manage_device(attr)

        # trying to delete a non-existent entry shouldn't raise an error
        device.neigh.delete(TEST_IP_NEIGH, mac_address)

    def _check_for_device_name(self, ip, name, should_exist):
        exist = any(d for d in ip.get_devices() if d.name == name)
        self.assertEqual(should_exist, exist)

    def test_dummy_exists(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture())
        dev_name = utils.get_rand_name()
        device = namespace.ip_wrapper.add_dummy(dev_name)
        self.addCleanup(self._safe_delete_device, device)
        self._check_for_device_name(namespace.ip_wrapper, dev_name, True)
        device.link.delete()
        self._check_for_device_name(namespace.ip_wrapper, dev_name, False)


class TestSetIpNonlocalBind(functional_base.BaseSudoTestCase):
    def test_assigned_value(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture())
        for expected in (0, 1):
            failed = ip_lib.set_ip_nonlocal_bind(expected, namespace.name)
            try:
                observed = ip_lib.get_ip_nonlocal_bind(namespace.name)
            except RuntimeError as rte:
                stat_message = (
                    'cannot stat /proc/sys/net/ipv4/ip_nonlocal_bind')
                if stat_message in str(rte):
                    raise self.skipException(
                        "This kernel doesn't support %s in network "
                        "namespaces." % ip_lib.IP_NONLOCAL_BIND)
                raise

            self.assertFalse(failed)
            self.assertEqual(expected, observed)
