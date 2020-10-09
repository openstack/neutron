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
import itertools
import signal

import netaddr
from neutron_lib import constants
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import uuidutils
from pyroute2.iproute import linux as iproute_linux
import testscenarios
import testtools

from neutron.agent.common import async_process
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux.bin import ip_monitor
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
        if ip_cidrs is None:
            ip_cidrs = ["%s/24" % TEST_IP]
        return Device(name or utils.get_rand_name(),
                      ip_cidrs,
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

    def _check_routes(self, expected_routes, actual_routes):
        actual_routes = [{key: route[key] for key in expected_routes[0].keys()}
                         for route in actual_routes]
        self.assertEqual(expected_routes, actual_routes)

    def test_rules_lifecycle(self):
        PRIORITY = 32768
        TABLE = 16
        attr = self.generate_device_details()
        device = self.manage_device(attr)

        test_cases = {
            constants.IP_VERSION_4: [
                {
                    'ip': '1.1.1.1',
                    'to': '8.8.8.0/24'
                },
                {
                    'ip': '1.1.1.1',
                    'iif': device.name,
                    'to': '7.7.7.0/24'
                }
            ],
            constants.IP_VERSION_6: [
                {
                    'ip': 'abcd::1',
                    'to': '1234::/64'
                },
                {
                    'ip': 'abcd::1',
                    'iif': device.name,
                    'to': '4567::/64'
                }
            ]
        }
        expected_rules = {
            constants.IP_VERSION_4: [
                {
                    'from': '1.1.1.1',
                    'to': '8.8.8.0/24',
                    'priority': str(PRIORITY),
                    'table': str(TABLE),
                    'type': 'unicast'
                }, {
                    'from': '0.0.0.0/0',
                    'to': '7.7.7.0/24',
                    'iif': device.name,
                    'priority': str(PRIORITY),
                    'table': str(TABLE),
                    'type': 'unicast'
                }
            ],
            constants.IP_VERSION_6: [
                {
                    'from': 'abcd::1',
                    'to': '1234::/64',
                    'priority': str(PRIORITY),
                    'table': str(TABLE),
                    'type': 'unicast'
                },
                {
                    'from': '::/0',
                    'to': '4567::/64',
                    'iif': device.name,
                    'priority': str(PRIORITY),
                    'table': str(TABLE),
                    'type': 'unicast',
                }
            ]
        }

        for ip_version, test_case in test_cases.items():
            for rule in test_case:
                ip_lib.add_ip_rule(namespace=device.namespace, table=TABLE,
                                   priority=PRIORITY, **rule)

            rules = ip_lib.list_ip_rules(device.namespace, ip_version)
            for expected_rule in expected_rules[ip_version]:
                self.assertIn(expected_rule, rules)

            for rule in test_case:
                ip_lib.delete_ip_rule(device.namespace, table=TABLE,
                                      priority=PRIORITY, **rule)

            rules = priv_ip_lib.list_ip_rules(device.namespace, ip_version)
            for expected_rule in expected_rules[ip_version]:
                self.assertNotIn(expected_rule, rules)

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

    def test_vlan_exists(self):
        attr = self.generate_device_details()
        ip = ip_lib.IPWrapper(namespace=attr.namespace)
        ip.netns.add(attr.namespace)
        self.addCleanup(ip.netns.delete, attr.namespace)
        priv_ip_lib.create_interface(attr.name, attr.namespace, 'dummy')
        self.assertFalse(ip_lib.vlan_in_use(1999, namespace=attr.namespace))
        device = ip.add_vlan('vlan1999', attr.name, 1999)
        self.assertTrue(ip_lib.vlan_in_use(1999, namespace=attr.namespace))
        device.link.delete()
        self.assertFalse(ip_lib.vlan_in_use(1999, namespace=attr.namespace))

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

    def test_gateway_lifecycle(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        metric = 1000
        device = self.manage_device(attr)
        gateways = {
            constants.IP_VERSION_4: attr.ip_cidrs[0].split('/')[0],
            constants.IP_VERSION_6: "fd00::ff"
        }
        expected_gateways = {
            constants.IP_VERSION_4: {
                'metric': metric,
                'via': gateways[constants.IP_VERSION_4]},
            constants.IP_VERSION_6: {
                'metric': metric,
                'via': gateways[constants.IP_VERSION_6]}}

        for ip_version, gateway_ip in gateways.items():
            device.route.add_gateway(gateway_ip, metric)
            self._check_routes(
                [expected_gateways[ip_version]],
                [device.route.get_gateway(ip_version=ip_version)])
            device.route.delete_gateway(gateway_ip)
            self.assertIsNone(
                device.route.get_gateway(ip_version=ip_version))

    def test_gateway_flush(self):
        attr = self.generate_device_details(
            ip_cidrs=["%s/24" % TEST_IP, "fd00::1/64"]
        )
        device = self.manage_device(attr)

        gateways = {
            constants.IP_VERSION_4: attr.ip_cidrs[0].split('/')[0],
            constants.IP_VERSION_6: "fd00::ff"
        }
        for ip_version, gateway_ip in gateways.items():
            # Ensure that there is no gateway configured
            self.assertIsNone(
                device.route.get_gateway(ip_version=ip_version))

            # Now lets add gateway
            device.route.add_gateway(gateway_ip, table="main")
            self.assertIsNotNone(
                device.route.get_gateway(ip_version=ip_version))

            # Flush gateway and check that there is no any gateway configured
            device.route.flush(ip_version, table="main")
            self.assertIsNone(
                device.route.get_gateway(ip_version=ip_version))

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

    def test_veth_exists(self):
        namespace1 = self.useFixture(net_helpers.NamespaceFixture())
        namespace2 = self.useFixture(net_helpers.NamespaceFixture())
        dev_name1 = utils.get_rand_name()
        dev_name2 = utils.get_rand_name()

        device1, device2 = namespace1.ip_wrapper.add_veth(
            dev_name1, dev_name2, namespace2.name)
        self.addCleanup(self._safe_delete_device, device1)
        self.addCleanup(self._safe_delete_device, device2)

        self._check_for_device_name(namespace1.ip_wrapper, dev_name1, True)
        self._check_for_device_name(namespace2.ip_wrapper, dev_name2, True)
        self._check_for_device_name(namespace1.ip_wrapper, dev_name2, False)
        self._check_for_device_name(namespace2.ip_wrapper, dev_name1, False)

        # As it is veth pair, remove of device1 should be enough to remove
        # both devices
        device1.link.delete()
        self._check_for_device_name(namespace1.ip_wrapper, dev_name1, False)
        self._check_for_device_name(namespace2.ip_wrapper, dev_name2, False)

    def test_macvtap_exists(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture())
        src_dev_name = utils.get_rand_name()
        src_dev = namespace.ip_wrapper.add_dummy(src_dev_name)
        self.addCleanup(self._safe_delete_device, src_dev)

        dev_name = utils.get_rand_name()
        device = namespace.ip_wrapper.add_macvtap(dev_name, src_dev_name)
        self.addCleanup(self._safe_delete_device, device)

        self._check_for_device_name(namespace.ip_wrapper, dev_name, True)
        device.link.delete()
        self._check_for_device_name(namespace.ip_wrapper, dev_name, False)

    def test_dummy_exists(self):
        namespace = self.useFixture(net_helpers.NamespaceFixture())
        dev_name = utils.get_rand_name()
        device = namespace.ip_wrapper.add_dummy(dev_name)
        self.addCleanup(self._safe_delete_device, device)
        self._check_for_device_name(namespace.ip_wrapper, dev_name, True)
        device.link.delete()
        self._check_for_device_name(namespace.ip_wrapper, dev_name, False)

    def test_set_link_mtu(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        device.link.set_mtu(1450)

        self.assertEqual(1450, device.link.mtu)

        # Check if proper exception will be raised when wrong MTU value is
        # provided
        self.assertRaises(ip_lib.InvalidArgument, device.link.set_mtu, 1)

    def test_set_link_allmulticast_on(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)

        self.assertFalse(device.link.allmulticast)
        device.link.set_allmulticast_on()
        self.assertTrue(device.link.allmulticast)

    def test_set_link_netns(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        original_namespace = device.namespace
        original_ip_wrapper = ip_lib.IPWrapper(namespace=original_namespace)
        new_namespace = self.useFixture(net_helpers.NamespaceFixture())

        device.link.set_netns(new_namespace.name)

        self.assertEqual(new_namespace.name, device.namespace)
        self._check_for_device_name(
            new_namespace.ip_wrapper, device.name, True)
        self._check_for_device_name(
            original_ip_wrapper, device.name, False)

    def test_set_link_name(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        ip_wrapper = ip_lib.IPWrapper(namespace=device.namespace)
        original_name = device.name
        new_name = utils.get_rand_name()

        # device has to be DOWN to rename it
        device.link.set_down()
        device.link.set_name(new_name)

        self.assertEqual(new_name, device.name)
        self._check_for_device_name(ip_wrapper, new_name, True)
        self._check_for_device_name(ip_wrapper, original_name, False)

    def test_set_link_alias(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        alias = utils.get_rand_name()

        device.link.set_alias(alias)

        self.assertEqual(alias, device.link.alias)

    def _add_and_check_ips(self, device, ip_addresses):
        for cidr, scope, expected_broadcast in ip_addresses:
            # For IPv4 address add_broadcast flag will be set to True only
            # if expected_broadcast is given.
            # For IPv6 add_broadcast flag can be set to True always but
            # broadcast address will not be set, so expected_broadcast for
            # IPv6 should be always given as None.
            add_broadcast = True
            if cidr.version == constants.IP_VERSION_4:
                add_broadcast = bool(expected_broadcast)
            device.addr.add(str(cidr), scope, add_broadcast)

        device_ips_info = [
            (netaddr.IPNetwork(ip_info['cidr']),
             ip_info['scope'],
             ip_info['broadcast']) for
            ip_info in device.addr.list()]
        self.assertItemsEqual(ip_addresses, device_ips_info)

    def _flush_ips(self, device, ip_version):
        device.addr.flush(ip_version)
        for ip_address in device.addr.list():
            cidr = netaddr.IPNetwork(ip_address['cidr'])
            self.assertNotEqual(ip_version, cidr.version)

    def test_add_ip_address(self):
        ip_addresses = [
            (netaddr.IPNetwork("10.10.10.10/30"), "global", '10.10.10.11'),
            (netaddr.IPNetwork("11.11.11.11/28"), "link", None),
            (netaddr.IPNetwork("2801::1/120"), "global", None),
            (netaddr.IPNetwork("fe80::/64"), "link", None)]
        attr = self.generate_device_details(ip_cidrs=[])
        device = self.manage_device(attr)
        self._add_and_check_ips(device, ip_addresses)

        # Now let's check if adding already existing IP address will raise
        # RuntimeError
        ip_address = ip_addresses[0]
        self.assertRaises(RuntimeError,
                          device.addr.add, str(ip_address[0]), ip_address[1])

    def test_delete_ip_address(self):
        attr = self.generate_device_details()
        cidr = attr.ip_cidrs[0]
        device = self.manage_device(attr)

        device_cidrs = [ip_info['cidr'] for ip_info in device.addr.list()]
        self.assertIn(cidr, device_cidrs)

        device.addr.delete(cidr)
        device_cidrs = [ip_info['cidr'] for ip_info in device.addr.list()]
        self.assertNotIn(cidr, device_cidrs)

        # Try to delete not existing IP address, it should be just fine and
        # finish without any error raised
        device.addr.delete(cidr)

    def test_flush_ip_addresses(self):
        ip_addresses = [
            (netaddr.IPNetwork("10.10.10.10/30"), "global", '10.10.10.11'),
            (netaddr.IPNetwork("11.11.11.11/28"), "link", None),
            (netaddr.IPNetwork("2801::1/120"), "global", None),
            (netaddr.IPNetwork("fe80::/64"), "link", None)]
        attr = self.generate_device_details(ip_cidrs=[])
        device = self.manage_device(attr)

        self._add_and_check_ips(device, ip_addresses)
        self._flush_ips(device, constants.IP_VERSION_4)
        self._flush_ips(device, constants.IP_VERSION_6)


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


class NamespaceTestCase(functional_base.BaseSudoTestCase):

    def setUp(self):
        super(NamespaceTestCase, self).setUp()
        self.namespace = 'test_ns_' + uuidutils.generate_uuid()
        ip_lib.create_network_namespace(self.namespace)
        self.addCleanup(self._delete_namespace)

    def _delete_namespace(self):
        ip_lib.delete_network_namespace(self.namespace)

    def test_network_namespace_exists_ns_exists(self):
        self.assertTrue(ip_lib.network_namespace_exists(self.namespace))

    def test_network_namespace_exists_ns_doesnt_exists(self):
        self.assertFalse(ip_lib.network_namespace_exists('another_ns'))

    def test_network_namespace_exists_ns_exists_try_is_ready(self):
        self.assertTrue(ip_lib.network_namespace_exists(self.namespace,
                                                        try_is_ready=True))

    def test_network_namespace_exists_ns_doesnt_exists_try_is_ready(self):
        self.assertFalse(ip_lib.network_namespace_exists('another_ns',
                                                         try_is_ready=True))


class IpMonitorTestCase(testscenarios.WithScenarios,
                        functional_base.BaseLoggingTestCase):

    scenarios = [
        ('namespace', {'namespace': 'ns_' + uuidutils.generate_uuid()}),
        ('no_namespace', {'namespace': None})
    ]

    def setUp(self):
        super(IpMonitorTestCase, self).setUp()
        self.addCleanup(self._cleanup)
        if self.namespace:
            priv_ip_lib.create_netns(self.namespace)
        self.devices = [('int_' + uuidutils.generate_uuid())[
                        :constants.DEVICE_NAME_MAX_LEN] for _ in range(5)]
        self.ip_wrapper = ip_lib.IPWrapper(self.namespace)
        self.temp_file = self.get_temp_file_path('out_' + self.devices[0] +
                                                 '.tmp')
        self.proc = self._run_ip_monitor(ip_monitor)

    def _cleanup(self):
        self.proc.stop(kill_timeout=10, kill_signal=signal.SIGTERM)
        if self.namespace:
            priv_ip_lib.remove_netns(self.namespace)
        else:
            for device in self.devices:
                try:
                    priv_ip_lib.delete_interface(device, self.namespace)
                except priv_ip_lib.NetworkInterfaceNotFound:
                    pass

    @staticmethod
    def _normalize_module_name(name):
        for suf in ['.pyc', '.pyo']:
            if name.endswith(suf):
                return name[:-len(suf)] + '.py'
        return name

    def _run_ip_monitor(self, module):
        executable = self._normalize_module_name(module.__file__)
        proc = async_process.AsyncProcess(
            [executable, self.temp_file, str(self.namespace)],
            run_as_root=True)
        proc.start(block=True)
        return proc

    def _read_file(self, ip_addresses):
        try:
            registers = []
            with open(self.temp_file, 'r') as f:
                data = f.read()
                for line in data.splitlines():
                    register = jsonutils.loads(line)
                    registers.append({'name': register['name'],
                                      'cidr': register['cidr'],
                                      'event': register['event']})
            for ip_address in ip_addresses:
                if ip_address not in registers:
                    return False
            return True
        except (OSError, IOError) as e:
            return False

    def _check_read_file(self, ip_addresses):
        try:
            utils.wait_until_true(lambda: self._read_file(ip_addresses),
                                  timeout=30)
        except utils.WaitTimeout:
            with open(self.temp_file, 'r') as f:
                registers = f.read()
            self.fail('Defined IP addresses: %s, IP addresses registered: %s' %
                      (ip_addresses, registers))

    def _handle_ip_addresses(self, event, ip_addresses):
        for ip_address in (_ip for _ip in ip_addresses
                           if _ip['event'] == event):
            ip_device = ip_lib.IPDevice(ip_address['name'], self.namespace)
            if event == 'removed':
                ip_device.addr.delete(ip_address['cidr'])
            if event == 'added':
                ip_device.addr.add(ip_address['cidr'])

    def test_add_remove_ip_address_and_interface(self):
        for device in self.devices:
            self.ip_wrapper.add_dummy(device)
        utils.wait_until_true(lambda: self._read_file({}), timeout=30)
        ip_addresses = [
            {'cidr': '192.168.250.1/24', 'event': 'added',
             'name': self.devices[0]},
            {'cidr': '192.168.250.2/24', 'event': 'added',
             'name': self.devices[1]},
            {'cidr': '192.168.250.3/24', 'event': 'added',
             'name': self.devices[2]},
            {'cidr': '192.168.250.10/24', 'event': 'added',
             'name': self.devices[3]},
            {'cidr': '192.168.250.10/24', 'event': 'removed',
             'name': self.devices[3]},
            {'cidr': '2001:db8::1/64', 'event': 'added',
             'name': self.devices[4]},
            {'cidr': '2001:db8::2/64', 'event': 'added',
             'name': self.devices[4]}]

        self._handle_ip_addresses('added', ip_addresses)
        self._handle_ip_addresses('removed', ip_addresses)
        self._check_read_file(ip_addresses)

        ip_device = ip_lib.IPDevice(self.devices[4], self.namespace)
        ip_device.link.delete()
        ip_addresses = [
            {'cidr': '2001:db8::1/64', 'event': 'removed',
             'name': self.devices[4]},
            {'cidr': '2001:db8::2/64', 'event': 'removed',
             'name': self.devices[4]}]
        self._check_read_file(ip_addresses)

    def test_interface_added_after_initilization(self):
        for device in self.devices[:len(self.devices) - 1]:
            self.ip_wrapper.add_dummy(device)
        utils.wait_until_true(lambda: self._read_file({}), timeout=30)
        ip_addresses = [
            {'cidr': '192.168.251.21/24', 'event': 'added',
             'name': self.devices[0]},
            {'cidr': '192.168.251.22/24', 'event': 'added',
             'name': self.devices[1]}]

        self._handle_ip_addresses('added', ip_addresses)
        self._check_read_file(ip_addresses)

        self.ip_wrapper.add_dummy(self.devices[-1])
        ip_addresses.append({'cidr': '192.168.251.23/24', 'event': 'added',
                             'name': self.devices[-1]})

        self._handle_ip_addresses('added', [ip_addresses[-1]])
        self._check_read_file(ip_addresses)

    def test_add_and_remove_multiple_ips(self):
        # NOTE(ralonsoh): testing [1], adding multiple IPs.
        # [1] https://bugs.launchpad.net/neutron/+bug/1832307
        utils.wait_until_true(lambda: self._read_file({}), timeout=30)
        self.ip_wrapper.add_dummy(self.devices[0])
        ip_addresses = []
        for i in range(100):
            _cidr = str(netaddr.IPNetwork('192.168.252.1/32').ip + i) + '/32'
            ip_addresses.append({'cidr': _cidr, 'event': 'added',
                                 'name': self.devices[0]})

        self._handle_ip_addresses('added', ip_addresses)
        self._check_read_file(ip_addresses)

        for i in range(100):
            _cidr = str(netaddr.IPNetwork('192.168.252.1/32').ip + i) + '/32'
            ip_addresses.append({'cidr': _cidr, 'event': 'removed',
                                 'name': self.devices[0]})

        self._handle_ip_addresses('removed', ip_addresses)
        self._check_read_file(ip_addresses)


class IpRouteCommandTestCase(functional_base.BaseSudoTestCase):

    def setUp(self):
        super(IpRouteCommandTestCase, self).setUp()
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        ip_lib.IPWrapper(self.namespace).add_dummy('test_device')
        self.device = ip_lib.IPDevice('test_device', namespace=self.namespace)
        self.device.link.set_up()
        self.device_cidr_ipv4 = '192.168.100.1/24'
        self.device_cidr_ipv6 = '2020::1/64'
        self.device.addr.add(self.device_cidr_ipv4)
        self.device.addr.add(self.device_cidr_ipv6)
        self.cidrs = ['192.168.0.0/24', '10.0.0.0/8', '2001::/64', 'faaa::/96']

    def _assert_route(self, ip_version, table=None, source_prefix=None,
                      cidr=None, scope=None, via=None, metric=None,
                      not_in=False):
        if not_in:
            fn = lambda: cmp not in self.device.route.list_routes(ip_version,
                                                                  table=table)
            msg = 'Route found: %s'
        else:
            fn = lambda: cmp in self.device.route.list_routes(ip_version,
                                                              table=table)
            msg = 'Route not found: %s'

        if cidr:
            ip_version = utils.get_ip_version(cidr)
        else:
            ip_version = utils.get_ip_version(via)
            cidr = constants.IP_ANY[ip_version]
        if constants.IP_VERSION_6 == ip_version:
            scope = ip_lib.IP_ADDRESS_SCOPE[0]
        elif not scope:
            scope = 'global' if via else 'link'
        if not metric:
            metric = ip_lib.IP_ROUTE_METRIC_DEFAULT[ip_version]
        table = table or iproute_linux.DEFAULT_TABLE
        table = ip_lib.IP_RULE_TABLES_NAMES.get(table, table)
        cmp = {'table': table,
               'cidr': cidr,
               'source_prefix': source_prefix,
               'scope': scope,
               'device': 'test_device',
               'via': via,
               'metric': metric}
        try:
            utils.wait_until_true(fn, timeout=5)
        except utils.WaitTimeout:
            raise self.fail(msg % cmp)

    def test_add_route_table(self):
        tables = (None, 1, 253, 254, 255)
        for cidr in self.cidrs:
            for table in tables:
                self.device.route.add_route(cidr, table=table)
                ip_version = utils.get_ip_version(cidr)
                self._assert_route(ip_version, cidr=cidr, table=table)

    def test_add_route_via(self):
        gateway_ipv4 = str(netaddr.IPNetwork(self.device_cidr_ipv4).ip)
        gateway_ipv6 = str(netaddr.IPNetwork(self.device_cidr_ipv6).ip + 1)
        for cidr in self.cidrs:
            ip_version = utils.get_ip_version(cidr)
            gateway = (gateway_ipv4 if ip_version == constants.IP_VERSION_4
                       else gateway_ipv6)
            self.device.route.add_route(cidr, via=gateway)
            self._assert_route(ip_version, cidr=cidr, via=gateway)

    def test_add_route_metric(self):
        metrics = (None, 1, 10, 255)
        for cidr in self.cidrs:
            for metric in metrics:
                self.device.route.add_route(cidr, metric=metric)
                ip_version = utils.get_ip_version(cidr)
                self._assert_route(ip_version, cidr=cidr, metric=metric)

    def test_add_route_scope(self):
        for cidr in self.cidrs:
            for scope in ip_lib.IP_ADDRESS_SCOPE_NAME:
                self.device.route.add_route(cidr, scope=scope)
                ip_version = utils.get_ip_version(cidr)
                self._assert_route(ip_version, cidr=cidr, scope=scope)

    def test_add_route_gateway(self):
        gateways = (str(netaddr.IPNetwork(self.device_cidr_ipv4).ip),
                    str(netaddr.IPNetwork(self.device_cidr_ipv6).ip + 1))
        for gateway in gateways:
            ip_version = utils.get_ip_version(gateway)
            self.device.route.add_gateway(gateway)
            self._assert_route(ip_version, cidr=None, via=gateway,
                               scope='global')

    def test_list_onlink_routes_ipv4(self):
        cidr_ipv4 = []
        for cidr in self.cidrs:
            if utils.get_ip_version(cidr) == constants.IP_VERSION_4:
                cidr_ipv4.append(cidr)
                self.device.route.add_onlink_route(cidr)

        for cidr in cidr_ipv4:
            self._assert_route(constants.IP_VERSION_4, cidr=cidr)

        routes = self.device.route.list_onlink_routes(constants.IP_VERSION_4)
        self.assertEqual(len(cidr_ipv4), len(routes))

    def test_get_and_delete_gateway(self):
        gateways = (str(netaddr.IPNetwork(self.device_cidr_ipv4).ip),
                    str(netaddr.IPNetwork(self.device_cidr_ipv6).ip + 1))
        scopes = ('global', 'site', 'link')
        metrics = (None, 1, 255)
        tables = (None, 1, 254, 255)
        for gateway, scope, metric, table in itertools.product(
                gateways, scopes, metrics, tables):
            ip_version = utils.get_ip_version(gateway)
            self.device.route.add_gateway(gateway, scope=scope, metric=metric,
                                          table=table)
            self._assert_route(ip_version, cidr=None, via=gateway, scope=scope,
                               metric=metric, table=table)
            self.assertEqual(gateway, self.device.route.get_gateway(
                ip_version=ip_version, table=table)['via'])

            self.device.route.delete_gateway(gateway, table=table, scope=scope)
            self.assertIsNone(self.device.route.get_gateway(
                ip_version=ip_version, table=table))

    def test_delete_route(self):
        scopes = ('global', 'site', 'link')
        tables = (None, 1, 254, 255)
        for cidr, scope, table in itertools.product(
                self.cidrs, scopes, tables):
            ip_version = utils.get_ip_version(cidr)
            self.device.route.add_route(cidr, table=table, scope=scope)
            self._assert_route(ip_version, cidr=cidr, scope=scope, table=table)

            self.device.route.delete_route(cidr, table=table, scope=scope)
            self._assert_route(ip_version, cidr=cidr, scope=scope, table=table,
                               not_in=True)

    def test_flush(self):
        tables = (None, 1, 200)
        ip_versions = (constants.IP_VERSION_4, constants.IP_VERSION_6)
        for cidr, table in itertools.product(self.cidrs, tables):
            self.device.route.add_route(cidr, table=table)

        for ip_version, table in itertools.product(ip_versions, tables):
            routes = self.device.route.list_routes(ip_version, table=table)
            self.assertGreater(len(routes), 0)
            self.device.route.flush(ip_version, table=table)
            routes = self.device.route.list_routes(ip_version, table=table)
            self.assertEqual([], routes)


class IpAddrCommandTestCase(functional_base.BaseSudoTestCase):

    def setUp(self):
        super(IpAddrCommandTestCase, self).setUp()
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        ip_lib.IPWrapper(self.namespace).add_dummy('test_device')
        self.device = ip_lib.IPDevice('test_device', namespace=self.namespace)
        self.device.link.set_up()

    def test_list_with_scope(self):
        scope_ip = [
            ('global', '192.168.100.1/24'),
            ('global', '2001:db8::1/64'),
            ('link', '192.168.101.1/24'),
            ('link', 'fe80::1:1/64'),
            ('site', 'fec0:0:0:f101::1/64'),
            ('host', '192.168.102.1/24')]
        for scope, _ip in scope_ip:
            self.device.addr.add(_ip, scope=scope)

        devices = self.device.addr.list()
        devices_cidr = {device['cidr'] for device in devices}
        for scope in scope_ip:
            self.assertIn(scope[1], devices_cidr)

        for scope, _ip in scope_ip:
            devices_filtered = self.device.addr.list(scope=scope)
            devices_cidr = {device['cidr'] for device in devices_filtered}
            self.assertIn(_ip, devices_cidr)
