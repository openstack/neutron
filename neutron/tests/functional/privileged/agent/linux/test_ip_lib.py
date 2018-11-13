# Copyright 2018 Red Hat, Inc.
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

from oslo_utils import uuidutils

from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib
from neutron.tests.functional import base as functional_base


class GetDevicesTestCase(functional_base.BaseLoggingTestCase):

    def _remove_ns(self, namespace):
        priv_ip_lib.remove_netns(namespace)

    def test_get_devices(self):
        namespace = 'ns_test-' + uuidutils.generate_uuid()
        priv_ip_lib.create_netns(namespace)
        self.addCleanup(self._remove_ns, namespace)
        interfaces = ['int_01', 'int_02', 'int_03', 'int_04', 'int_05']
        interfaces_to_check = (interfaces + ip_lib.FB_TUNNEL_DEVICE_NAMES +
                               [ip_lib.LOOPBACK_DEVNAME])
        for interface in interfaces:
            priv_ip_lib.create_interface(interface, namespace, 'dummy')

        device_names = priv_ip_lib.get_devices(namespace)
        for name in device_names:
            self.assertIn(name, interfaces_to_check)

        for interface in interfaces:
            priv_ip_lib.delete_interface(interface, namespace)

        device_names = priv_ip_lib.get_devices(namespace)
        for name in device_names:
            self.assertNotIn(name, interfaces)


class ListIpRulesTestCase(functional_base.BaseSudoTestCase):

    RULE_TABLES = {'default': 253, 'main': 254, 'local': 255}

    def setUp(self):
        super(ListIpRulesTestCase, self).setUp()
        self.namespace = 'ns_test-' + uuidutils.generate_uuid()
        self.ns = priv_ip_lib.create_netns(self.namespace)
        self.ip_rule = ip_lib.IPRule(namespace=self.namespace)
        self.addCleanup(self._remove_ns)

    def _remove_ns(self):
        priv_ip_lib.remove_netns(self.namespace)

    def test_list_default_rules_ipv4(self):
        rules_ipv4 = priv_ip_lib.list_ip_rules(self.namespace, 4)
        self.assertEqual(3, len(rules_ipv4))
        rule_tables = list(self.RULE_TABLES.values())
        for rule in rules_ipv4:
            rule_tables.remove(rule['table'])
        self.assertEqual(0, len(rule_tables))

    def test_list_rules_ipv4(self):
        self.ip_rule.rule.add('192.168.0.1/24', table=10)
        rules_ipv4 = priv_ip_lib.list_ip_rules(self.namespace, 4)
        for rule in rules_ipv4:
            if rule['table'] == 10:
                self.assertEqual('192.168.0.1', rule['attrs']['FRA_SRC'])
                self.assertEqual(24, rule['src_len'])
                break
        else:
            self.fail('Rule added (192.168.0.1/24, table 10) not found')

    def test_list_default_rules_ipv6(self):
        rules_ipv6 = priv_ip_lib.list_ip_rules(self.namespace, 6)
        self.assertEqual(2, len(rules_ipv6))
        rule_tables = [255, 254]
        for rule in rules_ipv6:
            rule_tables.remove(rule['table'])
        self.assertEqual(0, len(rule_tables))

    def test_list_rules_ipv6(self):
        self.ip_rule.rule.add('2001:db8::1/64', table=20)
        rules_ipv6 = priv_ip_lib.list_ip_rules(self.namespace, 6)
        for rule in rules_ipv6:
            if rule['table'] == 20:
                self.assertEqual('2001:db8::1', rule['attrs']['FRA_SRC'])
                self.assertEqual(64, rule['src_len'])
                break
        else:
            self.fail('Rule added (2001:db8::1/64, table 20) not found')
