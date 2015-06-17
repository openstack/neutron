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
import os.path

import testtools

from neutron.agent.linux import iptables_manager
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.tests import base
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base as linux_base
from neutron.tests.functional.agent.linux.bin import ipt_binname
from neutron.tests.functional import base as functional_base


class IptablesManagerTestCase(functional_base.BaseSudoTestCase):
    DIRECTION_CHAIN_MAPPER = {'ingress': 'INPUT',
                              'egress': 'OUTPUT'}
    PROTOCOL_BLOCK_RULE = '-p %s -j DROP'
    PROTOCOL_PORT_BLOCK_RULE = '-p %s --dport %d -j DROP'

    def setUp(self):
        super(IptablesManagerTestCase, self).setUp()

        bridge = self.useFixture(net_helpers.VethBridgeFixture()).bridge
        self.client, self.server = self.useFixture(
            machine_fixtures.PeerMachines(bridge)).machines

        self.client_fw, self.server_fw = self.create_firewalls()
        # The port is used in isolated namespace that precludes possibility of
        # port conflicts
        self.port = net_helpers.get_free_namespace_port(
            constants.PROTO_NAME_TCP, self.server.namespace)

    def create_firewalls(self):
        client_iptables = iptables_manager.IptablesManager(
            namespace=self.client.namespace)
        server_iptables = iptables_manager.IptablesManager(
            namespace=self.server.namespace)

        return client_iptables, server_iptables

    def filter_add_rule(self, fw_manager, address, direction, protocol, port):
        self._ipv4_filter_execute(fw_manager, 'add_rule', direction, protocol,
                                  port)

    def filter_remove_rule(self, fw_manager, address, direction, protocol,
                           port):
        self._ipv4_filter_execute(fw_manager, 'remove_rule', direction,
                                  protocol, port)

    def _ipv4_filter_execute(self, fw_manager, method, direction, protocol,
                             port):
        chain, rule = self._get_chain_and_rule(direction, protocol, port)
        method = getattr(fw_manager.ipv4['filter'], method)
        method(chain, rule)
        fw_manager.apply()

    def _get_chain_and_rule(self, direction, protocol, port):
        chain = self.DIRECTION_CHAIN_MAPPER[direction]
        if port:
            rule = self.PROTOCOL_PORT_BLOCK_RULE % (protocol, port)
        else:
            rule = self.PROTOCOL_BLOCK_RULE % protocol
        return chain, rule

    def _test_with_nc(self, fw_manager, direction, port, protocol):
        netcat = net_helpers.NetcatTester(
            self.client.namespace, self.server.namespace,
            self.server.ip, self.port, protocol)
        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())
        self.filter_add_rule(
            fw_manager, self.server.ip, direction, protocol, port)
        with testtools.ExpectedException(RuntimeError):
            netcat.test_connectivity()
        self.filter_remove_rule(
            fw_manager, self.server.ip, direction, protocol, port)
        self.assertTrue(netcat.test_connectivity(True))

    def test_icmp(self):
        self.client.assert_ping(self.server.ip)
        self.server_fw.ipv4['filter'].add_rule('INPUT',
                                               linux_base.ICMP_BLOCK_RULE)
        self.server_fw.apply()
        self.client.assert_no_ping(self.server.ip)
        self.server_fw.ipv4['filter'].remove_rule('INPUT',
                                                  linux_base.ICMP_BLOCK_RULE)
        self.server_fw.apply()
        self.client.assert_ping(self.server.ip)

    def test_mangle_icmp(self):
        self.client.assert_ping(self.server.ip)
        self.server_fw.ipv4['mangle'].add_rule('INPUT',
                                               linux_base.ICMP_MARK_RULE)
        self.server_fw.ipv4['filter'].add_rule('INPUT',
                                               linux_base.MARKED_BLOCK_RULE)
        self.server_fw.apply()
        self.client.assert_no_ping(self.server.ip)
        self.server_fw.ipv4['mangle'].remove_rule('INPUT',
                                                  linux_base.ICMP_MARK_RULE)
        self.server_fw.ipv4['filter'].remove_rule('INPUT',
                                                  linux_base.MARKED_BLOCK_RULE)
        self.server_fw.apply()
        self.client.assert_ping(self.server.ip)

    def test_tcp_input_port(self):
        self._test_with_nc(self.server_fw, 'ingress', self.port,
                           protocol=net_helpers.NetcatTester.TCP)

    def test_tcp_output_port(self):
        self._test_with_nc(self.client_fw, 'egress', self.port,
                           protocol=net_helpers.NetcatTester.TCP)

    def test_tcp_input(self):
        self._test_with_nc(self.server_fw, 'ingress', port=None,
                           protocol=net_helpers.NetcatTester.TCP)

    def test_tcp_output(self):
        self._test_with_nc(self.client_fw, 'egress', port=None,
                           protocol=net_helpers.NetcatTester.TCP)

    def test_udp_input_port(self):
        self._test_with_nc(self.server_fw, 'ingress', self.port,
                           protocol=net_helpers.NetcatTester.UDP)

    def test_udp_output_port(self):
        self._test_with_nc(self.client_fw, 'egress', self.port,
                           protocol=net_helpers.NetcatTester.UDP)

    def test_udp_input(self):
        self._test_with_nc(self.server_fw, 'ingress', port=None,
                           protocol=net_helpers.NetcatTester.UDP)

    def test_udp_output(self):
        self._test_with_nc(self.client_fw, 'egress', port=None,
                           protocol=net_helpers.NetcatTester.UDP)


class IptablesManagerNonRootTestCase(base.BaseTestCase):
    @staticmethod
    def _normalize_module_name(name):
        for suf in ['.pyc', '.pyo']:
            if name.endswith(suf):
                return name[:-len(suf)] + '.py'
        return name

    def _test_binary_name(self, module, *extra_options):
        executable = self._normalize_module_name(module.__file__)
        expected = os.path.basename(executable)[:16]
        observed = utils.execute([executable] + list(extra_options)).rstrip()
        self.assertEqual(expected, observed)

    def test_binary_name(self):
        self._test_binary_name(ipt_binname)

    def test_binary_name_eventlet_spawn(self):
        self._test_binary_name(ipt_binname, 'spawn')
