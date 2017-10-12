# Copyright 2017 Red Hat, Inc.
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

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent import firewall
from neutron.agent.linux import iptables_firewall
import neutron.agent.linux.openvswitch_firewall.firewall as ovs_fw_mod
import neutron.agent.linux.openvswitch_firewall.iptables as iptables_helper
from neutron.tests.common import conn_testers
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent import test_firewall
from neutron.tests.functional import base


class TestHelper(base.BaseSudoTestCase):
    def setUp(self):
        super(TestHelper, self).setUp()
        self.bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        self.iptables_firewall = (
            iptables_firewall.OVSHybridIptablesFirewallDriver(self.namespace))

    def add_sg_rules(self, port, security_group_rules):
        """Add security group rules to given port.

        Method creates a security group for isolated firewall use. Adds passed
        rules to it and calls to prepare_port_filter() to the firewall driver.
        Method returns port description.
        """
        sg_id = uuidutils.generate_uuid()
        self.iptables_firewall.update_security_group_rules(
            sg_id, security_group_rules)
        description = {
            'admin_state_up': True,
            'device': port.port_id,
            'device_owner': test_firewall.DEVICE_OWNER_COMPUTE,
            'fixed_ips': ['192.168.0.1'],
            'mac_address': port.port.link.address,
            'port_security_enabled': True,
            'security_groups': [sg_id],
            'status': 'ACTIVE',
            'network_id': uuidutils.generate_uuid()}

        self.iptables_firewall.prepare_port_filter(description)

        return description

    def _set_vlan_tag_on_port(self, port, tag):
        qvo_dev_name = iptables_helper.get_device_port_name(port.port_id)
        conn_testers.OVSBaseConnectionTester.set_tag(
            qvo_dev_name, self.bridge, tag)

    def _prepare_port_and_description(self, security_group_rules):
        hybrid_port = self.useFixture(
            net_helpers.OVSPortFixture(
                self.bridge, self.namespace, hybrid_plug=True))
        self._set_vlan_tag_on_port(hybrid_port, 1)
        description = self.add_sg_rules(hybrid_port, security_group_rules)

        return hybrid_port, description

    def _check_no_iptables_rules_for_port(self, port):
        tap_name = self.iptables_firewall._get_device_name(
            {'device': port.port_id})
        iptables_rules = (
            self.iptables_firewall.iptables.get_rules_for_table('filter'))
        for line in iptables_rules:
            if tap_name in line:
                raise Exception("port %s still has iptables rules in %s" % (
                    tap_name, line))

    def test_migration(self):
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': firewall.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP},
                    {'ethertype': constants.IPv4,
                     'direction': firewall.EGRESS_DIRECTION}]
        port, desc = self._prepare_port_and_description(sg_rules)
        ovs_firewall = ovs_fw_mod.OVSFirewallDriver(self.bridge)
        # Check that iptables driver was set and replace it with the one that
        # has access to namespace
        if isinstance(
                ovs_firewall.iptables_helper.iptables_driver,
                iptables_firewall.OVSHybridIptablesFirewallDriver):
            ovs_firewall.iptables_helper.iptables_driver = (
                self.iptables_firewall)
        ovs_firewall.prepare_port_filter(desc)
        self._check_no_iptables_rules_for_port(port)
