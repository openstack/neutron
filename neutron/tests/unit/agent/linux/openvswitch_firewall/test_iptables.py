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

import mock

from neutron.agent.linux import iptables_firewall
from neutron.agent.linux.openvswitch_firewall import iptables
from neutron.tests import base


class TestHelper(base.BaseTestCase):
    def setUp(self):
        super(TestHelper, self).setUp()
        self.helper = iptables.Helper(mock.Mock())
        mock.patch.object(iptables_firewall, 'cfg').start()
        mock.patch('neutron.agent.linux.ip_conntrack.get_conntrack').start()

    def test_get_hybrid_ports(self):
        present_ports = ['tap1234', 'qvo-1234', 'tap9876', 'qvo-fghfhfh']
        self.helper.int_br.get_port_name_list.return_value = present_ports
        expected_hybrid_ports = ['qvo-1234', 'qvo-fghfhfh']
        observed = self.helper.get_hybrid_ports()
        self.assertItemsEqual(expected_hybrid_ports, observed)

    def test_has_not_been_cleaned_no_value(self):
        other_config = {'foo': 'bar'}
        self.helper.int_br.db_get_val.return_value = other_config
        self.assertTrue(self.helper.has_not_been_cleaned)

    def test_has_not_been_cleaned_true(self):
        other_config = {'foo': 'bar', iptables.Helper.CLEANED_METADATA: 'true'}
        self.helper.int_br.db_get_val.return_value = other_config
        self.assertFalse(self.helper.has_not_been_cleaned)

    def test_has_not_been_cleaned_false(self):
        other_config = {'foo': 'bar',
                        iptables.Helper.CLEANED_METADATA: 'false'}
        self.helper.int_br.db_get_val.return_value = other_config
        self.assertTrue(self.helper.has_not_been_cleaned)

    def test_load_driver_if_needed_no_hybrid_ports(self):
        self.helper.int_br.get_port_name_list.return_value = [
            'tap1234', 'tap9876']
        self.helper.load_driver_if_needed()
        self.assertIsNone(self.helper.iptables_driver)

    def test_load_driver_if_needed_hybrid_ports_cleaned(self):
        """If was cleaned, driver shouldn't be loaded."""
        self.helper.int_br.get_port_name_list.return_value = [
            'tap1234', 'qvo-1234', 'tap9876', 'qvo-fghfhfh']
        self.helper.int_br.db_get_val.return_value = {
            'foo': 'bar', iptables.Helper.CLEANED_METADATA: 'true'}
        self.helper.load_driver_if_needed()
        self.assertIsNone(self.helper.iptables_driver)

    def test_load_driver_if_needed_hybrid_ports_not_cleaned(self):
        """If hasn't been cleaned, driver should be loaded."""
        self.helper.int_br.get_port_name_list.return_value = [
            'tap1234', 'qvo-1234', 'tap9876', 'qvo-fghfhfh']
        self.helper.int_br.db_get_val.return_value = {'foo': 'bar'}
        self.helper.load_driver_if_needed()
        self.assertIsNotNone(self.helper.iptables_driver)

    def test_get_iptables_driver_instance_has_correct_instance(self):
        instance = iptables.get_iptables_driver_instance()
        self.assertIsInstance(
            instance,
            iptables_firewall.OVSHybridIptablesFirewallDriver)

    def test_cleanup_port_last_port_marks_cleaned(self):
        self.helper.iptables_driver = mock.Mock()
        self.helper.hybrid_ports = {'qvoport'}
        with mock.patch.object(self.helper, 'mark_as_cleaned') as mock_mark:
            self.helper.cleanup_port({'device': 'port'})
        self.assertIsNone(self.helper.iptables_driver)
        self.assertTrue(mock_mark.called)

    def test_cleanup_port_existing_ports(self):
        self.helper.iptables_driver = mock.Mock()
        self.helper.hybrid_ports = {'qvoport', 'qvoanother'}
        with mock.patch.object(self.helper, 'mark_as_cleaned') as mock_mark:
            self.helper.cleanup_port({'device': 'port'})
        self.assertIsNotNone(self.helper.iptables_driver)
        self.assertFalse(mock_mark.called)

    def test_cleanup_port_unknown(self):
        self.helper.iptables_driver = mock.Mock()
        self.helper.hybrid_ports = {'qvoanother'}
        self.helper.cleanup_port({'device': 'port'})
        self.assertFalse(self.helper.iptables_driver.remove_port_filter.called)


class TestHybridIptablesHelper(base.BaseTestCase):

    def test_overloaded_remove_conntrack(self):
        with mock.patch.object(iptables_firewall.IptablesFirewallDriver,
                '_remove_conntrack_entries_from_port_deleted') as rcefpd, \
             mock.patch("neutron.agent.linux.ip_conntrack.IpConntrackManager"
                        "._populate_initial_zone_map"):
            firewall = iptables.get_iptables_driver_instance()
            firewall._remove_conntrack_entries_from_port_deleted(None)
            rcefpd.assert_not_called()
