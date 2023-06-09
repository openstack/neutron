# Copyright 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from oslo_config import cfg
from oslo_upgradecheck.upgradecheck import Code

from neutron.cmd.upgrade_checks import checks
from neutron.tests import base


class TestChecks(base.BaseTestCase):

    def setUp(self):
        super(TestChecks, self).setUp()
        self.checks = checks.CoreChecks()

    def test_get_checks_list(self):
        self.assertIsInstance(self.checks.get_checks(), list)

    def test_worker_check_good(self):
        cfg.CONF.set_override("api_workers", 2)
        cfg.CONF.set_override("rpc_workers", 2)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.SUCCESS, result.code)

    def test_worker_check_api_missing(self):
        cfg.CONF.set_override("api_workers", None)
        cfg.CONF.set_override("rpc_workers", 2)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_worker_check_rpc_missing(self):
        cfg.CONF.set_override("api_workers", 2)
        cfg.CONF.set_override("rpc_workers", None)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_worker_check_both_missing(self):
        cfg.CONF.set_override("api_workers", None)
        cfg.CONF.set_override("rpc_workers", None)
        result = checks.CoreChecks.worker_count_check(mock.Mock())
        self.assertEqual(Code.WARNING, result.code)

    def test_external_network_bridge_check_good(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"external_network_bridge": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.external_network_bridge_check(
                mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)

    def test_external_network_bridge_check_bad(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"external_network_bridge": "br-ex"}'},
            {'host': 'Host C',
             'configurations': '{"external_network_bridge": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.external_network_bridge_check(
                mock.Mock())
            self.assertEqual(Code.WARNING, result.code)
            self.assertIn('Host B', result.details)
            self.assertNotIn('Host A', result.details)
            self.assertNotIn('Host C', result.details)

    def test_gateway_external_network_check_good(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"gateway_external_network_id": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.gateway_external_network_check(
                mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)

    def test_gateway_external_network_check_bad(self):
        agents = [
            {'host': 'Host A', 'configurations': '{}'},
            {'host': 'Host B',
             'configurations': '{"gateway_external_network_id": "net-uuid"}'},
            {'host': 'Host C',
             'configurations': '{"gateway_external_network_id": ""}'}
        ]
        with mock.patch.object(checks, "get_l3_agents", return_value=agents):
            result = checks.CoreChecks.gateway_external_network_check(
                mock.Mock())
            self.assertEqual(Code.WARNING, result.code)
            self.assertIn('Host B', result.details)
            self.assertNotIn('Host A', result.details)
            self.assertNotIn('Host C', result.details)

    def test_network_mtu_check_good(self):
        networks = [
            {'id': 'net-uuid-a', 'mtu': 1500},
            {'id': 'net-uuid-b', 'mtu': 1450}
        ]
        with mock.patch.object(checks, "get_networks", return_value=networks):
            result = checks.CoreChecks.network_mtu_check(
                mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)

    def test_network_mtu_check_bad(self):
        networks = [
            {'id': 'net-uuid-a', 'mtu': None},
            {'id': 'net-uuid-b', 'mtu': 1500},
        ]
        with mock.patch.object(checks, "get_networks", return_value=networks):
            result = checks.CoreChecks.network_mtu_check(
                mock.Mock())
            self.assertEqual(Code.WARNING, result.code)
            self.assertIn('net-uuid-a', result.details)
            self.assertNotIn('net-uuid-b', result.details)

    def test_ovn_db_revision_check_no_networking_ovn_installed(self):
        with mock.patch.object(checks, "table_exists", return_value=False),\
                mock.patch.object(
                    checks, "get_ovn_db_revisions") as get_ovn_db_revisions:
            result = checks.CoreChecks.ovn_db_revision_check(mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)
            get_ovn_db_revisions.assert_not_called()

    def test_ovn_db_revision_check_networking_ovn_latest_revision(self):
        revisions = [
            checks.LAST_NETWORKING_OVN_EXPAND_HEAD,
            checks.LAST_NETWORKING_OVN_CONTRACT_HEAD]
        with mock.patch.object(checks, "table_exists", return_value=True),\
                mock.patch.object(
                    checks, "get_ovn_db_revisions",
                    return_value=revisions) as get_ovn_db_revisions:
            result = checks.CoreChecks.ovn_db_revision_check(mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)
            get_ovn_db_revisions.assert_called_once_with()

    def test_ovn_db_revision_check_networking_ovn_not_latest_revision(self):
        revisions = ["some_older_revision"]
        with mock.patch.object(checks, "table_exists", return_value=True),\
                mock.patch.object(
                    checks, "get_ovn_db_revisions",
                    return_value=revisions) as get_ovn_db_revisions:
            result = checks.CoreChecks.ovn_db_revision_check(mock.Mock())
            self.assertEqual(Code.FAILURE, result.code)
            get_ovn_db_revisions.assert_called_once_with()

    def test_nic_switch_agent_min_kernel_check_no_nic_switch_agents(self):
        with mock.patch.object(checks, "get_nic_switch_agents",
                               return_value=[]):
            result = checks.CoreChecks.nic_switch_agent_min_kernel_check(
                mock.Mock())
            self.assertEqual(Code.SUCCESS, result.code)

    def test_nic_switch_agent_min_kernel_check(self):
        agents = [
            {'host': 'Host A'},
            {'host': 'Host B'}
        ]
        with mock.patch.object(checks, "get_nic_switch_agents",
                               return_value=agents):
            result = checks.CoreChecks.nic_switch_agent_min_kernel_check(
                mock.Mock())
            self.assertEqual(Code.WARNING, result.code)
            self.assertIn('Host A', result.details)
            self.assertIn('Host B', result.details)

    def test_vlan_allocations_segid_check(self):
        cases = ([0, Code.SUCCESS], [1, Code.WARNING])
        with mock.patch.object(
                checks, 'count_vlan_allocations_invalid_segmentation_id') \
                as mock_count:
            for count, returned_code in cases:
                mock_count.return_value = count
                result = checks.CoreChecks.vlan_allocations_segid_check(
                    mock.ANY)
                self.assertEqual(returned_code, result.code)

    def test_port_mac_address_sanity(self):
        cases = ((['ca:fe:ca:fe:ca:fe'], Code.SUCCESS),
                 (['ca:fe:ca:fe:ca:f'], Code.WARNING))
        with mock.patch.object(
                checks, 'port_mac_addresses') \
                as mock_port_mac_addresses:
            for mac_addresses, returned_code in cases:
                mock_port_mac_addresses.return_value = mac_addresses
                result = checks.CoreChecks.port_mac_address_sanity(mock.ANY)
                self.assertEqual(returned_code, result.code)

    def test_networksegments_unique_constraint_check(self):
        cases = ([0, Code.SUCCESS], [1, Code.WARNING])
        with mock.patch.object(
                checks, 'get_duplicate_network_segment_count') as mock_count:
            for count, returned_code in cases:
                mock_count.return_value = count
                result = checks.CoreChecks.\
                    networksegments_unique_constraint_check(mock.ANY)
                self.assertEqual(returned_code, result.code)

    def test_port_binding_profile_sanity(self):
        new_format = {"allocation":
            {"397aec7a-1f69-11ec-9f1a-7b14e597e275":
                "41d7391e-1f69-11ec-a899-8f9d6d950f8d"}}
        old_format = {"allocation": "41d7391e-1f69-11ec-a899-8f9d6d950f8d"}
        cases = (([new_format], Code.SUCCESS),
                 ([old_format], Code.FAILURE))
        with mock.patch.object(
                checks, 'port_binding_profiles') \
                as mock_port_binding_profiles:
            for profile, returned_code in cases:
                mock_port_binding_profiles.return_value = profile
                result = checks.CoreChecks.port_binding_profile_sanity(
                    mock.ANY)
                self.assertEqual(returned_code, result.code)

    def test_floatingip_inherit_qos_from_network(self):
        cases = ([[], mock.ANY, Code.SUCCESS],
                 [['net1'], 0, Code.SUCCESS],
                 [['net1'], 1, Code.WARNING])
        with mock.patch.object(
                checks, 'get_external_networks_with_qos_policies') \
                as mock_nets, \
                mock.patch.object(checks,
                                  'get_fip_per_network_without_qos_policies') \
                as mock_fips:
            for _nets, _fips, returned_code in cases:
                mock_nets.return_value = _nets
                mock_fips.return_value = _fips
                result = checks.CoreChecks. \
                    floatingip_inherit_qos_from_network(mock.ANY)
                self.assertEqual(returned_code, result.code)

    def test_extra_dhcp_options_check_all_good(self):
        with mock.patch.object(
                checks, 'get_extra_dhcp_opts') as get_extra_dhcp_opts_mock:
            get_extra_dhcp_opts_mock.return_value = [
                mock.Mock(port_id="port-1", opt_name='foo', opt_value='bar')]
            result = checks.CoreChecks.extra_dhcp_options_check(mock.ANY)
            self.assertEqual(Code.SUCCESS, result.code)

    def test_extra_dhcp_options_check_bad_name(self):
        with mock.patch.object(
                checks, 'get_extra_dhcp_opts') as get_extra_dhcp_opts_mock:
            get_extra_dhcp_opts_mock.return_value = [
                mock.Mock(port_id='good',
                          opt_name='foo',
                          opt_value='bar'),
                mock.Mock(port_id='bad-name',
                          opt_name='foo\nfoo',
                          opt_value='bar')]
            result = checks.CoreChecks.extra_dhcp_options_check(mock.ANY)
            self.assertEqual(Code.WARNING, result.code)

    def test_extra_dhcp_options_check_bad_value(self):
        with mock.patch.object(
                checks, 'get_extra_dhcp_opts') as get_extra_dhcp_opts_mock:
            get_extra_dhcp_opts_mock.return_value = [
                mock.Mock(port_id='good',
                          opt_name='foo',
                          opt_value='bar'),
                mock.Mock(port_id='bad-value',
                          opt_name='foo',
                          opt_value='bar\nbar')]
            result = checks.CoreChecks.extra_dhcp_options_check(mock.ANY)
            self.assertEqual(Code.WARNING, result.code)

    @mock.patch.object(checks, 'get_duplicated_ha_networks_per_project')
    def test_duplicated_ha_network_per_project_check_success(self,
                                                             mock_ha_nets):
        mock_ha_nets.return_value = []
        result = checks.CoreChecks.duplicated_ha_network_per_project_check(
            mock.ANY)
        self.assertEqual(Code.SUCCESS, result.code)

    @mock.patch.object(checks, 'get_duplicated_ha_networks_per_project')
    def test_duplicated_ha_network_per_project_check_warning(self,
                                                             mock_ha_nets):
        mock_ha_nets.return_value = [
            {'project_id': 'project1', 'network_id': 'net1'},
            {'project_id': 'project1', 'network_id': 'net2'},
        ]
        result = checks.CoreChecks.duplicated_ha_network_per_project_check(
            mock.ANY)
        self.assertEqual(Code.WARNING, result.code)
