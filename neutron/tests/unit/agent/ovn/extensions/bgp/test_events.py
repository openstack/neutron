# Copyright 2026 Red Hat, Inc.
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

from neutron.agent.ovn.extensions.bgp import events
from neutron.services.bgp import constants
from neutron.tests import base


class _FakeRow:
    """Minimal stand-in for an OVSDB row with external_ids."""

    def __init__(self, external_ids=None):
        if external_ids is not None:
            self.external_ids = external_ids


class GetExternalIdsListTestCase(base.BaseTestCase):

    def test_returns_list_of_stripped_values(self):
        row = _FakeRow({'k': 'a, b, c'})
        self.assertEqual(['a', 'b', 'c'],
                         events._get_external_ids_list(row, 'k'))

    def test_single_value(self):
        row = _FakeRow({'k': 'only'})
        self.assertEqual(['only'],
                         events._get_external_ids_list(row, 'k'))

    def test_only_reads_requested_key(self):
        row = _FakeRow({'k': 'a,b', 'other': 'x,y,z'})
        self.assertEqual(['a', 'b'],
                         events._get_external_ids_list(row, 'k'))

    def test_missing_key_returns_empty(self):
        row = _FakeRow({'other': 'val'})
        self.assertEqual([], events._get_external_ids_list(row, 'k'))

    def test_no_external_ids_attr_returns_empty(self):
        row = _FakeRow()
        self.assertEqual([], events._get_external_ids_list(row, 'k'))

    def test_empty_string_value_returns_empty(self):
        row = _FakeRow({'k': ''})
        self.assertEqual([], events._get_external_ids_list(row, 'k'))

    def test_whitespace_only_items_are_filtered(self):
        row = _FakeRow({'k': ' , ,  '})
        self.assertEqual([], events._get_external_ids_list(row, 'k'))

    def test_mixed_empty_and_valid_items(self):
        row = _FakeRow({'k': 'a, , b,  , c'})
        self.assertEqual(['a', 'b', 'c'],
                         events._get_external_ids_list(row, 'k'))

    def test_leading_and_trailing_commas(self):
        row = _FakeRow({'k': ',a,b,'})
        self.assertEqual(['a', 'b'],
                         events._get_external_ids_list(row, 'k'))

    def test_preserves_order(self):
        row = _FakeRow({'k': 'z,a,m'})
        self.assertEqual(['z', 'a', 'm'],
                         events._get_external_ids_list(row, 'k'))


class GetBgpPeerBridgesTestCase(base.BaseTestCase):

    def test_returns_set(self):
        row = _FakeRow(
            {constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'})
        result = events._get_bgp_peer_bridges(row)
        self.assertIsInstance(result, set)
        self.assertEqual({'br-bgp-1', 'br-bgp-2'}, result)

    def test_deduplicates(self):
        row = _FakeRow(
            {constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp,br-bgp'})
        self.assertEqual({'br-bgp'}, events._get_bgp_peer_bridges(row))

    def test_missing_key_returns_empty_set(self):
        row = _FakeRow({})
        self.assertEqual(set(), events._get_bgp_peer_bridges(row))

    def test_empty_value_returns_empty_set(self):
        row = _FakeRow({constants.AGENT_BGP_PEER_BRIDGES: ''})
        self.assertEqual(set(), events._get_bgp_peer_bridges(row))

    def test_whitespace_around_values(self):
        row = _FakeRow(
            {constants.AGENT_BGP_PEER_BRIDGES: ' br-1 , br-2 '})
        self.assertEqual({'br-1', 'br-2'},
                         events._get_bgp_peer_bridges(row))

    def test_single_bridge(self):
        row = _FakeRow({constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp'})
        self.assertEqual({'br-bgp'}, events._get_bgp_peer_bridges(row))


class GetOvnBridgeMappingsTestCase(base.BaseTestCase):

    def test_returns_bridge_to_mapping_dict(self):
        row = _FakeRow(
            {'ovn-bridge-mappings': 'physnet1:br-ex,physnet2:br-data'})
        result = events._get_ovn_bridge_mappings(row)
        self.assertEqual({
            'br-ex': 'physnet1:br-ex',
            'br-data': 'physnet2:br-data',
        }, result)

    def test_single_mapping(self):
        row = _FakeRow({'ovn-bridge-mappings': 'physnet:br-ex'})
        self.assertEqual({'br-ex': 'physnet:br-ex'},
                         events._get_ovn_bridge_mappings(row))

    def test_empty_value_returns_empty_dict(self):
        row = _FakeRow({'ovn-bridge-mappings': ''})
        self.assertEqual({}, events._get_ovn_bridge_mappings(row))

    def test_missing_key_returns_empty_dict(self):
        row = _FakeRow({})
        self.assertEqual({}, events._get_ovn_bridge_mappings(row))

    def test_whitespace_around_entries(self):
        row = _FakeRow(
            {'ovn-bridge-mappings': ' physnet1:br-ex , physnet2:br-data '})
        self.assertEqual({
            'br-ex': 'physnet1:br-ex',
            'br-data': 'physnet2:br-data',
        }, events._get_ovn_bridge_mappings(row))

    def test_duplicate_bridge_last_wins(self):
        row = _FakeRow(
            {'ovn-bridge-mappings': 'net1:br-ex,net2:br-ex'})
        result = events._get_ovn_bridge_mappings(row)
        self.assertEqual({'br-ex': 'net2:br-ex'}, result)

    def test_bgp_style_self_mapping(self):
        row = _FakeRow(
            {'ovn-bridge-mappings': 'br-bgp:br-bgp'})
        self.assertEqual({'br-bgp': 'br-bgp:br-bgp'},
                         events._get_ovn_bridge_mappings(row))

    def test_missing_colon_skipped(self):
        row = _FakeRow({'ovn-bridge-mappings': 'malformed'})
        self.assertEqual({}, events._get_ovn_bridge_mappings(row))

    def test_extra_colons_skipped(self):
        row = _FakeRow({'ovn-bridge-mappings': 'physnet:br:ex'})
        self.assertEqual({}, events._get_ovn_bridge_mappings(row))

    def test_trailing_colon_skipped(self):
        row = _FakeRow({'ovn-bridge-mappings': 'physnet:'})
        self.assertEqual({}, events._get_ovn_bridge_mappings(row))

    def test_malformed_entries_among_valid_ones(self):
        row = _FakeRow(
            {'ovn-bridge-mappings':
             'net1:br-ex,bad,a:b:c,net2:br-data,trailing:'})
        result = events._get_ovn_bridge_mappings(row)
        self.assertEqual({
            'br-ex': 'net1:br-ex',
            'br-data': 'net2:br-data',
        }, result)
