# Copyright 2026 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron.agent.ovn.extensions import segment_bridge
from neutron.tests import base


class TestSegmentBridgeParsing(base.BaseTestCase):

    def test_ordered_prefixes_longest_first(self):
        prefixes = ['br', 'br-ex', '']
        self.assertEqual(['br-ex', 'br'],
                         segment_bridge.ordered_prefixes(prefixes))

    def test_matching_prefix_longest_wins(self):
        prefixes = ['br', 'br-ex']
        self.assertEqual('br-ex',
                         segment_bridge.matching_prefix('br-ex-100', prefixes))

    def test_vlan_from_bridge_name_valid(self):
        self.assertEqual(100,
                         segment_bridge.vlan_from_bridge_name('br-ex-100',
                                                              'br-ex'))

    def test_vlan_from_bridge_name_invalid(self):
        self.assertIsNone(segment_bridge.vlan_from_bridge_name('br-ex-foo',
                                                               'br-ex'))
        self.assertIsNone(segment_bridge.vlan_from_bridge_name('br-ex-0',
                                                               'br-ex'))
        self.assertIsNone(segment_bridge.vlan_from_bridge_name('br-ex-4095',
                                                               'br-ex'))
        self.assertIsNone(segment_bridge.vlan_from_bridge_name('br-ex',
                                                               'br-ex'))
        self.assertIsNone(segment_bridge.vlan_from_bridge_name('br-ex100',
                                                               'br-ex'))

    def test_desired_segment_bridges_from_mappings(self):
        value = ",".join([
            "physnet1:br-ex-100",
            "physnet2:br-provider-200",
            "physnet3:br-storage",
            "physnet4:br-ex-foo",
        ])
        prefixes = ['br-ex', 'br-provider']
        desired = segment_bridge.desired_segment_bridges_from_mappings(
            value, prefixes)

        expected = {
            segment_bridge.SegmentBridge(
                physnet='physnet1',
                bridge='br-ex-100',
                trunk_bridge='br-ex',
                vlan=100),
            segment_bridge.SegmentBridge(
                physnet='physnet2',
                bridge='br-provider-200',
                trunk_bridge='br-provider',
                vlan=200),
        }
        self.assertEqual(expected, desired)


class TestOvsBridgeMappingsUpdatedEvent(base.BaseTestCase):

    def test_ovs_event_match_fn_true_on_change(self):
        event = segment_bridge.OvsBridgeMappingsUpdatedEvent(
            ovn_agent=type('A', (), {'__getitem__': lambda *_: None})())

        row = type('R', (), {
            'external_ids': {'ovn-bridge-mappings': 'p1:br-ex-100'}})()
        old = type('R', (), {
            'external_ids': {'ovn-bridge-mappings': 'p1:br-ex-200'}})()

        self.assertTrue(event.match_fn(event.ROW_UPDATE, row, old))

    def test_ovs_event_match_fn_false_when_same(self):
        event = segment_bridge.OvsBridgeMappingsUpdatedEvent(
            ovn_agent=type('A', (), {'__getitem__': lambda *_: None})())

        row = type('R', (), {
            'external_ids': {'ovn-bridge-mappings': 'p1:br-ex-100'}})()
        old = type('R', (), {
            'external_ids': {'ovn-bridge-mappings': 'p1:br-ex-100'}})()

        self.assertFalse(event.match_fn(event.ROW_UPDATE, row, old))


class TestSegmentBridgeEnsure(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.ext = segment_bridge.SegmentBridgeExtension()
        self.ext.agent_api = mock.Mock()
        self.ext.agent_api.ovs_idl.db_set.return_value = mock.Mock(
            execute=mock.Mock())
        self.item = segment_bridge.SegmentBridge(
            physnet='physnet1',
            bridge='br-ex-100',
            trunk_bridge='br-ex',
            vlan=100,
        )

    def test__patch_port_names_unique(self):
        trunk, seg = self.ext._patch_port_names(self.item)
        self.assertNotEqual(trunk, seg)
        self.assertIn('br-ex', trunk)
        self.assertIn('100', trunk)

    def test__ensure_item_skips_when_trunk_missing(self):
        with mock.patch.object(self.ext, '_bridge_exists',
                               return_value=False), \
                mock.patch.object(self.ext, '_ensure_segment_bridge') as es, \
                mock.patch.object(self.ext, '_ensure_patch_ports') as ep, \
                mock.patch.object(self.ext,
                                  '_ensure_trunk_patch_vlan') as et:
            self.ext._ensure_item(self.item)

        es.assert_not_called()
        ep.assert_not_called()
        et.assert_not_called()

    def test__ensure_item_calls_ensure_when_trunk_exists(self):
        with mock.patch.object(self.ext, '_bridge_exists',
                               return_value=True), \
                mock.patch.object(self.ext, '_ensure_segment_bridge') as es, \
                mock.patch.object(self.ext, '_ensure_patch_ports') as ep, \
                mock.patch.object(self.ext,
                                  '_ensure_trunk_patch_vlan') as et:
            self.ext._ensure_item(self.item)

        es.assert_called_once_with(self.item)
        ep.assert_called_once_with(self.item)
        et.assert_called_once_with(self.item)

    def test__ensure_trunk_patch_vlan_sets_port(self):
        trunk_patch, _ = self.ext._patch_port_names(self.item)

        self.ext._ensure_trunk_patch_vlan(self.item)

        self.ext.agent_api.ovs_idl.db_set.assert_called_with(
            'Port', trunk_patch,
            ('vlan_mode', 'access'),
            ('tag', self.item.vlan),
        )


class TestSegmentBridgeManagedState(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.ext = segment_bridge.SegmentBridgeExtension()
        self.ext.agent_api = mock.Mock()
        self.item = segment_bridge.SegmentBridge(
            physnet='physnet1',
            bridge='br-ex-100',
            trunk_bridge='br-ex',
            vlan=100,
        )

    def test__managed_external_ids(self):
        self.assertEqual(
            {
                segment_bridge.MANAGED_KEY: segment_bridge.MANAGED_VAL,
                segment_bridge.OWNER_KEY: segment_bridge.OWNER_VAL,
                segment_bridge.PHYSNET_KEY: 'physnet1',
                segment_bridge.TRUNK_KEY: 'br-ex',
                segment_bridge.VLAN_KEY: '100',
            },
            self.ext._managed_external_ids(self.item))

    def test__is_managed_segment_bridge_true(self):
        row = type(
            'Row', (), {
                'external_ids': {
                    segment_bridge.MANAGED_KEY:
                        segment_bridge.MANAGED_VAL,
                    segment_bridge.OWNER_KEY:
                        segment_bridge.OWNER_VAL,
                }
            })()
        self.assertTrue(self.ext._is_managed_segment_bridge(row))

    def test__is_managed_segment_bridge_false(self):
        row = type(
            'Row', (), {
                'external_ids': {
                    segment_bridge.MANAGED_KEY: 'false',
                    segment_bridge.OWNER_KEY:
                        segment_bridge.OWNER_VAL,
                }
            })()
        self.assertFalse(self.ext._is_managed_segment_bridge(row))

    def test__row_to_segment_bridge(self):
        row = type(
            'Row', (), {
                'name': 'br-ex-100',
                'external_ids': {
                    segment_bridge.PHYSNET_KEY: 'physnet1',
                    segment_bridge.TRUNK_KEY: 'br-ex',
                    segment_bridge.VLAN_KEY: '100',
                }
            })()

        self.assertEqual(self.item, self.ext._row_to_segment_bridge(row))

    def test__row_to_segment_bridge_invalid_vlan(self):
        row = type(
            'Row', (), {
                'name': 'br-ex-foo',
                'external_ids': {
                    segment_bridge.PHYSNET_KEY: 'physnet1',
                    segment_bridge.TRUNK_KEY: 'br-ex',
                    segment_bridge.VLAN_KEY: 'foo',
                }
            })()

        self.assertIsNone(self.ext._row_to_segment_bridge(row))

    def test__actual_segment_bridges_returns_managed_only(self):
        managed_row = type(
            'Row', (), {
                'name': 'br-ex-100',
                'external_ids': {
                    segment_bridge.MANAGED_KEY:
                        segment_bridge.MANAGED_VAL,
                    segment_bridge.OWNER_KEY:
                        segment_bridge.OWNER_VAL,
                    segment_bridge.PHYSNET_KEY: 'physnet1',
                    segment_bridge.TRUNK_KEY: 'br-ex',
                    segment_bridge.VLAN_KEY: '100',
                }
            })()
        unmanaged_row = type(
            'Row', (), {
                'name': 'br-ex-200',
                'external_ids': {}
            })()

        bridge_table = mock.Mock()
        bridge_table.rows.values.return_value = [managed_row, unmanaged_row]
        self.ext.agent_api.ovs_idl.idl.tables.get.return_value = bridge_table

        self.assertEqual({self.item}, self.ext._actual_segment_bridges())

    def test__delete_item_deletes_patch_ports_and_bridge(self):
        with mock.patch.object(self.ext, '_bridge_exists',
                               side_effect=[True, True]), \
                mock.patch.object(self.ext, '_del_port_if_exists') as dp, \
                mock.patch.object(segment_bridge.ovs_lib,
                                  'OVSBridge') as ovs_bridge:
            self.ext._delete_item(self.item)

        trunk_patch, seg_patch = self.ext._patch_port_names(self.item)
        dp.assert_has_calls([
            mock.call(self.item.trunk_bridge, trunk_patch),
            mock.call(self.item.bridge, seg_patch),
        ])
        ovs_bridge.assert_called_with(self.item.bridge)
        ovs_bridge.return_value.delete_bridge.assert_called_once_with(
            self.item.bridge)

    def test__delete_item_skips_missing_trunk_bridge(self):
        with mock.patch.object(self.ext, '_bridge_exists',
                               side_effect=[False, True]), \
                mock.patch.object(self.ext, '_del_port_if_exists') as dp, \
                mock.patch.object(segment_bridge.ovs_lib,
                                  'OVSBridge') as ovs_bridge:
            self.ext._delete_item(self.item)

        _trunk_patch, seg_patch = self.ext._patch_port_names(self.item)
        dp.assert_called_once_with(self.item.bridge, seg_patch)
        ovs_bridge.return_value.delete_bridge.assert_called_once_with(
            self.item.bridge)

    def test__actual_segment_bridges_no_bridge_table(self):
        self.ext.agent_api.ovs_idl.idl.tables.get.return_value = None
        self.assertEqual(set(), self.ext._actual_segment_bridges())


class TestSegmentBridgePeriodicReconcile(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.ext = segment_bridge.SegmentBridgeExtension()
        self.ext.agent_api = mock.Mock()
        self.ext.agent_api.conf.ovn.segment_bridge_reconcile_interval = 60

    def test__start_periodic_reconcile_enabled(self):
        loop_obj = mock.Mock()

        with mock.patch.object(segment_bridge.loopingcall,
                               'FixedIntervalLoopingCall',
                               return_value=loop_obj) as loop:
            self.ext._start_periodic_reconcile()

        loop.assert_called_once_with(self.ext.reconcile)
        loop_obj.start.assert_called_once_with(
            interval=60, initial_delay=60)
        self.assertIs(loop_obj, self.ext._reconcile_loop)

    def test__start_periodic_reconcile_already_started(self):
        self.ext._reconcile_loop = mock.Mock()

        with mock.patch.object(segment_bridge.loopingcall,
                               'FixedIntervalLoopingCall') as loop:
            self.ext._start_periodic_reconcile()

        loop.assert_not_called()

    def test_start(self):
        with mock.patch.object(self.ext, 'reconcile') as reconcile, \
                mock.patch.object(self.ext,
                                  '_start_periodic_reconcile') as start:
            self.ext.start()

        reconcile.assert_called_once_with()
        start.assert_called_once_with()


class TestSegmentBridgeReconcile(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.ext = segment_bridge.SegmentBridgeExtension()
        self.item = segment_bridge.SegmentBridge(
            physnet='physnet1',
            bridge='br-ex-100',
            trunk_bridge='br-ex',
            vlan=100,
        )

    def test_reconcile_ensures_desired_even_when_already_actual(self):
        with mock.patch.object(self.ext, '_desired_segment_bridges',
                               return_value={self.item}), \
                mock.patch.object(self.ext, '_actual_segment_bridges',
                                  return_value={self.item}), \
                mock.patch.object(self.ext, '_ensure_item') as ensure, \
                mock.patch.object(self.ext, '_delete_item') as delete:
            self.ext.reconcile()

        ensure.assert_called_once_with(self.item)
        delete.assert_not_called()
