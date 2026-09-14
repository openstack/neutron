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

from dataclasses import dataclass
import re
import threading

from neutron_lib.utils import helpers
from oslo_log import log as logging
from oslo_service import loopingcall
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.agent.common import ovs_lib
from neutron.agent.ovn.extensions import extension_manager
from neutron.common.ovn import constants

LOG = logging.getLogger(__name__)

EXT_NAME = 'segment_bridge'


MANAGED_KEY = 'neutron-ovn-agent-managed'
MANAGED_VAL = 'true'
OWNER_KEY = 'neutron-ovn-agent-owner'
OWNER_VAL = 'segment-bridge'
PHYSNET_KEY = 'neutron-segment-physnet'
TRUNK_KEY = 'neutron-segment-trunk'
VLAN_KEY = 'neutron-segment-vlan'


@dataclass(frozen=True, order=True)
class SegmentBridge:
    physnet: str
    bridge: str
    trunk_bridge: str
    vlan: int


def ordered_prefixes(prefixes):
    """Return prefixes sorted longest-first and without empty values."""
    return sorted([p for p in (prefixes or []) if p], key=len, reverse=True)


def matching_prefix(bridge_name, prefixes):
    """Return the best matching prefix for bridge_name or None."""
    for prefix in ordered_prefixes(prefixes):
        if bridge_name.startswith(prefix):
            return prefix
    return None


def vlan_from_bridge_name(bridge_name, prefix):
    """Extract VLAN ID from '<prefix>-<vlan>' bridge name."""
    match = re.fullmatch(rf'{re.escape(prefix)}-(\d+)', bridge_name)
    if not match:
        return None
    vlan = int(match.group(1))
    if vlan < 1 or vlan > 4094:
        return None
    return vlan


def desired_segment_bridges_from_mappings(mappings_value, prefixes):
    """Return desired set [SegmentBridge] from ovn-bridge-mappings."""
    desired = set()
    parsed_mappings = helpers.parse_mappings(mappings_value.split(','))
    for physnet, bridge in parsed_mappings.items():
        prefix = matching_prefix(bridge, prefixes)
        if not prefix:
            continue
        trunk_bridge = prefix
        if not trunk_bridge:
            continue
        vlan = vlan_from_bridge_name(bridge, prefix)
        if vlan is None:
            continue
        desired.add(SegmentBridge(
            physnet=physnet,
            bridge=bridge,
            trunk_bridge=trunk_bridge,
            vlan=vlan,
        ))
    return desired


class OvsBridgeMappingsUpdatedEvent(row_event.RowEvent):
    """Trigger reconcile when ovn-bridge-mappings changes."""

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        super().__init__(events, 'Open_vSwitch', None)
        self.event_name = self.__class__.__name__

    @property
    def extension(self):
        return self.ovn_agent[EXT_NAME]

    @staticmethod
    def _mappings_value(row):
        try:
            return row.external_ids.get(constants.OVN_BRIDGE_MAPPINGS, '')
        except (AttributeError, KeyError):
            return ''

    def match_fn(self, event, row, old):
        new_val = self._mappings_value(row)
        old_val = self._mappings_value(old)
        return new_val != old_val

    def run(self, event, row, old):
        LOG.info('Detected %s change; reconciling segment bridges',
                 constants.OVN_BRIDGE_MAPPINGS)
        self.extension.reconcile()


class SegmentBridgeExtension(extension_manager.OVNAgentExtension):
    """OVN agent extension for segment bridge management."""

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._reconcile_loop = None

    @property
    def name(self):
        return 'OVN Segment Bridge Extension'

    def initialize(self, *args):
        LOG.info('Initializing %s extension', EXT_NAME)

    def start(self):
        LOG.info('Starting %s extension', EXT_NAME)
        self.reconcile()
        self._start_periodic_reconcile()

    def _start_periodic_reconcile(self):
        interval = self.agent_api.conf.ovn.segment_bridge_reconcile_interval
        if self._reconcile_loop is not None:
            return

        self._reconcile_loop = loopingcall.FixedIntervalLoopingCall(
            self.reconcile)
        self._reconcile_loop.start(interval=interval, initial_delay=interval)
        LOG.info('Started periodic reconcile for %s: interval=%s',
                 EXT_NAME, interval)

    @property
    def ovs_idl_events(self):
        return [OvsBridgeMappingsUpdatedEvent]

    @property
    def nb_idl_tables(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_tables(self):
        return []

    @property
    def sb_idl_events(self):
        return []

    def _configured_prefixes(self):
        return self.agent_api.conf.ovn.segment_bridge_prefixes

    @staticmethod
    def _read_ovn_bridge_mappings(agent):
        ovs_table = agent.ovs_idl.db_get('Open_vSwitch', '.',
                                         'external_ids').execute()
        return ovs_table.get(constants.OVN_BRIDGE_MAPPINGS, '')

    def _desired_segment_bridges(self):
        mappings_value = self._read_ovn_bridge_mappings(self.agent_api)
        return desired_segment_bridges_from_mappings(
            mappings_value, self._configured_prefixes())

    def _actual_segment_bridges(self):
        actual = set()
        bridge_table = self.agent_api.ovs_idl.idl.tables.get('Bridge')
        if not bridge_table:
            return actual

        for row in bridge_table.rows.values():
            if not self._is_managed_segment_bridge(row):
                continue
            item = self._row_to_segment_bridge(row)
            if item is not None:
                actual.add(item)
        return actual

    @staticmethod
    def _patch_port_names(item):
        """Return unique patch names for trunk and segment bridge."""
        trunk_side = 'patch-%s-to-%s' % (item.trunk_bridge, item.vlan)
        seg_side = 'patch-%s-to-%s' % (item.vlan, item.trunk_bridge)
        return trunk_side, seg_side

    @staticmethod
    def _bridge_exists(bridge_name):
        return ovs_lib.OVSBridge(bridge_name).bridge_exists(bridge_name)

    @staticmethod
    def _is_managed_segment_bridge(row):
        ext_ids = getattr(row, 'external_ids', {}) or {}
        return (
            ext_ids.get(MANAGED_KEY) == MANAGED_VAL and
            ext_ids.get(OWNER_KEY) == OWNER_VAL
        )

    @staticmethod
    def _row_to_segment_bridge(row):
        ext_ids = getattr(row, 'external_ids', {}) or {}
        physnet = ext_ids.get(PHYSNET_KEY, '')
        trunk = ext_ids.get(TRUNK_KEY, '')
        vlan_raw = ext_ids.get(VLAN_KEY)
        if not trunk or not vlan_raw:
            return None
        try:
            vlan = int(vlan_raw)
        except (TypeError, ValueError):
            return None
        return SegmentBridge(
            physnet=physnet,
            bridge=row.name,
            trunk_bridge=trunk,
            vlan=vlan,
        )

    def _ensure_segment_bridge(self, item):
        seg_br = ovs_lib.OVSBridge(item.bridge)
        if not seg_br.bridge_exists(item.bridge):
            LOG.info('Creating segment bridge %s', item.bridge)
            seg_br.add_bridge(item.bridge)
            self.agent_api.ovs_idl.db_set(
                'Bridge', item.bridge,
                ('external_ids', self._managed_external_ids(item)),
            ).execute(check_error=True)

    def _ensure_patch_ports(self, item):
        trunk_br = ovs_lib.OVSBridge(item.trunk_bridge)
        seg_br = ovs_lib.OVSBridge(item.bridge)

        trunk_patch, seg_patch = self._patch_port_names(item)

        trunk_ports = set(trunk_br.get_port_name_list())
        seg_ports = set(seg_br.get_port_name_list())

        if trunk_patch not in trunk_ports:
            LOG.info('Adding trunk patch port %s on %s',
                     trunk_patch, item.trunk_bridge)
            trunk_br.add_port(trunk_patch)
            self.agent_api.ovs_idl.db_set(
                'Interface', trunk_patch,
                ('type', 'patch'),
                ('options', {'peer': seg_patch}),
            ).execute(check_error=True)
        self._set_port_external_ids(trunk_patch, item)

        if seg_patch not in seg_ports:
            LOG.info('Adding segment patch port %s on %s',
                     seg_patch, item.bridge)
            seg_br.add_port(seg_patch)
            self.agent_api.ovs_idl.db_set(
                'Interface', seg_patch,
                ('type', 'patch'),
                ('options', {'peer': trunk_patch}),
            ).execute(check_error=True)
        self._set_port_external_ids(seg_patch, item)

    def _ensure_trunk_patch_vlan(self, item):
        trunk_patch, _seg_patch = self._patch_port_names(item)
        LOG.info('Setting trunk patch %s vlan access tag=%s',
                 trunk_patch, item.vlan)
        self.agent_api.ovs_idl.db_set(
            'Port', trunk_patch,
            ('vlan_mode', 'access'),
            ('tag', item.vlan),
        ).execute(check_error=True)

    def _ensure_item(self, item):
        if not self._bridge_exists(item.trunk_bridge):
            LOG.warning('Trunk bridge %s does not exist; skipping %s',
                        item.trunk_bridge, item.bridge)
            return

        self._ensure_segment_bridge(item)
        self._ensure_patch_ports(item)
        self._ensure_trunk_patch_vlan(item)

    def _managed_external_ids(self, item):
        return {
            MANAGED_KEY: MANAGED_VAL,
            OWNER_KEY: OWNER_VAL,
            PHYSNET_KEY: item.physnet,
            TRUNK_KEY: item.trunk_bridge,
            VLAN_KEY: str(item.vlan),
        }

    def _set_port_external_ids(self, port_name, item):
        self.agent_api.ovs_idl.db_set(
            'Port', port_name,
            ('external_ids', self._managed_external_ids(item)),
        ).execute(check_error=True)

    def _del_port_if_exists(self, bridge_name, port_name):
        br = ovs_lib.OVSBridge(bridge_name)
        ports = set(br.get_port_name_list())
        if port_name in ports:
            LOG.info('Deleting port %s from %s', port_name, bridge_name)
            br.delete_port(port_name)

    def _delete_item(self, item):
        # Delete patch ports first, then segment bridge.
        trunk_patch, seg_patch = self._patch_port_names(item)

        # Never delete trunk bridge. Only trunk patch port on it.
        if self._bridge_exists(item.trunk_bridge):
            self._del_port_if_exists(item.trunk_bridge, trunk_patch)

        if self._bridge_exists(item.bridge):
            self._del_port_if_exists(item.bridge, seg_patch)
            LOG.info('Deleting managed segment bridge %s', item.bridge)
            ovs_lib.OVSBridge(item.bridge).delete_bridge(item.bridge)

    def reconcile(self):
        with self._lock:
            desired = self._desired_segment_bridges()
            actual = self._actual_segment_bridges()

            to_add = desired - actual
            to_del = actual - desired

            LOG.info('Segment bridge reconcile: desired=%d actual=%d '
                     'to_add=%d to_del=%d',
                     len(desired), len(actual), len(to_add), len(to_del))

            for item in sorted(desired):
                try:
                    self._ensure_item(item)
                except Exception:
                    LOG.exception('Failed ensuring segment bridge %s',
                                  item.bridge)

            for item in sorted(to_del):
                try:
                    self._delete_item(item)
                except Exception:
                    LOG.exception('Failed deleting segment bridge %s',
                                  item.bridge)
