# Copyright (c) 2013 OpenStack Foundation
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
import sys

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.objects import network as net_obj
from neutron.objects import network_segment_range as range_obj
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2.drivers import helpers


LOG = log.getLogger(__name__)

driver_type.register_ml2_drivers_vlan_opts()


class VlanTypeDriver(helpers.SegmentTypeDriver):
    """Manage state for VLAN networks with ML2.

    The VlanTypeDriver implements the 'vlan' network_type. VLAN
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1Q conformant
    physical_network segmented into virtual networks via IEEE 802.1Q
    headers. Up to 4094 VLAN network segments can exist on each
    available physical_network.
    """

    def __init__(self):
        super().__init__()
        self._parse_network_vlan_ranges()

    def _populate_new_default_network_segment_ranges(self, ctx, start_time):
        for (physical_network, vlan_ranges) in (
                self._network_vlan_ranges.items()):
            for vlan_min, vlan_max in vlan_ranges:
                range_obj.NetworkSegmentRange.new_default(
                    ctx, self.get_type(), physical_network, vlan_min,
                    vlan_max, start_time)

    def _parse_network_vlan_ranges(self):
        try:
            self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        except Exception:
            LOG.exception("Failed to parse network_vlan_ranges. "
                          "Service terminated!")
            sys.exit(1)
        LOG.info("Network VLAN ranges: %s", self._network_vlan_ranges)

    @db_api.retry_db_errors
    def _get_network_segment_ranges_from_db(self, ctx=None):
        ranges = {}
        ctx = ctx or context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            range_objs = (range_obj.NetworkSegmentRange.get_objects(
                ctx, network_type=self.get_type()))
            for obj in range_objs:
                physical_network = obj['physical_network']
                if physical_network not in ranges:
                    ranges[physical_network] = []
                ranges[physical_network].append((obj['minimum'],
                                                 obj['maximum']))
        return ranges

    def get_type(self):
        return p_const.TYPE_VLAN

    def initialize(self):
        LOG.info("VlanTypeDriver initialization complete")

    @staticmethod
    def _network_segment_ranges(ctx, default=None):
        """VLAN ranges per physical network, as stored in the DB

        With ``default`` set to True only the registers populated from
        ``[ml2_type_vlan] network_vlan_ranges`` are returned, with False only
        those created through the API, and with None every one of them.
        """
        filters = {'network_type': p_const.TYPE_VLAN}
        if default is not None:
            filters['default'] = default
        ranges = collections.defaultdict(list)
        for obj in range_obj.NetworkSegmentRange.get_objects(ctx, **filters):
            ranges[obj['physical_network']].append(
                (obj['minimum'], obj['maximum']))
        return ranges

    @staticmethod
    def _covered_by(vlan_id, vlan_ranges):
        return any(vlan_min <= vlan_id <= vlan_max
                   for vlan_min, vlan_max in vlan_ranges)

    def _validate_config_ranges_cover_allocations(self, ctx,
                                                  previous_default_ranges):
        """Refuse to start when a config file edit orphaned an allocation

        ``network_vlan_ranges`` has been narrowed, or a physical network
        dropped from it, while segments still hold VLAN IDs that the new
        ranges no longer cover. Restoring the previous ranges in the
        configuration file lets Neutron start again, so failing here is
        recoverable and points at the change that caused it.

        Only VLAN IDs on network segments whose physical networks were
        covered by ``default`` registers are considered. Ranges created
        through the API are not part of that set: refusing to start over
        segments in API-managed ranges would leave an administrator unable
        to reach the API that would undo the change.
        """
        if not previous_default_ranges:
            return

        effective_ranges = self._network_segment_ranges(ctx)
        orphaned = collections.defaultdict(set)
        segments = net_obj.NetworkSegment.get_objects(
            ctx, network_type=self.get_type(),
            physical_network=list(previous_default_ranges))
        for segment in segments:
            physical_network = segment.physical_network
            vlan_id = segment.segmentation_id
            if vlan_id is None:
                continue
            if self._covered_by(vlan_id,
                                effective_ranges[physical_network]):
                continue
            if not self._covered_by(
                    vlan_id,
                    previous_default_ranges[physical_network]):
                continue
            orphaned[physical_network].add(vlan_id)

        if orphaned:
            raise ml2_exc.VlanAllocationOutsideConfiguredRanges(
                allocations='; '.join(
                    '{}: {}'.format(
                        physical_network,
                        ', '.join(str(v) for v in sorted(vlan_ids)))
                    for physical_network, vlan_ids in sorted(
                        orphaned.items())))

    @db_api.retry_db_errors
    def initialize_network_segment_range_support(self, start_time):
        admin_context = context.get_admin_context()
        try:
            with db_api.CONTEXT_WRITER.using(admin_context):
                # Read before the expired registers go away: they are the
                # only record of what the configuration file asked for the
                # last time Neutron started.
                previous_default_ranges = self._network_segment_ranges(
                    admin_context, default=True)
                self._delete_expired_default_network_segment_ranges(
                    admin_context, start_time)
                self._populate_new_default_network_segment_ranges(
                    admin_context, start_time)
                # Raising inside the transaction rolls the two calls above
                # back, so the previous default registers survive and the
                # next start reaches the same verdict instead of quietly
                # accepting the new ranges.
                self._validate_config_ranges_cover_allocations(
                    admin_context, previous_default_ranges)
        except o_exc.NeutronDbObjectDuplicateEntry:
            pass

        self._network_vlan_ranges = (
            self._get_network_segment_ranges_from_db(ctx=admin_context))

    def update_network_segment_range_allocations(self):
        pass

    def get_network_segment_ranges(self):
        """Get the driver network segment ranges.

        Queries all VLAN network segment ranges from DB if the
        ``NETWORK_SEGMENT_RANGE`` service plugin is enabled. Otherwise,
        they will be loaded from the host config file - `ml2_conf.ini`.
        """
        ranges = self._network_vlan_ranges
        if directory.get_plugin(plugin_constants.NETWORK_SEGMENT_RANGE):
            ranges = self._get_network_segment_ranges_from_db()

        return ranges

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        ranges = self.get_network_segment_ranges()
        if physical_network:
            if physical_network not in ranges:
                msg = (_("physical_network '%s' unknown "
                         "for VLAN provider network") % physical_network)
                raise exc.InvalidInput(error_message=msg)
            if segmentation_id is not None:
                if not plugin_utils.is_valid_vlan_tag(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': p_const.MIN_VLAN_TAG,
                            'max': p_const.MAX_VLAN_TAG})
                    raise exc.InvalidInput(error_message=msg)
        elif segmentation_id is not None:
            msg = _("segmentation_id requires physical_network for VLAN "
                    "provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = _("%s prohibited for VLAN provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment, filters=None):
        filters = filters or {}
        project_id = filters.get('project_id')
        physical_network = segment.get(api.PHYSICAL_NETWORK)

        if self.is_partial_segment(segment):
            if not (directory.get_plugin(
                    plugin_constants.NETWORK_SEGMENT_RANGE) and project_id):
                project_id = None

            if physical_network is not None:
                ranges = self.get_network_segment_ranges()
                pn_ranges = ranges.get(physical_network, [])
                seg_id = self.allocate_partially_specified_segment(
                    context, physical_network, pn_ranges,
                    project_id=project_id)
                if seg_id is None:
                    raise exc.NoNetworkAvailable()
            else:
                seg_id = None
                physical_network = None
                for pn, pn_ranges in self.get_network_segment_ranges(
                ).items():
                    seg_id = self.allocate_partially_specified_segment(
                        context, pn, pn_ranges,
                        project_id=project_id)
                    if seg_id is not None:
                        physical_network = pn
                        break
                if seg_id is None:
                    raise exc.NoNetworkAvailable()
        else:
            seg_id = segment.get(api.SEGMENTATION_ID)
            self._ensure_segmentation_id_available(
                context, physical_network, seg_id,
                exclude_segment_id=filters.get('segment_id'))

        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: physical_network,
                api.SEGMENTATION_ID: seg_id,
                api.MTU: self.get_mtu(physical_network)}

    def allocate_tenant_segment(self, context, filters=None):
        filters = filters or {}
        project_id = filters.get('project_id')
        if not (directory.get_plugin(
                plugin_constants.NETWORK_SEGMENT_RANGE) and project_id):
            project_id = None
        ranges = self.get_network_segment_ranges()
        for physnet, pn_ranges in ranges.items():
            seg_id = self.allocate_partially_specified_segment(
                context, physnet, pn_ranges, project_id=project_id)
            if seg_id is not None:
                return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                        api.PHYSICAL_NETWORK: physnet,
                        api.SEGMENTATION_ID: seg_id,
                        api.MTU: self.get_mtu(physnet)}

    def release_segment(self, context, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        vlan_id = segment[api.SEGMENTATION_ID]
        LOG.debug("Releasing vlan %(vlan_id)s on physical network "
                  "%(physical_network)s",
                  {'vlan_id': vlan_id,
                   'physical_network': physical_network})

    def get_mtu(self, physical_network):
        seg_mtu = super().get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0
