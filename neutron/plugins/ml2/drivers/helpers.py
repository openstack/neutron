# Copyright (c) 2014 Thales Services SAS
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

import itertools
import secrets

from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as p_utils
from oslo_config import cfg
from oslo_log import log
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy import sql

from neutron.db.models import segment as seg_model
from neutron.objects import network_segment_range as ns_range


LOG = log.getLogger(__name__)


class BaseTypeDriver(api.ML2TypeDriver):
    """BaseTypeDriver for functions common to Segment and flat."""

    def __init__(self):
        self.physnet_mtus = cfg.CONF.ml2.physical_network_mtus

    def get_mtu(self, physical_network=None):
        return p_utils.get_deployment_physnet_mtu()


# TODO(ralonsoh): Drop the legacy ML2 allocation tables
# (``ml2_vlan_allocations``, ``ml2_vxlan_allocations``,
# ``ml2_gre_allocations``, ``ml2_geneve_allocations``) in the 2028.1
# contract migration.  Neutron no longer reads or writes them once
# segment availability is derived from ``networksegments`` (LP#2168770).
class SegmentTypeDriver(BaseTypeDriver):
    """SegmentTypeDriver for segment allocation.

    Derives segment availability from ``networksegments``.  No
    separate allocation table is needed: the UNIQUE constraint on
    ``(network_type, physical_network, segmentation_id)`` prevents
    duplicate allocations at the DB level.
    """

    def _get_used_segmentation_ids(self, context, physical_network,
                                   exclude_segment_id=None):
        """Return the set of segmentation IDs already in use.

        This method must be called inside a reader context.
        """
        physnet_col = seg_model.NetworkSegment.physical_network
        if physical_network in (None, ''):
            physnet_filter = or_(physnet_col.is_(None), physnet_col == '')
        else:
            physnet_filter = physnet_col == physical_network
        query = context.session.query(
            seg_model.NetworkSegment.segmentation_id).filter(
            seg_model.NetworkSegment.network_type == self.get_type(),
            physnet_filter,
            seg_model.NetworkSegment.segmentation_id.isnot(None))
        if exclude_segment_id:
            query = query.filter(
                seg_model.NetworkSegment.id != exclude_segment_id)
        return {row[0] for row in query}

    def _ensure_segmentation_id_available(self, context, physical_network,
                                          segmentation_id,
                                          exclude_segment_id=None):
        """Raise if another network segment already uses this ID."""
        if segmentation_id is None:
            return
        physnet = physical_network if physical_network is not None else ''
        if segmentation_id not in self._get_used_segmentation_ids(
                context, physnet, exclude_segment_id=exclude_segment_id):
            return
        network_type = self.get_type()
        if network_type == constants.TYPE_VLAN:
            raise exc.VlanIdInUse(vlan_id=segmentation_id,
                                  physical_network=physnet)
        raise exc.TunnelIdInUse(tunnel_id=segmentation_id)

    def _pick_random_from_ranges(self, ranges, used_ids):
        """Pick a random available ID from the given ranges.

        Attempts a weighted random pick that avoids materialising the
        full set for typical fill ratios.  Falls back to full-set
        computation when random probing fails.
        """
        max_attempts = 100
        intervals = list(ranges)
        total = sum(hi - lo + 1 for lo, hi in intervals)
        if total <= 0:
            return None

        rng = secrets.SystemRandom()
        for _attempt in range(max_attempts):
            r = rng.randint(0, total - 1)
            for lo, hi in intervals:
                size = hi - lo + 1
                if r < size:
                    seg_id = lo + r
                    if seg_id not in used_ids:
                        return seg_id
                    break
                r -= size

        valid = set()
        for lo, hi in intervals:
            valid |= set(range(lo, hi + 1))
        available = valid - used_ids
        if available:
            return rng.choice(list(available))
        return None

    @db_api.CONTEXT_READER
    def allocate_partially_specified_segment(self, context,
                                             physical_network, ranges,
                                             project_id=None):
        """Pick a random available segmentation ID.

        When the ``network_segment_range`` service plugin is active,
        project ownership and shared ranges are respected.

        Returns a segmentation ID (int) or ``None``.
        """
        nsr_plugin = directory.get_plugin(
            plugin_constants.NETWORK_SEGMENT_RANGE)

        used = self._get_used_segmentation_ids(context, physical_network)

        if nsr_plugin:
            seg_id = self._allocate_from_nsr(
                context, physical_network, used, project_id)
        else:
            seg_id = self._pick_random_from_ranges(ranges, used)

        if seg_id is not None:
            LOG.debug('%(type)s segment %(seg_id)s allocated from pool',
                      {'type': self.get_type(), 'seg_id': seg_id})
        return seg_id

    def _allocate_from_nsr(self, context, physical_network, used_ids,
                           project_id):
        """Allocate using network segment range objects."""
        network_type = self.get_type()
        if project_id:
            ranges = self._nsr_ranges_for_project(
                context, network_type, physical_network, project_id)
            seg_id = self._pick_random_from_ranges(ranges, used_ids)
            if seg_id is not None:
                return seg_id

        ranges = self._nsr_ranges_shared(
            context, network_type, physical_network, project_id)
        return self._pick_random_from_ranges(ranges, used_ids)

    @staticmethod
    def _nsr_ranges_for_project(context, network_type, physical_network,
                                project_id):
        """Return ranges owned by a specific project."""
        objs = ns_range.NetworkSegmentRange.get_objects(
            context,
            network_type=network_type,
            physical_network=physical_network,
            project_id=project_id)
        return [(obj.minimum, obj.maximum) for obj in objs]

    @staticmethod
    def _nsr_ranges_shared(context, network_type, physical_network,
                           project_id):
        """Return shared ranges minus other projects' exclusive ranges.

        This method must be called inside a reader context.
        """
        nsr_model = ns_range.NetworkSegmentRange.db_model
        shared_objs = context.session.query(nsr_model).filter(
            and_(nsr_model.network_type == network_type,
                 nsr_model.shared == sql.expression.true()))
        if network_type == constants.TYPE_VLAN:
            shared_objs = shared_objs.filter(
                nsr_model.physical_network == physical_network)

        segment_ids = set()
        for obj in shared_objs.all():
            segment_ids.update(range(obj.minimum, obj.maximum + 1))
        if not segment_ids:
            return []

        other_objs = context.session.query(nsr_model).filter(
            and_(nsr_model.project_id != project_id,
                 nsr_model.project_id.isnot(None),
                 nsr_model.network_type == network_type))
        if network_type == constants.TYPE_VLAN:
            other_objs = other_objs.filter(
                nsr_model.physical_network == physical_network)
        for obj in other_objs.all():
            segment_ids -= set(range(obj.minimum, obj.maximum + 1))

        if not segment_ids:
            return []

        # NOTE(ralonsoh): https://stackoverflow.com/questions/4628333/
        # converting-a-list-of-integers-into-range-in-python
        segment_ranges = [
            [t[0][1], t[-1][1]] for t in
            (tuple(g[1]) for g in itertools.groupby(
                enumerate(segment_ids),
                key=lambda enum_seg: enum_seg[1] - enum_seg[0]))]

        return segment_ranges

    def _delete_expired_default_network_segment_ranges(self, ctx, start_time):
        (ns_range.NetworkSegmentRange.
        delete_expired_default_network_segment_ranges(
            ctx, self.get_type(), start_time))
