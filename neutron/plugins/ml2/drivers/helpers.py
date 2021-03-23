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

import functools

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as p_utils
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log

from neutron.objects import network_segment_range as ns_range


LOG = log.getLogger(__name__)


class BaseTypeDriver(api.ML2TypeDriver):
    """BaseTypeDriver for functions common to Segment and flat."""

    def __init__(self):
        try:
            self.physnet_mtus = helpers.parse_mappings(
                cfg.CONF.ml2.physical_network_mtus, unique_values=False
            )
        except Exception as e:
            LOG.error("Failed to parse physical_network_mtus: %s", e)
            self.physnet_mtus = []

    def get_mtu(self, physical_network=None):
        return p_utils.get_deployment_physnet_mtu()


class SegmentTypeDriver(BaseTypeDriver):
    """SegmentTypeDriver for segment allocation.

    Provide methods helping to perform segment allocation fully or partially
    specified.
    """

    def __init__(self, model):
        super(SegmentTypeDriver, self).__init__()
        self.model = model.db_model
        self.segmentation_obj = model
        primary_keys_columns = self.model.__table__.primary_key.columns
        self.primary_keys = {col.name for col in primary_keys_columns}

    def allocate_fully_specified_segment(self, context, **raw_segment):
        """Allocate segment fully specified by raw_segment.

        If segment exists, then try to allocate it and return db object
        If segment does not exists, then try to create it and return db object
        If allocation/creation failed, then return None
        """

        network_type = self.get_type()
        try:
            with db_api.CONTEXT_WRITER.using(context):
                alloc = (
                    context.session.query(self.model).filter_by(**raw_segment).
                    first())
                if alloc:
                    if alloc.allocated:
                        # Segment already allocated
                        return
                    else:
                        # Segment not allocated
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "started ",
                                  {"type": network_type,
                                   "segment": raw_segment})
                        count = (context.session.query(self.model).
                                 filter_by(allocated=False, **raw_segment).
                                 update({"allocated": True}))
                        if count:
                            LOG.debug("%(type)s segment %(segment)s allocate "
                                      "done ",
                                      {"type": network_type,
                                       "segment": raw_segment})
                            return alloc

                        # Segment allocated or deleted since select
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "failed: segment has been allocated or "
                                  "deleted",
                                  {"type": network_type,
                                   "segment": raw_segment})

                # Segment to create or already allocated
                LOG.debug("%(type)s segment %(segment)s create started",
                          {"type": network_type, "segment": raw_segment})
                alloc = self.model(allocated=True, **raw_segment)
                alloc.save(context.session)
                LOG.debug("%(type)s segment %(segment)s create done",
                          {"type": network_type, "segment": raw_segment})

        except db_exc.DBDuplicateEntry:
            # Segment already allocated (insert failure)
            alloc = None
            LOG.debug("%(type)s segment %(segment)s create failed",
                      {"type": network_type, "segment": raw_segment})

        return alloc

    def allocate_partially_specified_segment(self, context, **filters):
        """Allocate model segment from pool partially specified by filters.

        Return allocated db object or None.
        """
        network_type = self.get_type()
        if directory.get_plugin(plugin_constants.NETWORK_SEGMENT_RANGE):
            calls = [
                functools.partial(
                    ns_range.NetworkSegmentRange.get_segments_for_project,
                    context, self.model, network_type,
                    self.model_segmentation_id, **filters),
                functools.partial(
                    ns_range.NetworkSegmentRange.get_segments_shared,
                    context, self.model, network_type,
                    self.model_segmentation_id, **filters)]
        else:
            calls = [functools.partial(
                self.segmentation_obj.get_random_unallocated_segment,
                context, **filters)]

        try_to_allocate = False
        for call in calls:
            allocations = call()
            if not isinstance(allocations, list):
                allocations = [allocations] if allocations else []
            for alloc in allocations:
                segment = dict((k, alloc[k]) for k in self.primary_keys)
                try_to_allocate = True
                if self.segmentation_obj.allocate(context, **segment):
                    LOG.debug('%(type)s segment allocate from pool success '
                              'with %(segment)s ', {'type': network_type,
                                                    'segment': segment})
                    return alloc

        if try_to_allocate:
            raise db_exc.RetryRequest(
                exceptions.NoNetworkFoundInMaximumAllowedAttempts())

    @db_api.retry_db_errors
    def _delete_expired_default_network_segment_ranges(self):
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            filters = {'default': True, 'network_type': self.get_type()}
            ns_range.NetworkSegmentRange.delete_objects(ctx, **filters)
