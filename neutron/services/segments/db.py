# Copyright 2016 Hewlett Packard Enterprise Development, LP
#
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

from neutron_lib import constants
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron._i18n import _LI
from neutron.api.v2 import attributes
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import segments_db as db
from neutron.extensions import segment as extension
from neutron.services.segments import exceptions


LOG = logging.getLogger(__name__)


class SegmentHostMapping(model_base.BASEV2):

    segment_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networksegments.id',
                                         ondelete="CASCADE"),
                           primary_key=True,
                           index=True,
                           nullable=False)
    host = sa.Column(sa.String(255),
                     primary_key=True,
                     index=True,
                     nullable=False)

    # Add a relationship to the NetworkSegment model in order to instruct
    # SQLAlchemy to eagerly load this association
    network_segment = orm.relationship(
        db.NetworkSegment, backref=orm.backref("segment_host_mapping",
                                               lazy='joined',
                                               cascade='delete'))


def _extend_subnet_dict_binding(plugin, subnet_res, subnet_db):
    subnet_res['segment_id'] = subnet_db.get('segment_id')


# Register dict extend functions for subnets
common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
    attributes.SUBNETS, [_extend_subnet_dict_binding])


class SegmentDbMixin(common_db_mixin.CommonDbMixin):
    """Mixin class to add segment."""

    def _make_segment_dict(self, segment_db, fields=None):
        res = {'id': segment_db['id'],
               'network_id': segment_db['network_id'],
               db.PHYSICAL_NETWORK: segment_db[db.PHYSICAL_NETWORK],
               db.NETWORK_TYPE: segment_db[db.NETWORK_TYPE],
               db.SEGMENTATION_ID: segment_db[db.SEGMENTATION_ID]}
        return self._fields(res, fields)

    def _get_segment(self, context, segment_id):
        try:
            return self._get_by_id(
                context, db.NetworkSegment, segment_id)
        except exc.NoResultFound:
            raise exceptions.SegmentNotFound(segment_id=segment_id)

    @log_helpers.log_method_call
    def create_segment(self, context, segment):
        """Create a segment."""
        segment = segment['segment']
        segment_id = segment.get('id') or uuidutils.generate_uuid()
        with context.session.begin(subtransactions=True):
            network_id = segment['network_id']
            physical_network = segment[extension.PHYSICAL_NETWORK]
            if physical_network == constants.ATTR_NOT_SPECIFIED:
                physical_network = None
            network_type = segment[extension.NETWORK_TYPE]
            segmentation_id = segment[extension.SEGMENTATION_ID]
            if segmentation_id == constants.ATTR_NOT_SPECIFIED:
                segmentation_id = None
            args = {'id': segment_id,
                    'network_id': network_id,
                    db.PHYSICAL_NETWORK: physical_network,
                    db.NETWORK_TYPE: network_type,
                    db.SEGMENTATION_ID: segmentation_id}
            new_segment = db.NetworkSegment(**args)
            context.session.add(new_segment)

        return self._make_segment_dict(new_segment)

    @log_helpers.log_method_call
    def update_segment(self, context, uuid, segment):
        """Update an existing segment."""
        segment = segment['segment']
        with context.session.begin(subtransactions=True):
            curr_segment = self._get_segment(context, uuid)
            curr_segment.update(segment)
        return self._make_segment_dict(curr_segment)

    @log_helpers.log_method_call
    def get_segment(self, context, uuid, fields=None):
        segment_db = self._get_segment(context, uuid)
        return self._make_segment_dict(segment_db, fields)

    @log_helpers.log_method_call
    def get_segments(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'segment', limit, marker)
        make_segment_dict = functools.partial(self._make_segment_dict)
        return self._get_collection(context,
                                    db.NetworkSegment,
                                    make_segment_dict,
                                    filters=filters,
                                    fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log_helpers.log_method_call
    def get_segments_count(self, context, filters=None):
        return self._get_collection_count(context,
                                          db.NetworkSegment,
                                          filters=filters)

    @log_helpers.log_method_call
    def delete_segment(self, context, uuid):
        """Delete an existing segment."""
        with context.session.begin(subtransactions=True):
            query = self._model_query(context, db.NetworkSegment)
            query = query.filter(db.NetworkSegment.id == uuid)
            if 0 == query.delete():
                raise exceptions.SegmentNotFound(segment_id=uuid)


def update_segment_host_mapping(context, host, current_segment_ids):
    with context.session.begin(subtransactions=True):
        segments_host_query = context.session.query(
            SegmentHostMapping).filter_by(host=host)
        previous_segment_ids = {
            seg_host['segment_id'] for seg_host in segments_host_query}
        for segment_id in current_segment_ids - previous_segment_ids:
            context.session.add(SegmentHostMapping(segment_id=segment_id,
                                                   host=host))
        stale_segment_ids = previous_segment_ids - current_segment_ids
        if stale_segment_ids:
            context.session.query(SegmentHostMapping).filter(
                SegmentHostMapping.segment_id.in_(
                    stale_segment_ids)).delete(synchronize_session=False)


def _get_phys_nets(agent):
    configurations_dict = agent.get('configurations', {})
    mappings = configurations_dict.get('bridge_mappings', {})
    mappings.update(configurations_dict.get('interface_mappings', {}))
    mappings.update(configurations_dict.get('device_mappings', {}))
    return mappings.keys()


reported_hosts = set()


def update_segment_host_mapping_for_agent(context, host, plugin, agent):
    check_segment_for_agent = getattr(plugin, 'check_segment_for_agent', None)
    if not check_segment_for_agent:
        LOG.info(_LI("Core plug-in does not implement "
                     "'check_segment_for_agent'. It is not possible to "
                     "build a hosts segments mapping"))
        return
    phys_nets = _get_phys_nets(agent)
    if not phys_nets:
        return
    start_flag = agent.get('start_flag', None)
    if host in reported_hosts and not start_flag:
        return
    reported_hosts.add(host)
    with context.session.begin(subtransactions=True):
        segments = context.session.query(db.NetworkSegment).filter(
            db.NetworkSegment.physical_network.in_(phys_nets))
        current_segment_ids = {
            segment['id'] for segment in segments
            if check_segment_for_agent(segment, agent)}
        update_segment_host_mapping(context, host, current_segment_ids)
