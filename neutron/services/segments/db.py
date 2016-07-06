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
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import segments_db as db
from neutron.extensions import segment as extension
from neutron import manager
from neutron.services.segments import exceptions


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


class SegmentDbMixin(common_db_mixin.CommonDbMixin):
    """Mixin class to add segment."""

    def _make_segment_dict(self, segment_db, fields=None):
        res = {'id': segment_db['id'],
               'network_id': segment_db['network_id'],
               db.PHYSICAL_NETWORK: segment_db[db.PHYSICAL_NETWORK],
               db.NETWORK_TYPE: segment_db[db.NETWORK_TYPE],
               db.SEGMENTATION_ID: segment_db[db.SEGMENTATION_ID],
               'hosts': [mapping.host for mapping in
                         segment_db.segment_host_mapping]}
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
            registry.notify(resources.SEGMENT, events.PRECOMMIT_CREATE, self,
                            context=context, segment=new_segment)

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
            segments_host_query.filter(
                SegmentHostMapping.segment_id.in_(
                    stale_segment_ids)).delete(synchronize_session=False)


def _get_phys_nets(agent):
    configurations_dict = agent.get('configurations', {})
    mappings = configurations_dict.get('bridge_mappings', {})
    mappings.update(configurations_dict.get('interface_mappings', {}))
    mappings.update(configurations_dict.get('device_mappings', {}))
    return mappings.keys()


reported_hosts = set()


def get_segments_with_phys_nets(context, phys_nets):
    """Get segments from physical networks.

    L2 providers usually have information of hostname and physical networks.
    They could use this method to get related segments and then update
    SegmentHostMapping.
    """
    if not phys_nets:
        return []

    with context.session.begin(subtransactions=True):
        segments = context.session.query(db.NetworkSegment).filter(
            db.NetworkSegment.physical_network.in_(phys_nets))
        return segments


def _update_segment_host_mapping_for_agent(resource, event, trigger,
                                           context, host, plugin, agent):
    check_segment_for_agent = getattr(plugin, 'check_segment_for_agent', None)
    if not check_segment_for_agent:
        return
    phys_nets = _get_phys_nets(agent)
    if not phys_nets:
        return
    start_flag = agent.get('start_flag', None)
    if host in reported_hosts and not start_flag:
        return
    reported_hosts.add(host)
    segments = get_segments_with_phys_nets(context, phys_nets)
    current_segment_ids = {
        segment['id'] for segment in segments
        if check_segment_for_agent(segment, agent)}
    update_segment_host_mapping(context, host, current_segment_ids)


def _add_segment_host_mapping_for_segment(resource, event, trigger,
                                          context, segment):
    if not segment.physical_network:
        return
    cp = manager.NeutronManager.get_plugin()
    check_segment_for_agent = getattr(cp, 'check_segment_for_agent', None)
    if not hasattr(cp, 'get_agents') or not check_segment_for_agent:
        # not an agent-supporting plugin
        registry.unsubscribe(_add_segment_host_mapping_for_segment,
                             resources.SEGMENT, events.PRECOMMIT_CREATE)
        return
    hosts = {agent['host'] for agent in cp.get_agents(context)
             if check_segment_for_agent(segment, agent)}
    for host in hosts:
        context.session.add(SegmentHostMapping(segment_id=segment.id,
                                               host=host))


def subscribe():
    registry.subscribe(_update_segment_host_mapping_for_agent,
                       resources.AGENT,
                       events.AFTER_CREATE)
    registry.subscribe(_update_segment_host_mapping_for_agent,
                       resources.AGENT,
                       events.AFTER_UPDATE)
    registry.subscribe(_add_segment_host_mapping_for_segment,
                       resources.SEGMENT, events.PRECOMMIT_CREATE)

subscribe()
