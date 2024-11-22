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

from neutron_lib.api.definitions import segment as extension
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.db.models import agent as agent_model
from neutron.db.models import segment as segment_model
from neutron.db import segments_db as db
from neutron import manager
from neutron.objects import base as base_obj
from neutron.objects import network
from neutron.services.segments import exceptions


LOG = logging.getLogger(__name__)
_USER_CONFIGURED_SEGMENT_PLUGIN = None
FOR_NET_DELETE = 'for_net_delete'


def check_user_configured_segment_plugin():
    global _USER_CONFIGURED_SEGMENT_PLUGIN
    # _USER_CONFIGURED_SEGMENT_PLUGIN will contain 3 possible values:
    # 1. None, this just happens during neutron-server startup.
    # 2. True, this means that users configure the 'segments'
    #    service plugin in neutron config file.
    # 3. False, this means that can not find 'segments' service
    #    plugin in neutron config file.
    # This function just load once to store the result
    # into _USER_CONFIGURED_SEGMENT_PLUGIN during neutron-server startup.
    if _USER_CONFIGURED_SEGMENT_PLUGIN is None:
        segment_class = 'neutron.services.segments.plugin.Plugin'
        _USER_CONFIGURED_SEGMENT_PLUGIN = any(
            p in cfg.CONF.service_plugins for p in ['segments', segment_class])
    return _USER_CONFIGURED_SEGMENT_PLUGIN


class SegmentDbMixin:
    """Mixin class to add segment."""

    @staticmethod
    def _make_segment_dict(segment_obj, fields=None):
        res = {'id': segment_obj['id'],
               'network_id': segment_obj['network_id'],
               'name': segment_obj['name'],
               'description': segment_obj['description'],
               db.PHYSICAL_NETWORK: segment_obj[db.PHYSICAL_NETWORK],
               db.NETWORK_TYPE: segment_obj[db.NETWORK_TYPE],
               db.SEGMENTATION_ID: segment_obj[db.SEGMENTATION_ID],
               'hosts': segment_obj['hosts'],
               'segment_index': segment_obj['segment_index']}
        resource_extend.apply_funcs('segments', res, segment_obj.db_obj)
        return db_utils.resource_fields(res, fields)

    def _get_segment(self, context, segment_id):
        segment = network.NetworkSegment.get_object(context, id=segment_id)
        if not segment:
            raise exceptions.SegmentNotFound(segment_id=segment_id)
        return segment

    @log_helpers.log_method_call
    def create_segment(self, context, segment):
        """Create a segment."""
        segment = segment['segment']
        segment_id = segment.get('id') or uuidutils.generate_uuid()
        try:
            new_segment = self._create_segment_db(context, segment_id, segment)
        except db_exc.DBReferenceError:
            raise n_exc.NetworkNotFound(net_id=segment['network_id'])
        registry.publish(resources.SEGMENT, events.AFTER_CREATE, self,
                         payload=events.DBEventPayload(
                             context, resource_id=segment_id,
                             states=(new_segment,)))
        return self._make_segment_dict(new_segment)

    def _create_segment_db(self, context, segment_id, segment):
        with db_api.CONTEXT_WRITER.using(context):
            network_id = segment['network_id']
            physical_network = segment[extension.PHYSICAL_NETWORK]
            if physical_network == constants.ATTR_NOT_SPECIFIED:
                physical_network = None
            network_type = segment[extension.NETWORK_TYPE]
            segmentation_id = segment[extension.SEGMENTATION_ID]
            if segmentation_id == constants.ATTR_NOT_SPECIFIED:
                segmentation_id = None
            name = segment['name']
            if name == constants.ATTR_NOT_SPECIFIED:
                name = None
            description = segment['description']
            if description == constants.ATTR_NOT_SPECIFIED:
                description = None
            args = {'id': segment_id,
                    'network_id': network_id,
                    'name': name,
                    'description': description,
                    db.PHYSICAL_NETWORK: physical_network,
                    db.NETWORK_TYPE: network_type,
                    db.SEGMENTATION_ID: segmentation_id}
            # Calculate the index of segment
            segment_index = 0
            segments = self.get_segments(
                context,
                filters={'network_id': [network_id]},
                fields=['segment_index'],
                sorts=[('segment_index', True)])
            if segments:
                # NOTE(xiaohhui): The new index is the last index + 1, this
                # may cause discontinuous segment_index. But segment_index
                # can functionally work as the order index for segments.
                segment_index = (segments[-1].get('segment_index') + 1)
            args['segment_index'] = segment_index

            new_segment = network.NetworkSegment(context, **args)
            new_segment.create()
            # Do some preliminary operations before committing the segment to
            # db
            registry.publish(
                resources.SEGMENT, events.PRECOMMIT_CREATE, self,
                payload=events.DBEventPayload(context, resource_id=segment_id,
                                              states=(new_segment,)))
            # The new segment might have been updated by the callbacks
            # subscribed to the PRECOMMIT_CREATE event. So update it in the DB
            new_segment.update()
            return new_segment

    @log_helpers.log_method_call
    def update_segment(self, context, uuid, segment):
        """Update an existing segment."""
        segment = segment['segment']
        with db_api.CONTEXT_WRITER.using(context):
            curr_segment = self._get_segment(context, uuid)
            curr_segment.update_fields(segment)
            curr_segment.update()
        return self._make_segment_dict(curr_segment)

    @log_helpers.log_method_call
    def get_segment(self, context, uuid, fields=None):
        segment_db = self._get_segment(context, uuid)
        return self._make_segment_dict(segment_db, fields)

    @log_helpers.log_method_call
    def get_segments(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        segment_objs = network.NetworkSegment.get_objects(
            context, _pager=pager, **filters)
        return [self._make_segment_dict(obj) for obj in segment_objs]

    @log_helpers.log_method_call
    def get_segments_count(self, context, filters=None):
        filters = filters or {}
        return network.NetworkSegment.count(context, **filters)

    @log_helpers.log_method_call
    def get_segments_by_hosts(self, context, hosts):
        if not hosts:
            return []
        segment_host_mapping = network.SegmentHostMapping.get_objects(
            context, host=hosts)
        return list({mapping.segment_id for mapping in segment_host_mapping})

    @log_helpers.log_method_call
    def delete_segment(self, context, uuid, for_net_delete=False):
        """Delete an existing segment."""
        segment_dict = self.get_segment(context, uuid)
        # Do some preliminary operations before deleting the segment
        registry.publish(resources.SEGMENT, events.BEFORE_DELETE,
                         self.delete_segment,
                         payload=events.DBEventPayload(
                             context, metadata={
                                 FOR_NET_DELETE: for_net_delete},
                             states=(segment_dict,),
                             resource_id=uuid))

        # Delete segment in DB
        with db_api.CONTEXT_WRITER.using(context):
            if not network.NetworkSegment.delete_objects(context, id=uuid):
                raise exceptions.SegmentNotFound(segment_id=uuid)
            # Do some preliminary operations before deleting segment in db
            registry.publish(resources.SEGMENT, events.PRECOMMIT_DELETE,
                             self.delete_segment,
                             payload=events.DBEventPayload(
                                 context, metadata={
                                     FOR_NET_DELETE: for_net_delete},
                                 resource_id=uuid,
                                 states=(segment_dict,)))

        registry.publish(resources.SEGMENT, events.AFTER_DELETE,
                         self.delete_segment,
                         payload=events.DBEventPayload(
                             context, metadata={
                                 FOR_NET_DELETE: for_net_delete},
                             states=(segment_dict,),
                             resource_id=uuid))


@db_api.retry_if_session_inactive()
@lockutils.synchronized('update_segment_host_mapping')
def update_segment_host_mapping(context, host, current_segment_ids):
    with db_api.CONTEXT_WRITER.using(context):
        segment_host_mapping = network.SegmentHostMapping.get_objects(
            context, host=host)
        previous_segment_ids = {
            seg_host['segment_id'] for seg_host in segment_host_mapping}
        segment_ids = current_segment_ids - previous_segment_ids
        for segment_id in segment_ids:
            network.SegmentHostMapping(
                context, segment_id=segment_id, host=host).create()
        if segment_ids:
            registry.publish(
                resources.SEGMENT_HOST_MAPPING,
                events.AFTER_CREATE,
                update_segment_host_mapping,
                payload=events.DBEventPayload(
                    context,
                    metadata={
                        'host': host,
                        'current_segment_ids': segment_ids}))

        LOG.debug('Segments %s mapped to the host %s', segment_ids, host)
        stale_segment_ids = previous_segment_ids - current_segment_ids
        if stale_segment_ids:
            for entry in segment_host_mapping:
                if entry.segment_id in stale_segment_ids:
                    entry.delete()
                    LOG.debug('Segment %s unmapped from host %s',
                              entry.segment_id, entry.host)
            registry.publish(
                resources.SEGMENT_HOST_MAPPING,
                events.AFTER_DELETE,
                update_segment_host_mapping,
                payload=events.DBEventPayload(
                    context,
                    metadata={
                        'host': host,
                        'deleted_segment_ids': stale_segment_ids}))


def get_hosts_mapped_with_segments(context, include_agent_types=None,
                                   exclude_agent_types=None):
    """Get hosts that are mapped with segments.

    L2 providers can use this method to get an overview of SegmentHostMapping,
    and then delete the stale SegmentHostMapping.

    When using both include_agent_types and exclude_agent_types,
    exclude_agent_types is most significant.
    All hosts without agent are excluded when using any agent_type filter.

    :param context: current running context information
    :param include_agent_types: (set) List of agent types, include hosts
        with matching agents.
    :param exclude_agent_types: (set) List of agent types, exclude hosts
        with matching agents.
    """
    def add_filter_by_agent_types(qry, include, exclude):
        qry = qry.join(
            agent_model.Agent,
            segment_model.SegmentHostMapping.host == agent_model.Agent.host)
        if include:
            qry = qry.filter(agent_model.Agent.agent_type.in_(include))
        if exclude:
            qry = qry.filter(agent_model.Agent.agent_type.not_in(exclude))

        return qry

    with db_api.CONTEXT_READER.using(context):
        query = context.session.query(segment_model.SegmentHostMapping)
        if include_agent_types or exclude_agent_types:
            query = add_filter_by_agent_types(query, include_agent_types,
                                              exclude_agent_types)

        res = query.all()

    return {row.host for row in res}


def _get_phys_nets(agent):
    configurations_dict = agent.get('configurations', {})
    mappings = configurations_dict.get('bridge_mappings', {})
    mappings.update(configurations_dict.get('interface_mappings', {}))
    mappings.update(configurations_dict.get('device_mappings', {}))
    return list(mappings.keys())


reported_hosts = set()

# NOTE: Module level variable of segments plugin. It should be removed once
# segments becomes a default plugin.
segments_plugin = None


def get_segments_with_phys_nets(context, phys_nets):
    """Get segments from physical networks.

    L2 providers usually have information of hostname and physical networks.
    They could use this method to get related segments and then update
    SegmentHostMapping.
    """
    phys_nets = list(phys_nets)
    if not phys_nets:
        return []

    with db_api.CONTEXT_READER.using(context):
        return network.NetworkSegment.get_objects(
            context, physical_network=phys_nets)


def map_segment_to_hosts(context, segment_id, hosts):
    """Map segment to a collection of hosts."""
    with db_api.CONTEXT_WRITER.using(context):
        for host in hosts:
            network.SegmentHostMapping(
                context, segment_id=segment_id, host=host).create()
    LOG.debug('Segment %s mapped to the hosts %s', segment_id, hosts)


def _update_segment_host_mapping_for_agent(resource, event, trigger,
                                           payload=None):
    plugin = payload.metadata.get('plugin')
    agent = payload.desired_state
    host = payload.metadata.get('host')
    context = payload.context

    check_segment_for_agent = getattr(plugin, 'check_segment_for_agent', None)
    if (not check_user_configured_segment_plugin() or
            not check_segment_for_agent):
        return
    phys_nets = _get_phys_nets(agent)
    if not phys_nets:
        return
    start_flag = agent.get('start_flag', None)
    if host in reported_hosts and not start_flag:
        return
    reported_hosts.add(host)
    if (len(payload.states) > 1 and
            payload.states[1] is not None and
            agent.get('configurations') == payload.states[1].get(
                'configurations')):
        return
    segments = get_segments_with_phys_nets(context, phys_nets)
    current_segment_ids = {
        segment['id'] for segment in segments
        if check_segment_for_agent(segment, agent)}
    update_segment_host_mapping(context, host, current_segment_ids)


def _add_segment_host_mapping_for_segment(resource, event, trigger,
                                          payload=None):
    context = payload.context
    segment = payload.latest_state
    if not segment.physical_network:
        return
    cp = directory.get_plugin()
    check_segment_for_agent = getattr(cp, 'check_segment_for_agent', None)
    if not check_user_configured_segment_plugin() or not hasattr(
            cp, 'get_agents') or not check_segment_for_agent:
        # not an agent-supporting plugin
        registry.unsubscribe(_add_segment_host_mapping_for_segment,
                             resources.SEGMENT, events.PRECOMMIT_CREATE)
        return
    hosts = {agent['host'] for agent in cp.get_agents(context)
             if check_segment_for_agent(segment, agent)}
    map_segment_to_hosts(context, segment.id, hosts)


def _delete_segments_for_network(resource, event, trigger,
                                 payload=None, **kwargs):
    network_id = payload.resource_id
    admin_ctx = payload.context.elevated()
    global segments_plugin
    if not segments_plugin:
        segments_plugin = manager.NeutronManager.load_class_for_provider(
            'neutron.service_plugins', 'segments')()
    segments = segments_plugin.get_segments(
        admin_ctx, filters={'network_id': [network_id]})
    for segment in segments:
        segments_plugin.delete_segment(admin_ctx, segment['id'],
                                       for_net_delete=True)


def subscribe():
    registry.subscribe(_update_segment_host_mapping_for_agent,
                       resources.AGENT,
                       events.AFTER_CREATE)
    registry.subscribe(_update_segment_host_mapping_for_agent,
                       resources.AGENT,
                       events.AFTER_UPDATE)
    registry.subscribe(_add_segment_host_mapping_for_segment,
                       resources.SEGMENT, events.PRECOMMIT_CREATE)
    registry.subscribe(_delete_segments_for_network,
                       resources.NETWORK,
                       events.PRECOMMIT_DELETE)


subscribe()
