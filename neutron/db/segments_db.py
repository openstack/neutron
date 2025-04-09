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

from neutron_lib.api.definitions import segment as segment_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.plugins.ml2 import api as ml2_api
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.objects import base as base_obj
from neutron.objects import network as network_obj
from neutron.services.segments import exceptions as segments_exceptions

LOG = logging.getLogger(__name__)

NETWORK_TYPE = segment_def.NETWORK_TYPE
PHYSICAL_NETWORK = segment_def.PHYSICAL_NETWORK
SEGMENTATION_ID = segment_def.SEGMENTATION_ID
NETWORK_ID = 'network_id'


def _make_segment_dict(obj):
    """Make a segment dictionary out of an object."""
    return {'id': obj.id,
            NETWORK_TYPE: obj.network_type,
            PHYSICAL_NETWORK: obj.physical_network,
            SEGMENTATION_ID: obj.segmentation_id,
            NETWORK_ID: obj.network_id}


def add_network_segment(context, network_id, segment, segment_index=0,
                        is_dynamic=False):
    with db_api.CONTEXT_WRITER.using(context):
        netseg_obj = network_obj.NetworkSegment(
            context, id=uuidutils.generate_uuid(), network_id=network_id,
            network_type=segment.get(NETWORK_TYPE),
            physical_network=segment.get(PHYSICAL_NETWORK),
            segmentation_id=segment.get(SEGMENTATION_ID),
            segment_index=segment_index, is_dynamic=is_dynamic)
        netseg_obj.create()
        registry.publish(resources.SEGMENT,
                         events.PRECOMMIT_CREATE,
                         add_network_segment,
                         payload=events.DBEventPayload(
                             context, resource_id=netseg_obj.id,
                             states=(netseg_obj,)))
        segment['id'] = netseg_obj.id
    LOG.info("Added segment %(id)s of type %(network_type)s for network "
             "%(network_id)s",
             {'id': netseg_obj.id,
              'network_type': netseg_obj.network_type,
              'network_id': netseg_obj.network_id})


def update_network_segment(context, segment_id, segmentation_id):
    with db_api.CONTEXT_WRITER.using(context):
        netseg_obj = network_obj.NetworkSegment.get_object(context,
                                                           id=segment_id)
        if not netseg_obj:
            raise segments_exceptions.SegmentNotFound(segment_id=segment_id)
        netseg_obj[ml2_api.SEGMENTATION_ID] = segmentation_id
        netseg_obj.update()

    LOG.info("Updated segment %(id)s, segmentation_id: %(segmentation_id)s)",
             {'id': segment_id, 'segmentation_id': segmentation_id})


def get_network_segments(context, network_id, filter_dynamic=False):
    return get_networks_segments(
        context, [network_id], filter_dynamic)[network_id]


def get_networks_segments(context, network_ids, filter_dynamic=False):
    if not network_ids:
        return {}

    with db_api.CONTEXT_READER.using(context):
        filters = {
            'network_id': network_ids,
        }
        if filter_dynamic is not None:
            filters['is_dynamic'] = filter_dynamic
        objs = network_obj.NetworkSegment.get_objects(context, **filters)
        result = {net_id: [] for net_id in network_ids}
        for record in objs:
            result[record.network_id].append(_make_segment_dict(record))
        return result


def get_segment_by_id(context, segment_id):
    with db_api.CONTEXT_READER.using(context):
        net_obj = network_obj.NetworkSegment.get_object(context, id=segment_id)
        if net_obj:
            return _make_segment_dict(net_obj)


def get_dynamic_segment(context, network_id, physical_network=None,
                        segmentation_id=None):
    """Return a dynamic segment for the filters provided if one exists."""
    # Network segments have physical_network=None in tunnelled networks, unlike
    # network segment ranges, that have an empty string in order to force the
    # database constraint.
    physical_network = physical_network or None
    with db_api.CONTEXT_READER.using(context):
        filters = {
            'network_id': network_id,
            'is_dynamic': True,
        }
        if physical_network:
            filters['physical_network'] = physical_network
        if segmentation_id:
            filters['segmentation_id'] = segmentation_id
        pager = base_obj.Pager(limit=1)
        objs = network_obj.NetworkSegment.get_objects(
            context, _pager=pager, **filters)

        if objs:
            return _make_segment_dict(objs[0])
        LOG.debug("No dynamic segment found for "
                  "Network:%(network_id)s, "
                  "Physical network:%(physnet)s, "
                  "segmentation_id:%(segmentation_id)s",
                  {'network_id': network_id,
                   'physnet': physical_network,
                   'segmentation_id': segmentation_id})


def delete_network_segment(context, segment_id):
    """Release a dynamic segment for the params provided if one exists."""
    with db_api.CONTEXT_WRITER.using(context):
        network_obj.NetworkSegment.delete_objects(context, id=segment_id)


def network_segments_exist_in_range(context, network_type, physical_network,
                                    segment_range=None):
    """Check whether one or more network segments exist in a range."""
    # Network segments have physical_network=None in tunnelled networks, unlike
    # network segment ranges, that have an empty string in order to force the
    # database constraint.
    physical_network = physical_network or None
    with db_api.CONTEXT_READER.using(context):
        filters = {
            'network_type': network_type,
            'physical_network': physical_network,
        }
        segment_objs = network_obj.NetworkSegment.get_objects(
            context, **filters)
        if segment_range:
            minimum_id = segment_range['minimum']
            maximum_id = segment_range['maximum']
            segment_objs = [
                segment for segment in segment_objs if
                minimum_id <= segment.segmentation_id <= maximum_id]
        return len(segment_objs) > 0


def min_max_actual_segments_in_range(context, network_type, physical_network,
                                     segment_range=None):
    """Return the minimum and maximum segmentation IDs used in a network
    segment range
    """
    # Network segments have physical_network=None in tunnelled networks, unlike
    # network segment ranges, that have an empty string in order to force the
    # database constraint.
    physical_network = physical_network or None
    with db_api.CONTEXT_READER.using(context):
        filters = {
            'network_type': network_type,
            'physical_network': physical_network,
        }
        pager = base_obj.Pager()
        # (NOTE) True means ASC, False is DESC
        pager.sorts = [('segmentation_id', True)]
        segment_objs = network_obj.NetworkSegment.get_objects(
            context, _pager=pager, **filters)

        if segment_range:
            minimum_id = segment_range['minimum']
            maximum_id = segment_range['maximum']
            segment_objs = [
                segment for segment in segment_objs if
                minimum_id <= segment.segmentation_id <= maximum_id]

        if segment_objs:
            return (segment_objs[0].segmentation_id,
                    segment_objs[-1].segmentation_id)
        LOG.debug(
            "No existing segment found for Network type:%(network_type)s, "
            "Physical network:%(physical_network)s",
            {'network_type': network_type,
             'physical_network': physical_network})
        return None, None
