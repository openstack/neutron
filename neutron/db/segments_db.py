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

from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from neutron._i18n import _LI
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import _deprecate
from neutron.db.models import segment as segments_model

_deprecate._moved_global('NetworkSegment', new_module=segments_model)

LOG = logging.getLogger(__name__)

NETWORK_TYPE = segments_model.NetworkSegment.network_type.name
PHYSICAL_NETWORK = segments_model.NetworkSegment.physical_network.name
SEGMENTATION_ID = segments_model.NetworkSegment.segmentation_id.name


def _make_segment_dict(record):
    """Make a segment dictionary out of a DB record."""
    return {'id': record.id,
            NETWORK_TYPE: record.network_type,
            PHYSICAL_NETWORK: record.physical_network,
            SEGMENTATION_ID: record.segmentation_id}


def add_network_segment(context, network_id, segment, segment_index=0,
                        is_dynamic=False):
    with context.session.begin(subtransactions=True):
        record = segments_model.NetworkSegment(
            id=uuidutils.generate_uuid(),
            network_id=network_id,
            network_type=segment.get(NETWORK_TYPE),
            physical_network=segment.get(PHYSICAL_NETWORK),
            segmentation_id=segment.get(SEGMENTATION_ID),
            segment_index=segment_index,
            is_dynamic=is_dynamic
        )
        context.session.add(record)
        registry.notify(resources.SEGMENT,
                        events.PRECOMMIT_CREATE,
                        trigger=add_network_segment,
                        context=context,
                        segment=record)
        segment['id'] = record.id
    LOG.info(_LI("Added segment %(id)s of type %(network_type)s for network "
                 "%(network_id)s"),
             {'id': record.id,
              'network_type': record.network_type,
              'network_id': record.network_id})


def get_network_segments(context, network_id, filter_dynamic=False):
    return get_networks_segments(
        context, [network_id], filter_dynamic)[network_id]


def get_networks_segments(context, network_ids, filter_dynamic=False):
    if not network_ids:
        return {}

    with context.session.begin(subtransactions=True):
        query = (context.session.query(segments_model.NetworkSegment).
                 filter(segments_model.NetworkSegment.network_id
                        .in_(network_ids)).
                 order_by(segments_model.NetworkSegment.segment_index))
        if filter_dynamic is not None:
            query = query.filter_by(is_dynamic=filter_dynamic)
        records = query.all()
        result = {net_id: [] for net_id in network_ids}
        for record in records:
            result[record.network_id].append(_make_segment_dict(record))
        return result


def get_segment_by_id(context, segment_id):
    with context.session.begin(subtransactions=True):
        try:
            record = (context.session.query(segments_model.NetworkSegment).
                      filter_by(id=segment_id).
                      one())
            return _make_segment_dict(record)
        except exc.NoResultFound:
            return


def get_dynamic_segment(context, network_id, physical_network=None,
                        segmentation_id=None):
    """Return a dynamic segment for the filters provided if one exists."""
    with context.session.begin(subtransactions=True):
        query = (context.session.query(segments_model.NetworkSegment).
                 filter_by(network_id=network_id, is_dynamic=True))
        if physical_network:
            query = query.filter_by(physical_network=physical_network)
        if segmentation_id:
            query = query.filter_by(segmentation_id=segmentation_id)
        record = query.first()

    if record:
        return _make_segment_dict(record)
    else:
        LOG.debug("No dynamic segment found for "
                  "Network:%(network_id)s, "
                  "Physical network:%(physnet)s, "
                  "segmentation_id:%(segmentation_id)s",
                  {'network_id': network_id,
                   'physnet': physical_network,
                   'segmentation_id': segmentation_id})
        return None


def delete_network_segment(context, segment_id):
    """Release a dynamic segment for the params provided if one exists."""
    with context.session.begin(subtransactions=True):
        (context.session.query(segments_model.NetworkSegment).
         filter_by(id=segment_id).delete())


_deprecate._MovedGlobals()
