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

from neutron_lib.db import model_base
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron._i18n import _LI
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import standard_attr

LOG = logging.getLogger(__name__)


"""
Some standalone plugins need a DB table to store provider
network information. Initially there was no such table,
but in Mitaka the ML2 NetworkSegment table was promoted here.
"""


class NetworkSegment(standard_attr.HasStandardAttributes,
                     model_base.BASEV2, model_base.HasId):
    """Represent persistent state of a network segment.

    A network segment is a portion of a neutron network with a
    specific physical realization. A neutron network can consist of
    one or more segments.
    """

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)
    is_dynamic = sa.Column(sa.Boolean, default=False, nullable=False,
                           server_default=sa.sql.false())
    segment_index = sa.Column(sa.Integer, nullable=False, server_default='0')
    name = sa.Column(sa.String(attributes.NAME_MAX_LEN),
                     nullable=True)


NETWORK_TYPE = NetworkSegment.network_type.name
PHYSICAL_NETWORK = NetworkSegment.physical_network.name
SEGMENTATION_ID = NetworkSegment.segmentation_id.name


def _make_segment_dict(record):
    """Make a segment dictionary out of a DB record."""
    return {'id': record.id,
            NETWORK_TYPE: record.network_type,
            PHYSICAL_NETWORK: record.physical_network,
            SEGMENTATION_ID: record.segmentation_id}


def add_network_segment(context, network_id, segment, segment_index=0,
                        is_dynamic=False):
    with context.session.begin(subtransactions=True):
        record = NetworkSegment(
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


def get_network_segments(session, network_id, filter_dynamic=False):
    return get_networks_segments(
        session, [network_id], filter_dynamic)[network_id]


def get_networks_segments(session, network_ids, filter_dynamic=False):
    if not network_ids:
        return {}

    with session.begin(subtransactions=True):
        query = (session.query(NetworkSegment).
                 filter(NetworkSegment.network_id.in_(network_ids)).
                 order_by(NetworkSegment.segment_index))
        if filter_dynamic is not None:
            query = query.filter_by(is_dynamic=filter_dynamic)
        records = query.all()
        result = {net_id: [] for net_id in network_ids}
        for record in records:
            result[record.network_id].append(_make_segment_dict(record))
        return result


def get_segment_by_id(session, segment_id):
    with session.begin(subtransactions=True):
        try:
            record = (session.query(NetworkSegment).
                      filter_by(id=segment_id).
                      one())
            return _make_segment_dict(record)
        except exc.NoResultFound:
            return


def get_dynamic_segment(session, network_id, physical_network=None,
                        segmentation_id=None):
        """Return a dynamic segment for the filters provided if one exists."""
        with session.begin(subtransactions=True):
            query = (session.query(NetworkSegment).
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


def delete_network_segment(session, segment_id):
    """Release a dynamic segment for the params provided if one exists."""
    with session.begin(subtransactions=True):
        (session.query(NetworkSegment).
         filter_by(id=segment_id).delete())
