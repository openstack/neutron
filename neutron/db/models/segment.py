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

from neutron_lib.api.definitions import segment
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import models_v2


# Some standalone plugins need a DB table to store provider
# network information. Initially there was no such table,
# but in Mitaka the ML2 NetworkSegment table was promoted here.
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
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE),
                     nullable=True)
    network = orm.relationship(models_v2.Network,
                               backref=orm.backref("segments",
                                                   lazy='subquery',
                                                   cascade='delete'))
    api_collections = [segment.COLLECTION_NAME]

    __table_args__ = (
        sa.UniqueConstraint(
            network_id,
            network_type,
            physical_network,
            segment_index,
            name='uniq_networksegment0network_id0'
                 'network_type0physnet0sidx'),
        model_base.BASEV2.__table_args__
    )


class SegmentHostMapping(model_base.BASEV2):

    segment_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networksegments.id',
                                         ondelete="CASCADE"),
                           primary_key=True,
                           nullable=False)
    host = sa.Column(sa.String(255),
                     primary_key=True,
                     nullable=False)

    # Add a relationship to the NetworkSegment model in order to instruct
    # SQLAlchemy to eagerly load this association
    network_segment = orm.relationship(
        NetworkSegment, load_on_pending=True,
        backref=orm.backref("segment_host_mapping",
                            lazy='subquery',
                            cascade='delete'))
    revises_on_change = ('network_segment', )
