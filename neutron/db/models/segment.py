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


from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import segments_db as db


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
