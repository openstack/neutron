# Copyright (c) 2013 OpenStack Foundation
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

import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2


class NetworkSegment(model_base.BASEV2, models_v2.HasId):
    """Represent persistent state of a network segment.

    A network segment is a portion of a neutron network with a
    specific physical realization. A neutron network can consist of
    one or more segments.
    """

    __tablename__ = 'ml2_network_segments'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)
