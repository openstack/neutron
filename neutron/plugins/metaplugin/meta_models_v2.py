# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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
from sqlalchemy import Column, String

from neutron.db import models_v2


class NetworkFlavor(models_v2.model_base.BASEV2):
    """Represents a binding of network_id to flavor."""
    flavor = Column(String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id',
                                                        ondelete="CASCADE"),
                           primary_key=True)

    def __repr__(self):
        return "<NetworkFlavor(%s,%s)>" % (self.flavor, self.network_id)


class RouterFlavor(models_v2.model_base.BASEV2):
    """Represents a binding of router_id to flavor."""
    flavor = Column(String(255))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id',
                                                       ondelete="CASCADE"),
                          primary_key=True)

    def __repr__(self):
        return "<RouterFlavor(%s,%s)>" % (self.flavor, self.router_id)
