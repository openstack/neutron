# Copyright 2014 Embrane, Inc.
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

import sqlalchemy as sql

from neutron.db import model_base


class PoolPort(model_base.BASEV2):
    """Represents the connection between pools and ports."""
    __tablename__ = 'embrane_pool_port'

    pool_id = sql.Column(sql.String(36), sql.ForeignKey('pools.id'),
                         primary_key=True)
    port_id = sql.Column(sql.String(36), sql.ForeignKey('ports.id'),
                         nullable=False)
