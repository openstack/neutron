# Copyright (c) 2015 OpenStack Foundation.  All rights reserved.
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
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.api.v2 import attributes as attr
from neutron.db import model_base


class ResourceDelta(model_base.BASEV2):
    resource = sa.Column(sa.String(255), primary_key=True)
    reservation_id = sa.Column(sa.String(36),
                               sa.ForeignKey('reservations.id',
                                             ondelete='CASCADE'),
                               primary_key=True,
                               nullable=False)
    # Requested amount of resource
    amount = sa.Column(sa.Integer)


class Reservation(model_base.BASEV2, model_base.HasId):
    tenant_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN))
    expiration = sa.Column(sa.DateTime())
    resource_deltas = orm.relationship(ResourceDelta,
                                       backref='reservation',
                                       lazy="joined",
                                       cascade='all, delete-orphan')


class Quota(model_base.BASEV2, model_base.HasId, model_base.HasTenant):
    """Represent a single quota override for a tenant.

    If there is no row for a given tenant id and resource, then the
    default for the deployment is used.
    """
    resource = sa.Column(sa.String(255))
    limit = sa.Column(sa.Integer)


class QuotaUsage(model_base.BASEV2):
    """Represents the current usage for a given resource."""

    resource = sa.Column(sa.String(255), nullable=False,
                         primary_key=True, index=True)
    tenant_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN), nullable=False,
                          primary_key=True, index=True)
    dirty = sa.Column(sa.Boolean, nullable=False, server_default=sql.false())

    in_use = sa.Column(sa.Integer, nullable=False,
                       server_default="0")
    reserved = sa.Column(sa.Integer, nullable=False,
                         server_default="0")
