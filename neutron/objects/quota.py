# Copyright (c) 2016 Intel Corporation.  All rights reserved.
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

from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa
from sqlalchemy import sql
from sqlalchemy import types as sqltypes

from neutron.db.quota import models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class ResourceDelta(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.ResourceDelta

    primary_keys = ['resource', 'reservation_id']

    foreign_keys = {'Reservation': {'reservation_id': 'id'}}

    fields = {
        'resource': obj_fields.StringField(),
        'reservation_id': common_types.UUIDField(),
        'amount': obj_fields.IntegerField(nullable=True),
    }


@base.NeutronObjectRegistry.register
class Reservation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.Reservation

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'expiration': obj_fields.DateTimeField(tzinfo_aware=False,
                                               nullable=True),
        'resource_deltas': obj_fields.ListOfObjectsField(
            ResourceDelta.__name__, nullable=True),
    }

    synthetic_fields = ['resource_deltas']

    def create(self):
        deltas = self.resource_deltas
        with self.db_context_writer(self.obj_context):
            super().create()
            if deltas:
                for delta in deltas:
                    delta.reservation_id = self.id
                    delta.create()
                    self.resource_deltas.append(delta)
                self.obj_reset_changes(['resource_deltas'])

    @classmethod
    def delete_expired(cls, context, expiring_time, project_id):
        resv_query = context.session.query(models.Reservation)
        if project_id:
            project_expr = (models.Reservation.project_id == project_id)
        else:
            project_expr = sql.true()
        # TODO(manjeets) Fetch and delete objects using
        # object/db/api.py once comparison operations are
        # supported
        resv_query = resv_query.filter(sa.and_(
            project_expr, models.Reservation.expiration < expiring_time))
        return resv_query.delete()

    @classmethod
    def get_total_reservations_map(cls, context, now, project_id,
                                   resources, expired):
        if not resources:
            return
        resv_query = context.session.query(
            models.ResourceDelta.resource,
            models.Reservation.expiration,
            sql.func.cast(
                sql.func.sum(models.ResourceDelta.amount),
                sqltypes.Integer)).join(models.Reservation)
        if expired:
            exp_expr = (models.Reservation.expiration < now)
        else:
            exp_expr = (models.Reservation.expiration >= now)
        resv_query = resv_query.filter(sa.and_(
            models.Reservation.project_id == project_id,
            models.ResourceDelta.resource.in_(resources),
            exp_expr)).group_by(
                models.ResourceDelta.resource,
                models.Reservation.expiration)
        return {resource: total_reserved
                for (resource, exp, total_reserved) in resv_query}


@base.NeutronObjectRegistry.register
class Quota(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.Quota

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'resource': obj_fields.StringField(nullable=True),
        'limit': obj_fields.IntegerField(nullable=True),
    }


@base.NeutronObjectRegistry.register
class QuotaUsage(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.QuotaUsage

    primary_keys = ['resource', 'project_id']

    fields = {
        'resource': obj_fields.StringField(),
        'project_id': obj_fields.StringField(),
        'dirty': obj_fields.BooleanField(default=False),
        'in_use': obj_fields.IntegerField(default=0),
        'reserved': obj_fields.IntegerField(default=0),
    }

    @classmethod
    def get_object_dirty_protected(cls, context, **kwargs):
        query = context.session.query(cls.db_model)
        query = query.filter_by(**cls.modify_fields_to_db(kwargs))
        # NOTE(manjeets) as lock mode was just for protecting dirty bits
        # an update on dirty will prevent the race.
        query.filter_by(dirty=True).update({'dirty': True})
        res = query.first()
        if res:
            return cls._load_object(context, res)
