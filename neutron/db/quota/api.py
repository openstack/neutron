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

import collections
import datetime

import sqlalchemy as sa
from sqlalchemy.orm import exc as orm_exc
from sqlalchemy import sql

from neutron.db import _utils as db_utils
from neutron.db import api as db_api
from neutron.db.quota import models as quota_models


# Wrapper for utcnow - needed for mocking it in unit tests
def utcnow():
    return datetime.datetime.utcnow()


class QuotaUsageInfo(collections.namedtuple(
    'QuotaUsageInfo', ['resource', 'tenant_id', 'used', 'dirty'])):
    """Information about resource quota usage."""


class ReservationInfo(collections.namedtuple(
    'ReservationInfo', ['reservation_id', 'tenant_id',
                        'expiration', 'deltas'])):
    """Information about a resource reservation."""


@db_api.retry_if_session_inactive()
def get_quota_usage_by_resource_and_tenant(context, resource, tenant_id,
                                           lock_for_update=False):
    """Return usage info for a given resource and tenant.

    :param context: Request context
    :param resource: Name of the resource
    :param tenant_id: Tenant identifier
    :param lock_for_update: if True sets a write-intent lock on the query
    :returns: a QuotaUsageInfo instance
    """

    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource, tenant_id=tenant_id)

    if lock_for_update:
        query = query.with_lockmode('update')

    result = query.first()
    if not result:
        return
    return QuotaUsageInfo(result.resource,
                          result.tenant_id,
                          result.in_use,
                          result.dirty)


@db_api.retry_if_session_inactive()
def get_quota_usage_by_resource(context, resource):
    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource)
    return [QuotaUsageInfo(item.resource,
                           item.tenant_id,
                           item.in_use,
                           item.dirty) for item in query]


@db_api.retry_if_session_inactive()
def get_quota_usage_by_tenant_id(context, tenant_id):
    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(tenant_id=tenant_id)
    return [QuotaUsageInfo(item.resource,
                           item.tenant_id,
                           item.in_use,
                           item.dirty) for item in query]


@db_api.retry_if_session_inactive()
def set_quota_usage(context, resource, tenant_id,
                    in_use=None, delta=False):
    """Set resource quota usage.

    :param context: instance of neutron context with db session
    :param resource: name of the resource for which usage is being set
    :param tenant_id: identifier of the tenant for which quota usage is
                      being set
    :param in_use: integer specifying the new quantity of used resources,
                   or a delta to apply to current used resource
    :param delta: Specifies whether in_use is an absolute number
                  or a delta (default to False)
    """
    with db_api.autonested_transaction(context.session):
        query = db_utils.model_query(context, quota_models.QuotaUsage)
        query = query.filter_by(resource=resource).filter_by(
            tenant_id=tenant_id)
        usage_data = query.first()
        if not usage_data:
            # Must create entry
            usage_data = quota_models.QuotaUsage(
                resource=resource,
                tenant_id=tenant_id)
            context.session.add(usage_data)
        # Perform explicit comparison with None as 0 is a valid value
        if in_use is not None:
            if delta:
                in_use = usage_data.in_use + in_use
            usage_data.in_use = in_use
        # After an explicit update the dirty bit should always be reset
        usage_data.dirty = False
    return QuotaUsageInfo(usage_data.resource,
                          usage_data.tenant_id,
                          usage_data.in_use,
                          usage_data.dirty)


@db_api.retry_if_session_inactive()
@db_api.context_manager.writer
def set_quota_usage_dirty(context, resource, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given resource and tenant.

    :param resource: a resource for which quota usage if tracked
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: 1 if the quota usage data were updated, 0 otherwise.
    """
    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource).filter_by(tenant_id=tenant_id)
    return query.update({'dirty': dirty})


@db_api.retry_if_session_inactive()
@db_api.context_manager.writer
def set_resources_quota_usage_dirty(context, resources, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given tenant and multiple resources.

    :param resources: list of resource for which the dirty bit is going
                      to be set
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: the number of records for which the bit was actually set.
    """
    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(tenant_id=tenant_id)
    if resources:
        query = query.filter(quota_models.QuotaUsage.resource.in_(resources))
    # synchronize_session=False needed because of the IN condition
    return query.update({'dirty': dirty}, synchronize_session=False)


@db_api.retry_if_session_inactive()
@db_api.context_manager.writer
def set_all_quota_usage_dirty(context, resource, dirty=True):
    """Set the dirty bit on quota usage for all tenants.

    :param resource: the resource for which the dirty bit should be set
    :returns: the number of tenants for which the dirty bit was
              actually updated
    """
    query = db_utils.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource)
    return query.update({'dirty': dirty})


@db_api.retry_if_session_inactive()
def create_reservation(context, tenant_id, deltas, expiration=None):
    # This method is usually called from within another transaction.
    # Consider using begin_nested
    with context.session.begin(subtransactions=True):
        expiration = expiration or (utcnow() + datetime.timedelta(0, 120))
        resv = quota_models.Reservation(tenant_id=tenant_id,
                                        expiration=expiration)
        context.session.add(resv)
        for (resource, delta) in deltas.items():
            context.session.add(
                quota_models.ResourceDelta(resource=resource,
                                           amount=delta,
                                           reservation=resv))
    return ReservationInfo(resv['id'],
                           resv['tenant_id'],
                           resv['expiration'],
                           dict((delta.resource, delta.amount)
                                for delta in resv.resource_deltas))


@db_api.retry_if_session_inactive()
def get_reservation(context, reservation_id):
    query = context.session.query(quota_models.Reservation).filter_by(
        id=reservation_id)
    resv = query.first()
    if not resv:
        return
    return ReservationInfo(resv['id'],
                           resv['tenant_id'],
                           resv['expiration'],
                           dict((delta.resource, delta.amount)
                                for delta in resv.resource_deltas))


@db_api.retry_if_session_inactive()
@db_api.context_manager.writer
def remove_reservation(context, reservation_id, set_dirty=False):
    delete_query = context.session.query(quota_models.Reservation).filter_by(
        id=reservation_id)
    # Not handling MultipleResultsFound as the query is filtering by primary
    # key
    try:
        reservation = delete_query.one()
    except orm_exc.NoResultFound:
        # TODO(salv-orlando): Raise here and then handle the exception?
        return
    tenant_id = reservation.tenant_id
    resources = [delta.resource for delta in reservation.resource_deltas]
    num_deleted = delete_query.delete()
    if set_dirty:
        # quota_usage for all resource involved in this reservation must
        # be marked as dirty
        set_resources_quota_usage_dirty(context, resources, tenant_id)
    return num_deleted


@db_api.retry_if_session_inactive()
def get_reservations_for_resources(context, tenant_id, resources,
                                   expired=False):
    """Retrieve total amount of reservations for specified resources.

    :param context: Neutron context with db session
    :param tenant_id: Tenant identifier
    :param resources: Resources for which reserved amounts should be fetched
    :param expired: False to fetch active reservations, True to fetch expired
                    reservations (defaults to False)
    :returns: a dictionary mapping resources with corresponding deltas
    """
    if not resources:
        # Do not waste time
        return
    now = utcnow()
    resv_query = context.session.query(
        quota_models.ResourceDelta.resource,
        quota_models.Reservation.expiration,
        sql.func.sum(quota_models.ResourceDelta.amount)).join(
        quota_models.Reservation)
    if expired:
        exp_expr = (quota_models.Reservation.expiration < now)
    else:
        exp_expr = (quota_models.Reservation.expiration >= now)
    resv_query = resv_query.filter(sa.and_(
        quota_models.Reservation.tenant_id == tenant_id,
        quota_models.ResourceDelta.resource.in_(resources),
        exp_expr)).group_by(
        quota_models.ResourceDelta.resource,
        quota_models.Reservation.expiration)
    return dict((resource, total_reserved)
            for (resource, exp, total_reserved) in resv_query)


@db_api.retry_if_session_inactive()
@db_api.context_manager.writer
def remove_expired_reservations(context, tenant_id=None):
    now = utcnow()
    resv_query = context.session.query(quota_models.Reservation)
    if tenant_id:
        tenant_expr = (quota_models.Reservation.tenant_id == tenant_id)
    else:
        tenant_expr = sql.true()
    resv_query = resv_query.filter(sa.and_(
        tenant_expr, quota_models.Reservation.expiration < now))
    return resv_query.delete()
