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

import abc
import collections
import datetime

from neutron_lib.db import api as db_api
from oslo_db import exception as db_exc

from neutron.common import utils
from neutron.objects import quota as quota_obj


RESERVATION_EXPIRATION_TIMEOUT = 120  # seconds
UNLIMITED_QUOTA = -1


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
def get_quota_usage_by_resource_and_tenant(context, resource, tenant_id):
    """Return usage info for a given resource and tenant.

    :param context: Request context
    :param resource: Name of the resource
    :param tenant_id: Tenant identifier
    :returns: a QuotaUsageInfo instance
    """

    result = quota_obj.QuotaUsage.get_object_dirty_protected(
        context, resource=resource, project_id=tenant_id)
    if not result:
        return
    return QuotaUsageInfo(result.resource, result.project_id, result.in_use,
                          result.dirty)


@db_api.retry_if_session_inactive()
def get_quota_usage_by_resource(context, resource):
    objs = quota_obj.QuotaUsage.get_objects(context, resource=resource)
    return [QuotaUsageInfo(item.resource,
                           item.project_id,
                           item.in_use,
                           item.dirty) for item in objs]


@db_api.retry_if_session_inactive()
def get_quota_usage_by_tenant_id(context, tenant_id):
    objs = quota_obj.QuotaUsage.get_objects(context, project_id=tenant_id)
    return [QuotaUsageInfo(item.resource,
                           tenant_id,
                           item.in_use,
                           item.dirty) for item in objs]


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
    with db_api.CONTEXT_WRITER.using(context):
        usage_data = quota_obj.QuotaUsage.get_object(
            context, resource=resource, project_id=tenant_id)
        if not usage_data:
            # Must create entry
            usage_data = quota_obj.QuotaUsage(
                context, resource=resource, project_id=tenant_id)
            usage_data.create()
        # Perform explicit comparison with None as 0 is a valid value
        if in_use is not None:
            if delta:
                in_use = usage_data.in_use + in_use
            usage_data.in_use = in_use
        # After an explicit update the dirty bit should always be reset
        usage_data.dirty = False
        usage_data.update()
    return QuotaUsageInfo(usage_data.resource, usage_data.project_id,
                          usage_data.in_use, usage_data.dirty)


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_WRITER
def set_quota_usage_dirty(context, resource, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given resource and tenant.

    :param resource: a resource for which quota usage if tracked
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: 1 if the quota usage data were updated, 0 otherwise.
    """
    obj = quota_obj.QuotaUsage.get_object(
        context, resource=resource, project_id=tenant_id)
    if obj:
        obj.dirty = dirty
        obj.update()
        return 1
    return 0


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_WRITER
def set_resources_quota_usage_dirty(context, resources, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given tenant and multiple resources.

    :param resources: list of resource for which the dirty bit is going
                      to be set
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: the number of records for which the bit was actually set.
    """
    filters = {'project_id': tenant_id}
    if resources:
        filters['resource'] = resources
    objs = quota_obj.QuotaUsage.get_objects(context, **filters)
    for obj in objs:
        obj.dirty = dirty
        obj.update()
    return len(objs)


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_WRITER
def set_all_quota_usage_dirty(context, resource, dirty=True):
    """Set the dirty bit on quota usage for all tenants.

    :param resource: the resource for which the dirty bit should be set
    :returns: the number of tenants for which the dirty bit was
              actually updated
    """
    # TODO(manjeets) consider squashing this method with
    # set_resources_quota_usage_dirty
    objs = quota_obj.QuotaUsage.get_objects(context, resource=resource)
    for obj in objs:
        obj.dirty = dirty
        obj.update()
    return len(objs)


@db_api.retry_if_session_inactive()
def create_reservation(context, tenant_id, deltas, expiration=None):
    # This method is usually called from within another transaction.
    # Consider using begin_nested
    expiration = expiration or (
            utcnow() + datetime.timedelta(0, RESERVATION_EXPIRATION_TIMEOUT))
    delta_objs = []
    for (resource, delta) in deltas.items():
        delta_objs.append(quota_obj.ResourceDelta(
            context, resource=resource, amount=delta))
    reserv_obj = quota_obj.Reservation(
        context, project_id=tenant_id, expiration=expiration,
        resource_deltas=delta_objs)
    reserv_obj.create()
    return ReservationInfo(reserv_obj['id'],
                           reserv_obj['project_id'],
                           reserv_obj['expiration'],
                           dict((delta.resource, delta.amount)
                                for delta in reserv_obj.resource_deltas))


@db_api.retry_if_session_inactive()
def get_reservation(context, reservation_id):
    reserv_obj = quota_obj.Reservation.get_object(context, id=reservation_id)
    if not reserv_obj:
        return
    return ReservationInfo(reserv_obj['id'],
                           reserv_obj['project_id'],
                           reserv_obj['expiration'],
                           dict((delta.resource, delta.amount)
                                for delta in reserv_obj.resource_deltas))


@utils.transaction_guard
@utils.skip_exceptions(db_exc.DBError)
@db_api.CONTEXT_WRITER
def remove_reservation(context, reservation_id, set_dirty=False):
    reservation = quota_obj.Reservation.get_object(context, id=reservation_id)
    if not reservation:
        # TODO(salv-orlando): Raise here and then handle the exception?
        return
    tenant_id = reservation.project_id
    resources = [delta.resource for delta in reservation.resource_deltas]
    reservation.delete()
    if set_dirty:
        # quota_usage for all resource involved in this reservation must
        # be marked as dirty
        set_resources_quota_usage_dirty(context, resources, tenant_id)
    return 1


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_READER
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
    # NOTE(manjeets) we are using utcnow() here because it
    # can be mocked easily where as datetime is built in type
    # mock.path does not allow mocking built in types.
    return quota_obj.Reservation.get_total_reservations_map(
        context, utcnow(), tenant_id, resources, expired)


@db_api.CONTEXT_WRITER
def remove_expired_reservations(context, tenant_id=None, timeout=None):
    expiring_time = utcnow()
    if timeout:
        expiring_time -= datetime.timedelta(seconds=timeout)
    return quota_obj.Reservation.delete_expired(context, expiring_time,
                                                tenant_id)


class QuotaDriverAPI(object, metaclass=abc.ABCMeta):

    @staticmethod
    @abc.abstractmethod
    def get_default_quotas(context, resources, project_id):
        """Given a list of resources, retrieve the default quotas set for
        a tenant.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return default quotas for.
        :return: dict from resource name to dict of name and limit
        """

    @staticmethod
    @abc.abstractmethod
    def get_tenant_quotas(context, resources, project_id):
        """Retrieve the quotas for the given list of resources and project

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return quotas for.
        :return: dict from resource name to dict of name and limit
        """

    @staticmethod
    @abc.abstractmethod
    def get_detailed_tenant_quotas(context, resources, project_id):
        """Retrieve detailed quotas for the given list of resources and project

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return quotas for.
        :return dict: mapping resource name in dict to its corresponding limit
                      used and reserved. Reserved currently returns default
                      value of 0
        """

    @staticmethod
    @abc.abstractmethod
    def delete_tenant_quota(context, project_id):
        """Delete the quota entries for a given project_id.

        After deletion, this tenant will use default quota values in conf.
        Raise a "not found" error if the quota for the given tenant was
        never defined.

        :param context: The request context, for access checks.
        :param project_id: The ID of the project to return quotas for.
        """

    @staticmethod
    @abc.abstractmethod
    def get_all_quotas(context, resources):
        """Given a list of resources, retrieve the quotas for the all tenants.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return: quotas list of dict of project_id:, resourcekey1:
                 resourcekey2: ...
        """

    @staticmethod
    @abc.abstractmethod
    def update_quota_limit(context, project_id, resource, limit):
        """Update the quota limit for a resource in a project

        :param context: The request context, for access checks.
        :param project_id: The ID of the project to update the quota.
        :param resource: the resource to update the quota.
        :param limit: new resource quota limit.
        """

    @staticmethod
    @abc.abstractmethod
    def make_reservation(context, project_id, resources, deltas, plugin):
        """Make multiple resource reservations for a given project

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to make the reservations for.
        :return: ``ReservationInfo`` object.
        """

    @staticmethod
    @abc.abstractmethod
    def commit_reservation(context, reservation_id):
        """Commit a reservation register

        :param context: The request context, for access checks.
        :param reservation_id: ID of the reservation register to commit.
        """

    @staticmethod
    @abc.abstractmethod
    def cancel_reservation(context, reservation_id):
        """Cancel a reservation register

        :param context: The request context, for access checks.
        :param reservation_id: ID of the reservation register to cancel.
        """

    @staticmethod
    @abc.abstractmethod
    def limit_check(context, project_id, resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param project_id: The ID of the project to make the reservations for.
        :param resources: A dictionary of the registered resource.
        :param values: A dictionary of the values to check against the
                       quota.
        """

    @staticmethod
    @abc.abstractmethod
    def get_resource_usage(context, project_id, resources, resource_name):
        """Return the resource current usage

        :param context: The request context, for access checks.
        :param project_id: The ID of the project to make the reservations for.
        :param resources: A dictionary of the registered resources.
        :param resource_name: The name of the resource to retrieve the usage.
        :return: The current resource usage.
        """

    @staticmethod
    @abc.abstractmethod
    def quota_limit_check(context, project_id, resources, deltas):
        """Check the current resource usage against a set of deltas.

        This method will check if the provided resource deltas could be
        assigned depending on the current resource usage and the quota limits.
        If the resource deltas plus the resource usage fit under the quota
        limit, the method will pass. If not, a ``OverQuota`` will be raised.

        :param context: The request context, for access checks.
        :param project_id: The ID of the project to make the reservations for.
        :param resources: A dictionary of the registered resource.
        :param deltas: A dictionary of the values to check against the
                       quota limits.
        :return: None if passed; ``OverQuota`` if quota limits are exceeded,
                 ``InvalidQuotaValue`` if delta values are invalid.
        """


class NullQuotaDriver(QuotaDriverAPI):

    @staticmethod
    def get_default_quotas(context, resources, project_id):
        pass

    @staticmethod
    def get_tenant_quotas(context, resources, project_id):
        pass

    @staticmethod
    def get_detailed_tenant_quotas(context, resources, project_id):
        pass

    @staticmethod
    def delete_tenant_quota(context, project_id):
        pass

    @staticmethod
    def get_all_quotas(context, resources):
        pass

    @staticmethod
    def update_quota_limit(context, project_id, resource, limit):
        pass

    @staticmethod
    def make_reservation(context, project_id, resources, deltas, plugin):
        pass

    @staticmethod
    def commit_reservation(context, reservation_id):
        pass

    @staticmethod
    def cancel_reservation(context, reservation_id):
        pass

    @staticmethod
    def limit_check(context, project_id, resources, values):
        pass

    @staticmethod
    def get_resource_usage(context, project_id, resources, resource_name):
        pass

    @staticmethod
    def quota_limit_check(context, project_id, resources, deltas):
        pass
