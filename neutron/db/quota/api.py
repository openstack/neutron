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

from neutron.db import common_db_mixin as common_db_api
from neutron.db.quota import models as quota_models


class QuotaUsageInfo(collections.namedtuple(
    'QuotaUsageInfo', ['resource', 'tenant_id', 'used', 'reserved', 'dirty'])):

    @property
    def total(self):
        """Total resource usage (reserved and used)."""
        return self.reserved + self.used


def get_quota_usage_by_resource_and_tenant(context, resource, tenant_id,
                                           lock_for_update=False):
    """Return usage info for a given resource and tenant.

    :param context: Request context
    :param resource: Name of the resource
    :param tenant_id: Tenant identifier
    :param lock_for_update: if True sets a write-intent lock on the query
    :returns: a QuotaUsageInfo instance
    """

    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource, tenant_id=tenant_id)

    if lock_for_update:
        query = query.with_lockmode('update')

    result = query.first()
    if not result:
        return
    return QuotaUsageInfo(result.resource,
                          result.tenant_id,
                          result.in_use,
                          result.reserved,
                          result.dirty)


def get_quota_usage_by_resource(context, resource):
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource)
    return [QuotaUsageInfo(item.resource,
                           item.tenant_id,
                           item.in_use,
                           item.reserved,
                           item.dirty) for item in query]


def get_quota_usage_by_tenant_id(context, tenant_id):
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(tenant_id=tenant_id)
    return [QuotaUsageInfo(item.resource,
                           item.tenant_id,
                           item.in_use,
                           item.reserved,
                           item.dirty) for item in query]


def set_quota_usage(context, resource, tenant_id,
                    in_use=None, reserved=None, delta=False):
    """Set resource quota usage.

    :param context: instance of neutron context with db session
    :param resource: name of the resource for which usage is being set
    :param tenant_id: identifier of the tenant for which quota usage is
                      being set
    :param in_use: integer specifying the new quantity of used resources,
                   or a delta to apply to current used resource
    :param reserved: integer specifying the new quantity of reserved resources,
                     or a delta to apply to current reserved resources
    :param delta: Specififies whether in_use or reserved are absolute numbers
                  or deltas (default to False)
    """
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource).filter_by(tenant_id=tenant_id)
    usage_data = query.first()
    with context.session.begin(subtransactions=True):
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
        if reserved is not None:
            if delta:
                reserved = usage_data.reserved + reserved
            usage_data.reserved = reserved
        # After an explicit update the dirty bit should always be reset
        usage_data.dirty = False
    return QuotaUsageInfo(usage_data.resource,
                          usage_data.tenant_id,
                          usage_data.in_use,
                          usage_data.reserved,
                          usage_data.dirty)


def set_quota_usage_dirty(context, resource, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given resource and tenant.

    :param resource: a resource for which quota usage if tracked
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: 1 if the quota usage data were updated, 0 otherwise.
    """
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource).filter_by(tenant_id=tenant_id)
    return query.update({'dirty': dirty})


def set_resources_quota_usage_dirty(context, resources, tenant_id, dirty=True):
    """Set quota usage dirty bit for a given tenant and multiple resources.

    :param resources: list of resource for which the dirty bit is going
                      to be set
    :param tenant_id: tenant identifier
    :param dirty: the desired value for the dirty bit (defaults to True)
    :returns: the number of records for which the bit was actually set.
    """
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(tenant_id=tenant_id)
    if resources:
        query = query.filter(quota_models.QuotaUsage.resource.in_(resources))
    # synchronize_session=False needed because of the IN condition
    return query.update({'dirty': dirty}, synchronize_session=False)


def set_all_quota_usage_dirty(context, resource, dirty=True):
    """Set the dirty bit on quota usage for all tenants.

    :param resource: the resource for which the dirty bit should be set
    :returns: the number of tenants for which the dirty bit was
              actually updated
    """
    query = common_db_api.model_query(context, quota_models.QuotaUsage)
    query = query.filter_by(resource=resource)
    return query.update({'dirty': dirty})
