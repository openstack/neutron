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

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as oslo_db_exception
from oslo_log import log
from sqlalchemy import event

from neutron.db import api as db_api
from neutron.db.quota import api as quota_api
from neutron.i18n import _LE

LOG = log.getLogger(__name__)


def _count_resource(context, plugin, resources, tenant_id):
    count_getter_name = "get_%s_count" % resources

    # Some plugins support a count method for particular resources,
    # using a DB's optimized counting features. We try to use that one
    # if present. Otherwise just use regular getter to retrieve all objects
    # and count in python, allowing older plugins to still be supported
    try:
        obj_count_getter = getattr(plugin, count_getter_name)
        meh = obj_count_getter(context, filters={'tenant_id': [tenant_id]})
        return meh
    except (NotImplementedError, AttributeError):
        obj_getter = getattr(plugin, "get_%s" % resources)
        obj_list = obj_getter(context, filters={'tenant_id': [tenant_id]})
        return len(obj_list) if obj_list else 0


class BaseResource(object):
    """Describe a single resource for quota checking."""

    def __init__(self, name, flag):
        """Initializes a resource.

        :param name: The name of the resource, i.e., "instances".
        :param flag: The name of the flag or configuration option
        """

        self.name = name
        self.flag = flag

    @property
    def default(self):
        """Return the default value of the quota."""
        # Any negative value will be interpreted as an infinite quota,
        # and stored as -1 for compatibility with current behaviour
        value = getattr(cfg.CONF.QUOTAS,
                        self.flag,
                        cfg.CONF.QUOTAS.default_quota)
        return max(value, -1)

    @property
    def dirty(self):
        """Return the current state of the Resource instance.

        :returns: True if the resource count is out of sync with actual date,
                  False if it is in sync, and None if the resource instance
                  does not track usage.
        """


class CountableResource(BaseResource):
    """Describe a resource where the counts are determined by a function."""

    def __init__(self, name, count, flag=None):
        """Initializes a CountableResource.

        Countable resources are those resources which directly
        correspond to objects in the database, i.e., netowk, subnet,
        etc.,.  A CountableResource must be constructed with a counting
        function, which will be called to determine the current counts
        of the resource.

        The counting function will be passed the context, along with
        the extra positional and keyword arguments that are passed to
        Quota.count().  It should return an integer specifying the
        count.

        :param name: The name of the resource, i.e., "instances".
        :param count: A callable which returns the count of the
                      resource.  The arguments passed are as described
                      above.
        :param flag: The name of the flag or configuration option
                     which specifies the default value of the quota
                     for this resource.
        """

        super(CountableResource, self).__init__(name, flag=flag)
        self.count = count


class TrackedResource(BaseResource):
    """Resource which keeps track of its usage data."""

    def __init__(self, name, model_class, flag):
        """Initializes an instance for a given resource.

        TrackedResource are directly mapped to data model classes.
        Resource usage is tracked in the database, and the model class to
        which this resource refers is monitored to ensure always "fresh"
        usage data are employed when performing quota checks.

        This class operates under the assumption that the model class
        describing the resource has a tenant identifier attribute.

        :param name: The name of the resource, i.e., "networks".
        :param model_class: The sqlalchemy model class of the resource for
                            which this instance is being created
        :param flag: The name of the flag or configuration option
                     which specifies the default value of the quota
                     for this resource.
        """
        super(TrackedResource, self).__init__(name, flag)
        # Register events for addition/removal of records in the model class
        # As tenant_id is immutable for all Neutron objects there is no need
        # to register a listener for update events
        self._model_class = model_class
        self._dirty_tenants = set()
        self._out_of_sync_tenants = set()

    @property
    def dirty(self):
        return self._dirty_tenants

    @lockutils.synchronized('dirty_tenants')
    def mark_dirty(self, context, nested=False):
        if not self._dirty_tenants:
            return
        with context.session.begin(nested=nested, subtransactions=True):
            for tenant_id in self._dirty_tenants:
                quota_api.set_quota_usage_dirty(context, self.name, tenant_id)
                LOG.debug(("Persisted dirty status for tenant:%(tenant_id)s "
                           "on resource:%(resource)s"),
                          {'tenant_id': tenant_id, 'resource': self.name})
        self._out_of_sync_tenants |= self._dirty_tenants
        self._dirty_tenants.clear()

    @lockutils.synchronized('dirty_tenants')
    def _db_event_handler(self, mapper, _conn, target):
        tenant_id = target.get('tenant_id')
        if not tenant_id:
            # NOTE: This is an unexpected error condition. Log anomaly but do
            # not raise as this might have unexpected effects on other
            # operations
            LOG.error(_LE("Model class %s does not have tenant_id attribute"),
                      target)
            return
        self._dirty_tenants.add(tenant_id)

    # Retry the operation if a duplicate entry exception is raised. This
    # can happen is two or more workers are trying to create a resource of a
    # give kind for the same tenant concurrently. Retrying the operation will
    # ensure that an UPDATE statement is emitted rather than an INSERT one
    @oslo_db_api.wrap_db_retry(
        max_retries=db_api.MAX_RETRIES,
        exception_checker=lambda exc:
        isinstance(exc, oslo_db_exception.DBDuplicateEntry))
    def _set_quota_usage(self, context, tenant_id, in_use):
        return quota_api.set_quota_usage(context, self.name,
                                         tenant_id, in_use=in_use)

    def _resync(self, context, tenant_id, in_use):
        # Update quota usage
        usage_info = self._set_quota_usage(
            context, tenant_id, in_use=in_use)
        self._dirty_tenants.discard(tenant_id)
        self._out_of_sync_tenants.discard(tenant_id)
        LOG.debug(("Unset dirty status for tenant:%(tenant_id)s on "
                   "resource:%(resource)s"),
                  {'tenant_id': tenant_id, 'resource': self.name})
        return usage_info

    def resync(self, context, tenant_id):
        if tenant_id not in self._out_of_sync_tenants:
            return
        LOG.debug(("Synchronizing usage tracker for tenant:%(tenant_id)s on "
                   "resource:%(resource)s"),
                  {'tenant_id': tenant_id, 'resource': self.name})
        in_use = context.session.query(self._model_class).filter_by(
            tenant_id=tenant_id).count()
        # Update quota usage
        return self._resync(context, tenant_id, in_use)

    def count(self, context, _plugin, _resources, tenant_id,
              resync_usage=False):
        """Return the current usage count for the resource."""
        # Load current usage data
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            context, self.name, tenant_id)
        # If dirty or missing, calculate actual resource usage querying
        # the database and set/create usage info data
        # NOTE: this routine "trusts" usage counters at service startup. This
        # assumption is generally valid, but if the database is tampered with,
        # or if data migrations do not take care of usage counters, the
        # assumption will not hold anymore
        if (tenant_id in self._dirty_tenants or not usage_info
            or usage_info.dirty):
            LOG.debug(("Usage tracker for resource:%(resource)s and tenant:"
                       "%(tenant_id)s is out of sync, need to count used "
                       "quota"), {'resource': self.name,
                                  'tenant_id': tenant_id})
            in_use = context.session.query(self._model_class).filter_by(
                tenant_id=tenant_id).count()
            # Update quota usage, if requested (by default do not do that, as
            # typically one counts before adding a record, and that would mark
            # the usage counter as dirty again)
            if resync_usage or not usage_info:
                usage_info = self._resync(context, tenant_id, in_use)
            else:
                usage_info = quota_api.QuotaUsageInfo(usage_info.resource,
                                                      usage_info.tenant_id,
                                                      in_use,
                                                      usage_info.reserved,
                                                      usage_info.dirty)

        return usage_info.total

    def register_events(self):
        event.listen(self._model_class, 'after_insert', self._db_event_handler)
        event.listen(self._model_class, 'after_delete', self._db_event_handler)

    def unregister_events(self):
        event.remove(self._model_class, 'after_insert', self._db_event_handler)
        event.remove(self._model_class, 'after_delete', self._db_event_handler)
