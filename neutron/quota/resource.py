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

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as oslo_db_exception
from oslo_log import log
from oslo_utils import excutils
from sqlalchemy import event

from neutron.db import api as db_api
from neutron.db.quota import api as quota_api
from neutron.i18n import _LE

LOG = log.getLogger(__name__)


def _count_resource(context, plugin, collection_name, tenant_id):
    count_getter_name = "get_%s_count" % collection_name

    # Some plugins support a count method for particular resources,
    # using a DB's optimized counting features. We try to use that one
    # if present. Otherwise just use regular getter to retrieve all objects
    # and count in python, allowing older plugins to still be supported
    try:
        obj_count_getter = getattr(plugin, count_getter_name)
        meh = obj_count_getter(context, filters={'tenant_id': [tenant_id]})
        return meh
    except (NotImplementedError, AttributeError):
        obj_getter = getattr(plugin, "get_%s" % collection_name)
        obj_list = obj_getter(context, filters={'tenant_id': [tenant_id]})
        return len(obj_list) if obj_list else 0


class BaseResource(object):
    """Describe a single resource for quota checking."""

    def __init__(self, name, flag, plural_name=None):
        """Initializes a resource.

        :param name: The name of the resource, i.e., "instances".
        :param flag: The name of the flag or configuration option
        :param plural_name: Plural form of the resource name. If not
                            specified, it is generated automatically by
                            appending an 's' to the resource name, unless
                            it ends with a 'y'. In that case the last
                            letter is removed, and 'ies' is appended.
                            Dashes are always converted to underscores.
        """

        self.name = name
        # If a plural name is not supplied, default to adding an 's' to
        # the resource name, unless the resource name ends in 'y', in which
        # case remove the 'y' and add 'ies'. Even if the code should not fiddle
        # too much with English grammar, this is a rather common and easy to
        # implement rule.
        if plural_name:
            self.plural_name = plural_name
        elif self.name[-1] == 'y':
            self.plural_name = "%sies" % self.name[:-1]
        else:
            self.plural_name = "%ss" % self.name
        # always convert dashes to underscores
        self.plural_name = self.plural_name.replace('-', '_')
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

    def __init__(self, name, count, flag=None, plural_name=None):
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
        :param plural_name: Plural form of the resource name. If not
                            specified, it is generated automatically by
                            appending an 's' to the resource name, unless
                            it ends with a 'y'. In that case the last
                            letter is removed, and 'ies' is appended.
                            Dashes are always converted to underscores.
        """

        super(CountableResource, self).__init__(
            name, flag=flag, plural_name=plural_name)
        self._count_func = count

    def count(self, context, plugin, tenant_id):
        return self._count_func(context, plugin, self.plural_name, tenant_id)


class TrackedResource(BaseResource):
    """Resource which keeps track of its usage data."""

    def __init__(self, name, model_class, flag, plural_name=None):
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
        :param plural_name: Plural form of the resource name. If not
                            specified, it is generated automatically by
                            appending an 's' to the resource name, unless
                            it ends with a 'y'. In that case the last
                            letter is removed, and 'ies' is appended.
                            Dashes are always converted to underscores.

        """
        super(TrackedResource, self).__init__(
            name, flag=flag, plural_name=plural_name)
        # Register events for addition/removal of records in the model class
        # As tenant_id is immutable for all Neutron objects there is no need
        # to register a listener for update events
        self._model_class = model_class
        self._dirty_tenants = set()
        self._out_of_sync_tenants = set()

    @property
    def dirty(self):
        return self._dirty_tenants

    def mark_dirty(self, context, nested=False):
        if not self._dirty_tenants:
            return
        with context.session.begin(nested=nested, subtransactions=True):
            # It is not necessary to protect this operation with a lock.
            # Indeed when this method is called the request has been processed
            # and therefore all resources created or deleted.
            # dirty_tenants will contain all the tenants for which the
            # resource count is changed. The list might contain also tenants
            # for which resource count was altered in other requests, but this
            # won't be harmful.
            dirty_tenants_snap = self._dirty_tenants.copy()
            for tenant_id in dirty_tenants_snap:
                quota_api.set_quota_usage_dirty(context, self.name, tenant_id)
                LOG.debug(("Persisted dirty status for tenant:%(tenant_id)s "
                           "on resource:%(resource)s"),
                          {'tenant_id': tenant_id, 'resource': self.name})
        self._out_of_sync_tenants |= dirty_tenants_snap
        self._dirty_tenants = self._dirty_tenants - dirty_tenants_snap

    def _db_event_handler(self, mapper, _conn, target):
        try:
            tenant_id = target['tenant_id']
        except AttributeError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Model class %s does not have a tenant_id "
                              "attribute"), target)
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
        return quota_api.set_quota_usage(
            context, self.name, tenant_id, in_use=in_use)

    def _resync(self, context, tenant_id, in_use):
        # Update quota usage
        usage_info = self._set_quota_usage(context, tenant_id, in_use)

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

    def count(self, context, _plugin, tenant_id, resync_usage=False):
        """Return the current usage count for the resource.

        This method will fetch aggregate information for resource usage
        data, unless usage data are marked as "dirty".
        In the latter case resource usage will be calculated counting
        rows for tenant_id in the resource's database model.
        Active reserved amount are instead always calculated by summing
        amounts for matching records in the 'reservations' database model.

        The _plugin and _resource parameters are unused but kept for
        compatibility with the signature of the count method for
        CountableResource instances.
        """
        # Load current usage data, setting a row-level lock on the DB
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            context, self.name, tenant_id, lock_for_update=True)
        # Always fetch reservations, as they are not tracked by usage counters
        reservations = quota_api.get_reservations_for_resources(
            context, tenant_id, [self.name])
        reserved = reservations.get(self.name, 0)

        # If dirty or missing, calculate actual resource usage querying
        # the database and set/create usage info data
        # NOTE: this routine "trusts" usage counters at service startup. This
        # assumption is generally valid, but if the database is tampered with,
        # or if data migrations do not take care of usage counters, the
        # assumption will not hold anymore
        if (tenant_id in self._dirty_tenants or
            not usage_info or usage_info.dirty):
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
                # NOTE(salv-orlando): Passing 0 for reserved amount as
                # reservations are currently not supported
                usage_info = quota_api.QuotaUsageInfo(usage_info.resource,
                                                      usage_info.tenant_id,
                                                      in_use,
                                                      usage_info.dirty)

            LOG.debug(("Quota usage for %(resource)s was recalculated. "
                       "Used quota:%(used)d."),
                      {'resource': self.name,
                       'used': usage_info.used})
        return usage_info.used + reserved

    def register_events(self):
        event.listen(self._model_class, 'after_insert', self._db_event_handler)
        event.listen(self._model_class, 'after_delete', self._db_event_handler)

    def unregister_events(self):
        event.remove(self._model_class, 'after_insert', self._db_event_handler)
        event.remove(self._model_class, 'after_delete', self._db_event_handler)
