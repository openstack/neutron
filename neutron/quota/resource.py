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

from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import session as se

from neutron._i18n import _
from neutron.conf import quota as quota_conf
from neutron.db.quota import api as quota_api

LOG = log.getLogger(__name__)


def _count_resource(context, collection_name, project_id):
    count_getter_name = "get_%s_count" % collection_name
    getter_name = "get_%s" % collection_name

    plugins = directory.get_plugins()
    for pname in sorted(plugins,
                        # inspect core plugin first
                        key=lambda n: n != constants.CORE):
        # Some plugins support a count method for particular resources, using a
        # DB's optimized counting features. We try to use that one if present.
        # Otherwise just use regular getter to retrieve all objects and count
        # in python, allowing older plugins to still be supported
        try:
            obj_count_getter = getattr(plugins[pname], count_getter_name)
            return obj_count_getter(
                context, filters={'project_id': [project_id]})
        except (NotImplementedError, AttributeError):
            try:
                obj_getter = getattr(plugins[pname], getter_name)
                obj_list = obj_getter(
                    context, filters={'project_id': [project_id]})
                return len(obj_list) if obj_list else 0
            except (NotImplementedError, AttributeError):
                pass
    raise NotImplementedError(
        _('No plugins that support counting %s found.') % collection_name)


class BaseResource(object, metaclass=abc.ABCMeta):
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
        return max(value, quota_api.UNLIMITED_QUOTA)

    @property
    @abc.abstractmethod
    def dirty(self):
        """Return the current state of the Resource instance.

        :returns: True if the resource count is out of sync with actual date,
                  False if it is in sync, and None if the resource instance
                  does not track usage.
        """

    @abc.abstractmethod
    def count(self, context, plugin, project_id, **kwargs):
        """Return the total count of this resource"""


class CountableResource(BaseResource):
    """Describe a resource where the counts are determined by a function."""

    def __init__(self, name, count, flag=None, plural_name=None):
        """Initializes a CountableResource.

        Countable resources are those resources which directly
        correspond to objects in the database, i.e., network, subnet,
        etc.,.  A CountableResource must be constructed with a counting
        function, which will be called to determine the current counts
        of the resource.

        The counting function will be passed the context, along with
        the extra positional and keyword arguments that are passed to
        Quota.count().  It should return an integer specifying the
        count.

        :param name: The name of the resource, i.e., "instances".
        :param count: A callable which returns the count of the
                      resource. The arguments passed are as described
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

    @property
    def dirty(self):
        return

    def count(self, context, plugin, project_id, **kwargs):
        # NOTE(ihrachys) _count_resource doesn't receive plugin
        return self._count_func(context, self.plural_name, project_id)


class TrackedResource(BaseResource):
    """Resource which keeps track of its usage data."""

    def __init__(self, name, model_class, flag, plural_name=None):
        """Initializes an instance for a given resource.

        TrackedResource are directly mapped to data model classes.
        Resource usage is tracked in the database, and the model class to
        which this resource refers is monitored to ensure always "fresh"
        usage data are employed when performing quota checks.

        This class operates under the assumption that the model class
        describing the resource has a project identifier attribute.

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
        # As project_id is immutable for all Neutron objects there is no need
        # to register a listener for update events
        self._model_class = model_class
        self._dirty_projects = set()
        self._out_of_sync_projects = set()
        # NOTE(ralonsoh): "DbQuotaNoLockDriver" driver does not need to track
        # the DB events or resync the resource quota usage.
        if cfg.CONF.QUOTAS.quota_driver == quota_conf.QUOTA_DB_DRIVER:
            self._track_resource_events = False
        else:
            self._track_resource_events = True

    @property
    def dirty(self):
        if not self._track_resource_events:
            return
        return self._dirty_projects

    def mark_dirty(self, context):
        if not self._dirty_projects or not self._track_resource_events:
            return
        with db_api.CONTEXT_WRITER.using(context):
            # It is not necessary to protect this operation with a lock.
            # Indeed when this method is called the request has been processed
            # and therefore all resources created or deleted.
            # dirty_projects will contain all the projects for which the
            # resource count is changed. The list might contain also projects
            # for which resource count was altered in other requests, but this
            # won't be harmful.
            dirty_projects_snap = self._dirty_projects.copy()
            for project_id in dirty_projects_snap:
                quota_api.set_resources_quota_usage_dirty(context, self.name,
                                                          project_id)
        self._out_of_sync_projects |= dirty_projects_snap
        self._dirty_projects -= dirty_projects_snap

    def _db_event_handler(self, mapper, _conn, target):
        try:
            project_id = target['project_id']
        except AttributeError:
            with excutils.save_and_reraise_exception():
                LOG.error("Model class %s does not have a project_id "
                          "attribute", target)
        self._dirty_projects.add(project_id)

    # Retry the operation if a duplicate entry exception is raised. This
    # can happen is two or more workers are trying to create a resource of a
    # give kind for the same project concurrently. Retrying the operation will
    # ensure that an UPDATE statement is emitted rather than an INSERT one
    @db_api.retry_if_session_inactive()
    def _set_quota_usage(self, context, project_id, in_use):
        return quota_api.set_quota_usage(
            context, self.name, project_id, in_use=in_use)

    def _resync(self, context, project_id, in_use):
        # Update quota usage
        usage_info = self._set_quota_usage(context, project_id, in_use)

        self._dirty_projects.discard(project_id)
        self._out_of_sync_projects.discard(project_id)
        LOG.debug(("Unset dirty status for project:%(project_id)s on "
                   "resource:%(resource)s"),
                  {'project_id': project_id, 'resource': self.name})
        return usage_info

    @db_api.CONTEXT_WRITER
    def resync(self, context, project_id):
        if (project_id not in self._out_of_sync_projects or
                not self._track_resource_events):
            return
        LOG.debug(("Synchronizing usage tracker for project:%(project_id)s on "
                   "resource:%(resource)s"),
                  {'project_id': project_id, 'resource': self.name})
        in_use = context.session.query(
            self._model_class.project_id).filter_by(
                project_id=project_id).count()
        # Update quota usage
        return self._resync(context, project_id, in_use)

    @db_api.CONTEXT_WRITER
    def count_used(self, context, project_id, resync_usage=True):
        """Returns the current usage count for the resource.

        :param context: The request context.
        :param project_id: The ID of the project
        :param resync_usage: Default value is set to True. Syncs
            with in_use usage.
        """
        # Load current usage data, setting a row-level lock on the DB
        usage_info = quota_api.get_quota_usage_by_resource_and_project(
            context, self.name, project_id)

        # If dirty or missing, calculate actual resource usage querying
        # the database and set/create usage info data
        # NOTE: this routine "trusts" usage counters at service startup. This
        # assumption is generally valid, but if the database is tampered with,
        # or if data migrations do not take care of usage counters, the
        # assumption will not hold anymore
        if (project_id in self._dirty_projects or
                not usage_info or usage_info.dirty):
            LOG.debug(("Usage tracker for resource:%(resource)s and project:"
                       "%(project_id)s is out of sync, need to count used "
                       "quota"), {'resource': self.name,
                                  'project_id': project_id})
            in_use = context.session.query(
                self._model_class.project_id).filter_by(
                    project_id=project_id).count()

            # Update quota usage, if requested (by default do not do that, as
            # typically one counts before adding a record, and that would mark
            # the usage counter as dirty again)
            if resync_usage:
                usage_info = self._resync(context, project_id, in_use)
            else:
                resource = usage_info.resource if usage_info else self.name
                project_id = (usage_info.project_id if usage_info else
                              project_id)
                dirty = usage_info.dirty if usage_info else True
                usage_info = quota_api.QuotaUsageInfo(
                    resource, project_id, in_use, dirty)

            LOG.debug(("Quota usage for %(resource)s was recalculated. "
                       "Used quota:%(used)d."),
                      {'resource': self.name,
                       'used': usage_info.used})
        return usage_info.used

    def count_reserved(self, context, project_id):
        """Return the current reservation count for the resource."""
        # NOTE(princenana) Current implementation of reservations
        # is ephemeral and returns the default value
        reservations = quota_api.get_reservations_for_resources(
            context, project_id, [self.name])
        reserved = reservations.get(self.name, 0)
        return reserved

    def count(self, context, _plugin, project_id, resync_usage=True,
              count_db_registers=False):
        """Return the count of the resource.

        The _plugin parameter is unused but kept for
        compatibility with the signature of the count method for
        CountableResource instances.
        """
        if count_db_registers:
            count = self.count_db_registers(context, project_id)
        else:
            count = self.count_used(context, project_id, resync_usage)

        return count + self.count_reserved(context, project_id)

    def count_db_registers(self, context, project_id):
        """Return the existing resources (self._model_class) in a project.

        The query executed must be as fast as possible. To avoid retrieving all
        model backref relationship columns, only "project_id" is requested
        (this column always exists in the DB model because is used in the
        filter).
        """
        # TODO(ralonsoh): declare the OVO class instead the DB model and use
        # ``NeutronDbObject.count`` with the needed filters and fields to
        # retrieve ("project_id").
        admin_context = context.elevated()
        with db_api.CONTEXT_READER.using(admin_context):
            query = admin_context.session.query(self._model_class.project_id)
            query = query.filter(self._model_class.project_id == project_id)
            return query.count()

    def _except_bulk_delete(self, delete_context):
        if delete_context.mapper.class_ == self._model_class:
            raise RuntimeError(_("%s may not be deleted in bulk because "
                                 "it is tracked by the quota engine via "
                                 "SQLAlchemy event handlers, which are not "
                                 "compatible with bulk deletes.") %
                               self._model_class)

    def register_events(self):
        if not self._track_resource_events:
            return
        listen = db_api.sqla_listen
        listen(self._model_class, 'after_insert', self._db_event_handler)
        listen(self._model_class, 'after_delete', self._db_event_handler)
        listen(se.Session, 'after_bulk_delete', self._except_bulk_delete)

    def unregister_events(self):
        if not self._track_resource_events:
            return
        try:
            db_api.sqla_remove(self._model_class, 'after_insert',
                               self._db_event_handler)
            db_api.sqla_remove(self._model_class, 'after_delete',
                               self._db_event_handler)
            db_api.sqla_remove(se.Session, 'after_bulk_delete',
                               self._except_bulk_delete)
        except sql_exc.InvalidRequestError:
            LOG.warning("No sqlalchemy event for resource %s found",
                        self.name)
