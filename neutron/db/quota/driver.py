# Copyright 2011 OpenStack Foundation.
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

from neutron_lib.api import attributes
from neutron_lib.db import api as db_api
from neutron_lib.db import quota_api as nlib_quota_api
from neutron_lib import exceptions
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_log import log

from neutron.db.quota import api as quota_api
from neutron.objects import quota as quota_obj
from neutron.quota import resource as res

LOG = log.getLogger(__name__)


class DbQuotaDriver(nlib_quota_api.QuotaDriverAPI):
    """Driver to perform necessary checks to enforce quotas and obtain quota
    information.

    The default driver utilizes the local database.
    """

    @staticmethod
    def get_default_quotas(context, resources, project_id):
        """Given a list of resources, retrieve the default quotas set for
        a project.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return default quotas for.
        :return: dict from resource name to dict of name and limit
        """
        # Currently the project_id parameter is unused, since all projects
        # share the same default values. This may change in the future so
        # we include project ID to remain backwards compatible.
        return dict((key, resource.default)
                    for key, resource in resources.items())

    @staticmethod
    @db_api.retry_if_session_inactive()
    def get_project_quotas(context, resources, project_id):
        """Given a list of resources, retrieve the quotas for the given
        project. If no limits are found for the specified project, the
        operation returns the default limits.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return quotas for.
        :return: dict from resource name to dict of name and limit
        """

        # init with defaults
        project_quota = dict((key, resource.default)
                            for key, resource in resources.items())

        # update with project specific limits
        quota_objs = quota_obj.Quota.get_objects(context,
                                                 project_id=project_id)
        for item in quota_objs:
            project_quota[item['resource']] = item['limit']

        return project_quota

    @db_api.retry_if_session_inactive()
    def get_detailed_project_quotas(self, context, resources, project_id):
        """Given a list of resources and a specific project, retrieve
        the detailed quotas (limit, used, reserved).
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the project to return quotas for.
        :return dict: mapping resource name in dict to its corresponding limit
            used and reserved. Reserved currently returns default value of 0
        """
        res_reserve_info = quota_api.get_reservations_for_resources(
            context, project_id, resources.keys())
        project_quota_ext = {}
        for key, resource in resources.items():
            if isinstance(resource, res.TrackedResource):
                used = self.get_resource_count(context, project_id, resource)
            else:
                # NOTE(ihrachys) .count won't use the plugin we pass, but we
                # pass it regardless to keep the quota driver API intact
                plugins = directory.get_plugins()
                plugin = plugins.get(key, plugins[constants.CORE])
                used = resource.count(context, plugin, project_id)

            project_quota_ext[key] = {
                'limit': resource.default,
                'used': used,
                'reserved': res_reserve_info.get(key, 0),
            }
        # update with specific project limits
        quota_objs = quota_obj.Quota.get_objects(context,
                                                 project_id=project_id)
        for item in quota_objs:
            project_quota_ext[item['resource']]['limit'] = item['limit']
        return project_quota_ext

    @staticmethod
    @db_api.retry_if_session_inactive()
    def delete_project_quota(context, project_id):
        """Delete the quota entries for a given project_id.

        After deletion, this project will use default quota values in conf.
        Raise a "not found" error if the quota for the given project was
        never defined.
        """
        if quota_obj.Quota.delete_objects(context, project_id=project_id) < 1:
            # No record deleted means the quota was not found
            raise exceptions.TenantQuotaNotFound(tenant_id=project_id)

    @staticmethod
    @db_api.retry_if_session_inactive()
    def get_all_quotas(context, resources):
        """Given a list of resources, retrieve the quotas for the all projects.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return: quotas list of dict of project_id:, resourcekey1:
        resourcekey2: ...
        """
        project_default = dict((key, resource.default)
                              for key, resource in resources.items())

        all_project_quotas = {}

        for quota in quota_obj.Quota.get_objects(context):
            project_id = quota['project_id']

            # avoid setdefault() because only want to copy when actually
            # required
            project_quota = all_project_quotas.get(project_id)
            if project_quota is None:
                project_quota = project_default.copy()
                project_quota['project_id'] = project_id
                attributes.populate_project_info(project_quota)
                all_project_quotas[project_id] = project_quota

            project_quota[quota['resource']] = quota['limit']

        # Convert values to a list to as caller expect an indexable iterable,
        # where python3's dict_values does not support indexing
        return list(all_project_quotas.values())

    @staticmethod
    @db_api.retry_if_session_inactive()
    def update_quota_limit(context, project_id, resource, limit):
        project_quotas = quota_obj.Quota.get_objects(
            context, project_id=project_id, resource=resource)
        if project_quotas:
            project_quotas[0].limit = limit
            project_quotas[0].update()
        else:
            quota_obj.Quota(context, project_id=project_id, resource=resource,
                            limit=limit).create()

    def _get_quotas(self, context, project_id, resources):
        """Retrieves the quotas for specific resources.

        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param project_id: the project ID to check quota.
        :param resources: A dictionary of the registered resources.
        """
        # Grab and return the quotas (without usages)
        quotas = DbQuotaDriver.get_project_quotas(
            context, resources, project_id)

        return dict((k, v) for k, v in quotas.items())

    def _handle_expired_reservations(self, context, project_id):
        LOG.debug("Deleting expired reservations for project: %s", project_id)
        # Delete expired reservations (we don't want them to accrue
        # in the database)
        quota_api.remove_expired_reservations(context, project_id=project_id)

    @db_api.retry_if_session_inactive()
    def make_reservation(self, context, project_id, resources, deltas, plugin):
        # Lock current reservation table
        # NOTE(salv-orlando): This routine uses DB write locks.
        # These locks are acquired by the count() method invoked on resources.
        # Please put your shotguns aside.
        # A non locking algorithm for handling reservation is feasible, however
        # it will require two database writes even in cases when there are not
        # concurrent reservations.
        # For this reason it might be advisable to handle contention using
        # this kind of locks and paying the cost of a write set certification
        # failure when a MySQL Galera cluster is employed. Also, this class of
        # locks should be ok to use when support for sending "hotspot" writes
        # to a single node will be available.
        requested_resources = deltas.keys()
        with db_api.CONTEXT_WRITER.using(context):
            # "get_project_quotas" needs in input a dictionary mapping resource
            # name to BaseResource instances so that the default quota can be
            # retrieved
            current_limits = self.get_project_quotas(
                context, resources, project_id)
            unlimited_resources = set([resource for (resource, limit) in
                                       current_limits.items() if limit < 0])
            # Do not even bother counting resources and calculating headroom
            # for resources with unlimited quota
            LOG.debug("Resources %s have unlimited quota limit. It is not "
                      "required to calculate headroom ",
                      ",".join(unlimited_resources))
            requested_resources = (set(requested_resources) -
                                   unlimited_resources)
            # Gather current usage information
            # TODO(salv-orlando): calling get_resource_usage() for every
            # resource triggers multiple queries on quota usage. This should be
            # improved, however this is not an urgent matter as the REST API
            # currently only allows allocation of a resource at a time
            current_usages = dict(
                (resource, self.get_resource_usage(context, project_id,
                                                   resources, resource)) for
                resource in requested_resources)
            # Adjust for expired reservations. Apparently it is cheaper than
            # querying every time for active reservations and counting overall
            # quantity of resources reserved
            expired_deltas = quota_api.get_reservations_for_resources(
                context, project_id, requested_resources, expired=True)
            # Verify that the request can be accepted with current limits
            resources_over_limit = []
            for resource in requested_resources:
                expired_reservations = expired_deltas.get(resource, 0)
                total_usage = current_usages[resource] - expired_reservations
                res_headroom = current_limits[resource] - total_usage
                LOG.debug(("Attempting to reserve %(delta)d items for "
                           "resource %(resource)s. Total usage: %(total)d; "
                           "quota limit: %(limit)d; headroom:%(headroom)d"),
                          {'resource': resource,
                           'delta': deltas[resource],
                           'total': total_usage,
                           'limit': current_limits[resource],
                           'headroom': res_headroom})
                if res_headroom < deltas[resource]:
                    resources_over_limit.append(resource)
                if expired_reservations:
                    self._handle_expired_reservations(context, project_id)

            if resources_over_limit:
                raise exceptions.OverQuota(overs=sorted(resources_over_limit))
            # Success, store the reservation
            # TODO(salv-orlando): Make expiration time configurable
            return quota_api.create_reservation(
                context, project_id, deltas)

    def commit_reservation(self, context, reservation_id):
        # Do not mark resource usage as dirty. If a reservation is committed,
        # then the relevant resources have been created. Usage data for these
        # resources has therefore already been marked dirty.
        quota_api.remove_reservation(context, reservation_id,
                                     set_dirty=False)

    def cancel_reservation(self, context, reservation_id):
        # Mark resource usage as dirty so the next time both actual resources
        # used and reserved will be recalculated
        quota_api.remove_reservation(context, reservation_id,
                                     set_dirty=True)

    def limit_check(self, context, project_id, resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param project_id: The project ID to check the quota.
        :param resources: A dictionary of the registered resources.
        :param values: A dictionary of the values to check against the
                       quota.
        """

        # Ensure no value is less than zero
        unders = [key for key, val in values.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        # Get the applicable quotas
        quotas = self._get_quotas(context, project_id, resources)

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items() if 0 <= quotas[key] < val]
        if overs:
            raise exceptions.OverQuota(overs=sorted(overs))

    @staticmethod
    def get_resource_usage(context, project_id, resources, resource_name):
        tracked_resource = resources.get(resource_name)
        if not tracked_resource:
            return

        return tracked_resource.count(context, None, project_id,
                                      resync_usage=False)

    @staticmethod
    def get_resource_count(context, project_id, tracked_resource):
        return tracked_resource.count_used(context, project_id,
                                           resync_usage=False)

    def quota_limit_check(self, context, project_id, resources, deltas):
        # Ensure no value is less than zero
        unders = [key for key, val in deltas.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        current_limits = self.get_project_quotas(context, resources,
                                                 project_id)
        overs = set()
        for resource_name, delta in deltas.items():
            resource_limit = current_limits.get(resource_name)
            if resource_limit in (None, quota_api.UNLIMITED_QUOTA):
                continue

            resource_usage = self.get_resource_usage(context, project_id,
                                                     resources, resource_name)
            if resource_usage is None:
                continue

            if resource_usage + delta > resource_limit:
                overs.add(resource_name)

        if overs:
            raise exceptions.OverQuota(overs=sorted(overs))

    @staticmethod
    def get_workers():
        return []
