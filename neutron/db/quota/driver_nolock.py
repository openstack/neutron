# Copyright (c) 2021 Red Hat Inc.
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

from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from oslo_db import exception as db_exc
from oslo_log import log

from neutron.common import utils
from neutron.db.quota import api as quota_api
from neutron.db.quota import driver as quota_driver
from neutron import worker as neutron_worker


LOG = log.getLogger(__name__)


class DbQuotaNoLockDriver(quota_driver.DbQuotaDriver):
    """Driver to enforce quotas and retrieve quota information

    This driver does not use a (resource, project_id) lock but relays on the
    simplicity of the calculation method, that is executed in a single database
    transaction. The method (1) counts the number of created resources and (2)
    the number of resource reservations. If the requested number of resources
    do not exceeds the quota, a new reservation register is created.

    This calculation method does not guarantee the quota enforcement if, for
    example, the database isolation level is read committed; two transactions
    can count the same number of resources and reservations, committing both
    a new reservation exceeding the quota. But the goal of this reservation
    method is to be fast enough to avoid the concurrency when counting the
    resources while not blocking concurrent API operations.
    """
    @staticmethod
    @utils.skip_exceptions(db_exc.DBError)
    def _remove_expired_reservations():
        """Remove expired reservations from all projects

        Any DB exception will be catch and dismissed. This operation can have
        been successfully executed by another concurrent request. There is no
        need to fail or retry it.
        """
        context = n_context.get_admin_context()
        quota_api.remove_expired_reservations(
            context, timeout=quota_api.RESERVATION_EXPIRATION_TIMEOUT)

    @db_api.retry_if_session_inactive()
    def make_reservation(self, context, project_id, resources, deltas, plugin):
        resources_over_limit = []
        with db_api.CONTEXT_WRITER.using(context):
            # Filter out unlimited resources.
            limits = self.get_project_quotas(context, resources, project_id)
            unlimited_resources = set([resource for (resource, limit) in
                                       limits.items() if limit < 0])
            requested_resources = (set(deltas.keys()) - unlimited_resources)

            # Count the number of (1) used and (2) reserved resources for this
            # project_id. If any resource limit is exceeded, raise exception.
            for resource_name in requested_resources:
                used_and_reserved = self.get_resource_usage(
                    context, project_id, resources, resource_name)
                resource_num = deltas[resource_name]
                if limits[resource_name] < (used_and_reserved + resource_num):
                    resources_over_limit.append(resource_name)

            if resources_over_limit:
                raise exceptions.OverQuota(overs=sorted(resources_over_limit))

            return quota_api.create_reservation(context, project_id, deltas)

    def cancel_reservation(self, context, reservation_id):
        quota_api.remove_reservation(context, reservation_id, set_dirty=False)

    @staticmethod
    def get_resource_usage(context, project_id, resources, resource_name):
        tracked_resource = resources.get(resource_name)
        if not tracked_resource:
            return
        return tracked_resource.count(context, None, project_id,
                                      count_db_registers=True)

    @staticmethod
    def get_resource_count(context, project_id, tracked_resource):
        return tracked_resource.count_db_registers(context, project_id)

    @staticmethod
    def get_workers():
        interval = quota_api.RESERVATION_EXPIRATION_TIMEOUT
        method = DbQuotaNoLockDriver._remove_expired_reservations
        return [neutron_worker.PeriodicWorker(method, interval, interval)]
