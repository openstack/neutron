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

from oslo_db import api as oslo_db_api
from oslo_log import log

from neutron.common import exceptions
from neutron.db import api as db_api
from neutron.db.quota import api as quota_api
from neutron.db.quota import models as quota_models

LOG = log.getLogger(__name__)


class DbQuotaDriver(object):
    """Driver to perform necessary checks to enforce quotas and obtain quota
    information.

    The default driver utilizes the local database.
    """

    @staticmethod
    def get_tenant_quotas(context, resources, tenant_id):
        """Given a list of resources, retrieve the quotas for the given
        tenant.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param tenant_id: The ID of the tenant to return quotas for.
        :return dict: from resource name to dict of name and limit
        """

        # init with defaults
        tenant_quota = dict((key, resource.default)
                            for key, resource in resources.items())

        # update with tenant specific limits
        q_qry = context.session.query(quota_models.Quota).filter_by(
            tenant_id=tenant_id)
        for item in q_qry:
            tenant_quota[item['resource']] = item['limit']

        return tenant_quota

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        """Delete the quota entries for a given tenant_id.

        Atfer deletion, this tenant will use default quota values in conf.
        """
        with context.session.begin():
            tenant_quotas = context.session.query(quota_models.Quota)
            tenant_quotas = tenant_quotas.filter_by(tenant_id=tenant_id)
            tenant_quotas.delete()

    @staticmethod
    def get_all_quotas(context, resources):
        """Given a list of resources, retrieve the quotas for the all tenants.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return quotas: list of dict of tenant_id:, resourcekey1:
        resourcekey2: ...
        """
        tenant_default = dict((key, resource.default)
                              for key, resource in resources.items())

        all_tenant_quotas = {}

        for quota in context.session.query(quota_models.Quota):
            tenant_id = quota['tenant_id']

            # avoid setdefault() because only want to copy when actually req'd
            tenant_quota = all_tenant_quotas.get(tenant_id)
            if tenant_quota is None:
                tenant_quota = tenant_default.copy()
                tenant_quota['tenant_id'] = tenant_id
                all_tenant_quotas[tenant_id] = tenant_quota

            tenant_quota[quota['resource']] = quota['limit']

        # Convert values to a list to as caller expect an indexable iterable,
        # where python3's dict_values does not support indexing
        return list(all_tenant_quotas.values())

    @staticmethod
    def update_quota_limit(context, tenant_id, resource, limit):
        with context.session.begin():
            tenant_quota = context.session.query(quota_models.Quota).filter_by(
                tenant_id=tenant_id, resource=resource).first()

            if tenant_quota:
                tenant_quota.update({'limit': limit})
            else:
                tenant_quota = quota_models.Quota(tenant_id=tenant_id,
                                                  resource=resource,
                                                  limit=limit)
                context.session.add(tenant_quota)

    def _get_quotas(self, context, tenant_id, resources):
        """Retrieves the quotas for specific resources.

        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param tenant_id: the tenant_id to check quota.
        :param resources: A dictionary of the registered resources.
        """
        # Grab and return the quotas (without usages)
        quotas = DbQuotaDriver.get_tenant_quotas(
            context, resources, tenant_id)

        return dict((k, v) for k, v in quotas.items())

    def _handle_expired_reservations(self, context, tenant_id):
        LOG.debug("Deleting expired reservations for tenant:%s" % tenant_id)
        # Delete expired reservations (we don't want them to accrue
        # in the database)
        quota_api.remove_expired_reservations(
            context, tenant_id=tenant_id)

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_request=True,
                               retry_on_deadlock=True)
    def make_reservation(self, context, tenant_id, resources, deltas, plugin):
        # Lock current reservation table
        # NOTE(salv-orlando): This routine uses DB write locks.
        # These locks are acquired by the count() method invoked on resources.
        # Please put your shotguns aside.
        # A non locking algorithm for handling reservation is feasible, however
        # it will require two database writes even in cases when there are not
        # concurrent reservations.
        # For this reason it might be advisable to handle contention using
        # this kind of locks and paying the cost of a write set certification
        # failure when a mysql galera cluster is employed. Also, this class of
        # locks should be ok to use when support for sending "hotspot" writes
        # to a single node will be avaialable.
        requested_resources = deltas.keys()
        with context.session.begin():
            # Gather current usage information
            # TODO(salv-orlando): calling count() for every resource triggers
            # multiple queries on quota usage. This should be improved, however
            # this is not an urgent matter as the REST API currently only
            # allows allocation of a resource at a time
            # NOTE: pass plugin too for compatibility with CountableResource
            # instances
            current_usages = dict(
                (resource, resources[resource].count(
                    context, plugin, tenant_id)) for
                resource in requested_resources)
            # get_tenant_quotes needs in inout a dictionary mapping resource
            # name to BaseResosurce instances so that the default quota can be
            # retrieved
            current_limits = self.get_tenant_quotas(
                context, resources, tenant_id)
            # Adjust for expired reservations. Apparently it is cheaper than
            # querying everytime for active reservations and counting overall
            # quantity of resources reserved
            expired_deltas = quota_api.get_reservations_for_resources(
                context, tenant_id, requested_resources, expired=True)
            # Verify that the request can be accepted with current limits
            resources_over_limit = []
            for resource in requested_resources:
                expired_reservations = expired_deltas.get(resource, 0)
                total_usage = current_usages[resource] - expired_reservations
                # A negative quota limit means infinite
                if current_limits[resource] < 0:
                    LOG.debug(("Resource %(resource)s has unlimited quota "
                               "limit. It is possible to allocate %(delta)s "
                               "items."), {'resource': resource,
                                           'delta': deltas[resource]})
                    continue
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
                    self._handle_expired_reservations(context, tenant_id)

            if resources_over_limit:
                raise exceptions.OverQuota(overs=sorted(resources_over_limit))
            # Success, store the reservation
            # TODO(salv-orlando): Make expiration time configurable
            return quota_api.create_reservation(
                context, tenant_id, deltas)

    def commit_reservation(self, context, reservation_id):
        # Do not mark resource usage as dirty. If a reservation is committed,
        # then the releveant resources have been created. Usage data for these
        # resources has therefore already been marked dirty.
        quota_api.remove_reservation(context, reservation_id,
                                     set_dirty=False)

    def cancel_reservation(self, context, reservation_id):
        # Mark resource usage as dirty so the next time both actual resources
        # used and reserved will be recalculated
        quota_api.remove_reservation(context, reservation_id,
                                     set_dirty=True)

    def limit_check(self, context, tenant_id, resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param tenant_id: The tenant_id to check the quota.
        :param resources: A dictionary of the registered resources.
        :param values: A dictionary of the values to check against the
                       quota.
        """

        # Ensure no value is less than zero
        unders = [key for key, val in values.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        # Get the applicable quotas
        quotas = self._get_quotas(context, tenant_id, resources)

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items()
                 if quotas[key] >= 0 and quotas[key] < val]
        if overs:
            raise exceptions.OverQuota(overs=sorted(overs))
