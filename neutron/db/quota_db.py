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

import sqlalchemy as sa

from neutron.common import exceptions
from neutron.db import model_base
from neutron.db import models_v2


class Quota(model_base.BASEV2, models_v2.HasId):
    """Represent a single quota override for a tenant.

    If there is no row for a given tenant id and resource, then the
    default for the quota class is used.
    """
    tenant_id = sa.Column(sa.String(255), index=True)
    resource = sa.Column(sa.String(255))
    limit = sa.Column(sa.Integer)


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
        q_qry = context.session.query(Quota).filter_by(tenant_id=tenant_id)
        tenant_quota.update((q['resource'], q['limit']) for q in q_qry)

        return tenant_quota

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        """Delete the quota entries for a given tenant_id.

        Atfer deletion, this tenant will use default quota values in conf.
        """
        with context.session.begin():
            tenant_quotas = context.session.query(Quota)
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

        for quota in context.session.query(Quota):
            tenant_id = quota['tenant_id']

            # avoid setdefault() because only want to copy when actually req'd
            tenant_quota = all_tenant_quotas.get(tenant_id)
            if tenant_quota is None:
                tenant_quota = tenant_default.copy()
                tenant_quota['tenant_id'] = tenant_id
                all_tenant_quotas[tenant_id] = tenant_quota

            tenant_quota[quota['resource']] = quota['limit']

        return all_tenant_quotas.values()

    @staticmethod
    def update_quota_limit(context, tenant_id, resource, limit):
        with context.session.begin():
            tenant_quota = context.session.query(Quota).filter_by(
                tenant_id=tenant_id, resource=resource).first()

            if tenant_quota:
                tenant_quota.update({'limit': limit})
            else:
                tenant_quota = Quota(tenant_id=tenant_id,
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
