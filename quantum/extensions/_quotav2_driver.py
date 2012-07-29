# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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

from quantum.common import exceptions
from quantum.extensions import _quotav2_model as quotav2_model


class DbQuotaDriver(object):
    """
    Driver to perform necessary checks to enforce quotas and obtain
    quota information.  The default driver utilizes the local
    database.
    """

    @staticmethod
    def get_tenant_quotas(context, resources, tenant_id):
        """
        Given a list of resources, retrieve the quotas for the given
        tenant.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param tenant_id: The ID of the tenant to return quotas for.
        :return dict: from resource name to dict of name and limit
        """

        quotas = {}
        tenant_quotas = context.session.query(
            quotav2_model.Quota).filter_by(tenant_id=tenant_id).all()
        tenant_quotas_dict = {}
        for _quota in tenant_quotas:
            tenant_quotas_dict[_quota['resource']] = _quota['limit']
        for key, resource in resources.items():
            quotas[key] = dict(
                name=key,
                limit=tenant_quotas_dict.get(key, resource.default))
        return quotas

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        """Delete the quota entries for a given tenant_id.

        Atfer deletion, this tenant will use default quota values in conf.
        """
        with context.session.begin():
            tenant_quotas = context.session.query(
                quotav2_model.Quota).filter_by(tenant_id=tenant_id).all()
            for quota in tenant_quotas:
                context.session.delete(quota)

    @staticmethod
    def get_all_quotas(context, resources):
        """
        Given a list of resources, retrieve the quotas for the all
        tenants.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return quotas: list of dict of tenant_id:, resourcekey1:
        resourcekey2: ...
        """

        _quotas = context.session.query(quotav2_model.Quota).all()
        quotas = {}
        tenant_quotas_dict = {}
        for _quota in _quotas:
            tenant_id = _quota['tenant_id']
            if tenant_id not in quotas:
                quotas[tenant_id] = {'tenant_id': tenant_id}
            tenant_quotas_dict = quotas[tenant_id]
            tenant_quotas_dict[_quota['resource']] = _quota['limit']

        # we complete the quotas according to input resources
        for tenant_quotas_dict in quotas.itervalues():
            for key, resource in resources.items():
                tenant_quotas_dict[key] = tenant_quotas_dict.get(
                    key, resource.default)
        return quotas.itervalues()

    def _get_quotas(self, context, tenant_id, resources, keys):
        """
        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param tenant_id: the tenant_id to check quota.
        :param resources: A dictionary of the registered resources.
        :param keys: A list of the desired quotas to retrieve.

        """

        desired = set(keys)
        sub_resources = dict((k, v) for k, v in resources.items()
                             if k in desired)

        # Make sure we accounted for all of them...
        if len(keys) != len(sub_resources):
            unknown = desired - set(sub_resources.keys())
            raise exceptions.QuotaResourceUnknown(unknown=sorted(unknown))

        # Grab and return the quotas (without usages)
        quotas = DbQuotaDriver.get_tenant_quotas(
            context, sub_resources, context.tenant_id)

        return dict((k, v['limit']) for k, v in quotas.items())

    def limit_check(self, context, tenant_id, resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        This method will raise a QuotaResourceUnknown exception if a
        given resource is unknown or if it is not a simple limit
        resource.

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
        quotas = self._get_quotas(context, tenant_id, resources, values.keys())

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items()
                 if quotas[key] >= 0 and quotas[key] < val]
        if overs:
            raise exceptions.OverQuota(overs=sorted(overs))
