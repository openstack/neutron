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

"""Quotas for instances, volumes, and floating ips."""

import sys

from neutron_lib import exceptions as lib_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_log import versionutils
from oslo_utils import importutils
import six
import webob

from neutron._i18n import _
from neutron.common import exceptions
from neutron.conf import quota
from neutron.db.quota import api as quota_api
from neutron.quota import resource_registry

LOG = logging.getLogger(__name__)
QUOTA_DB_MODULE = quota.QUOTA_DB_MODULE
QUOTA_DB_DRIVER = quota.QUOTA_DB_DRIVER
QUOTA_CONF_DRIVER = quota.QUOTA_CONF_DRIVER


# Register the configuration options
quota.register_quota_opts(quota.core_quota_opts)


class ConfDriver(object):
    """Configuration driver.

    Driver to perform necessary checks to enforce quotas and obtain
    quota information. The default driver utilizes the default values
    in neutron.conf.
    """

    def _get_quotas(self, context, resources):
        """Get quotas.

        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resources.
        """

        quotas = {}
        for resource in resources.values():
            quotas[resource.name] = resource.default
        return quotas

    def limit_check(self, context, tenant_id,
                    resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param tenant_id: The tenant_id to check quota.
        :param resources: A dictionary of the registered resources.
        :param values: A dictionary of the values to check against the
                       quota.
        """
        # Ensure no value is less than zero
        unders = [key for key, val in values.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        # Get the applicable quotas
        quotas = self._get_quotas(context, resources)

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items()
                 if quotas[key] >= 0 and quotas[key] < val]
        if overs:
            raise lib_exc.OverQuota(overs=sorted(overs), quotas=quotas,
                                    usages={})

    @staticmethod
    def get_tenant_quotas(context, resources, tenant_id):
        quotas = {}
        sub_resources = dict((k, v) for k, v in resources.items())
        for resource in sub_resources.values():
            quotas[resource.name] = resource.default
        return quotas

    @staticmethod
    def get_all_quotas(context, resources):
        return []

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        msg = _('Access to this resource was denied.')
        raise webob.exc.HTTPForbidden(msg)

    @staticmethod
    def update_quota_limit(context, tenant_id, resource, limit):
        msg = _('Access to this resource was denied.')
        raise webob.exc.HTTPForbidden(msg)

    def make_reservation(self, context, tenant_id, resources, deltas, plugin):
        """This driver does not support reservations.

        This routine is provided for backward compatibility purposes with
        the API controllers which have now been adapted to make reservations
        rather than counting resources and checking limits - as this
        routine ultimately does.
        """
        for resource in deltas.keys():
            count = QUOTAS.count(context, resource, plugin, tenant_id)
            total_use = deltas.get(resource, 0) + count
            deltas[resource] = total_use

        self.limit_check(
            context,
            tenant_id,
            resource_registry.get_all_resources(),
            deltas)
        # return a fake reservation - the REST controller expects it
        return quota_api.ReservationInfo('fake', None, None, None)

    def commit_reservation(self, context, reservation_id):
        """This is a noop as this driver does not support reservations."""

    def cancel_reservation(self, context, reservation_id):
        """This is a noop as this driver does not support reservations."""


class QuotaEngine(object):
    """Represent the set of recognized quotas."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = cls()
        return cls._instance

    def __init__(self, quota_driver_class=None):
        """Initialize a Quota object."""
        self._driver = None
        self._driver_class = quota_driver_class

    def get_driver(self):
        if self._driver is None:
            _driver_class = (self._driver_class or
                             cfg.CONF.QUOTAS.quota_driver)
            if (_driver_class == QUOTA_DB_DRIVER and
                    QUOTA_DB_MODULE not in sys.modules):
                # If quotas table is not loaded, force config quota driver.
                _driver_class = QUOTA_CONF_DRIVER
                LOG.info("ConfDriver is used as quota_driver because the "
                         "loaded plugin does not support 'quotas' table.")
            if isinstance(_driver_class, six.string_types):
                _driver_class = importutils.import_object(_driver_class)
            if isinstance(_driver_class, ConfDriver):
                versionutils.report_deprecated_feature(
                    LOG, ("The quota driver neutron.quota.ConfDriver is "
                          "deprecated as of Liberty. "
                          "neutron.db.quota.driver.DbQuotaDriver should "
                          "be used in its place"))
            self._driver = _driver_class
            LOG.info('Loaded quota_driver: %s.', _driver_class)
        return self._driver

    def count(self, context, resource_name, *args, **kwargs):
        """Count a resource.

        For countable resources, invokes the count() function and
        returns its result.  Arguments following the context and
        resource are passed directly to the count function declared by
        the resource.

        :param context: The request context, for access checks.
        :param resource_name: The name of the resource, as a string.
        """

        # Get the resource
        res = resource_registry.get_resource(resource_name)
        if not res or not hasattr(res, 'count'):
            raise exceptions.QuotaResourceUnknown(unknown=[resource_name])

        return res.count(context, *args, **kwargs)

    def make_reservation(self, context, tenant_id, deltas, plugin):
        # Verify that resources are managed by the quota engine
        # Ensure no value is less than zero
        unders = [key for key, val in deltas.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        requested_resources = set(deltas.keys())
        all_resources = resource_registry.get_all_resources()
        managed_resources = set([res for res in all_resources.keys()
                                 if res in requested_resources])
        # Make sure we accounted for all of them...
        unknown_resources = requested_resources - managed_resources

        if unknown_resources:
            raise exceptions.QuotaResourceUnknown(
                unknown=sorted(unknown_resources))
        # FIXME(salv-orlando): There should be no reason for sending all the
        # resource in the registry to the quota driver, but as other driver
        # APIs request them, this will be sorted out with a different patch.
        return self.get_driver().make_reservation(
            context,
            tenant_id,
            all_resources,
            deltas,
            plugin)

    def commit_reservation(self, context, reservation_id):
        self.get_driver().commit_reservation(context, reservation_id)

    def cancel_reservation(self, context, reservation_id):
        self.get_driver().cancel_reservation(context, reservation_id)

    def limit_check(self, context, tenant_id, **values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.  The
        values to check are given as keyword arguments, where the key
        identifies the specific quota limit to check, and the value is
        the proposed value.

        This method will raise a QuotaResourceUnknown exception if a
        given resource is unknown or if it is not a countable resource.

        If any of the proposed values exceeds the respective quota defined
        for the tenant, an OverQuota exception will be raised.
        The exception will include a sorted list with the resources
        which exceed the quota limit. Otherwise, the method returns nothing.

        :param context: Request context
        :param tenant_id: Tenant for which the quota limit is being checked
        :param values: Dict specifying requested deltas for each resource
        """
        # TODO(salv-orlando): Deprecate calls to this API
        # Verify that resources are managed by the quota engine
        requested_resources = set(values.keys())
        managed_resources = set([res for res in
                                 resource_registry.get_all_resources()
                                 if res in requested_resources])

        # Make sure we accounted for all of them...
        unknown_resources = requested_resources - managed_resources
        if unknown_resources:
            raise exceptions.QuotaResourceUnknown(
                unknown=sorted(unknown_resources))

        return self.get_driver().limit_check(
            context, tenant_id, resource_registry.get_all_resources(), values)


QUOTAS = QuotaEngine.get_instance()
