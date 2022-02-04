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

from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.conf import quota
from neutron.quota import resource_registry

LOG = logging.getLogger(__name__)


# Register the configuration options
quota.register_quota_opts(quota.core_quota_opts)


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
            if isinstance(_driver_class, str):
                _driver_class = importutils.import_object(_driver_class)
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

    def quota_limit_check(self, context, project_id, **deltas):
        return self.get_driver().quota_limit_check(
            context, project_id, resource_registry.get_all_resources(), deltas)


QUOTAS = QuotaEngine.get_instance()
