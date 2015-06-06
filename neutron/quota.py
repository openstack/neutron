#    Copyright 2011 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_log import versionutils
from oslo_utils import importutils
import six
import webob

from neutron.common import exceptions
from neutron.i18n import _LI, _LW


LOG = logging.getLogger(__name__)
QUOTA_DB_MODULE = 'neutron.db.quota_db'
QUOTA_DB_DRIVER = 'neutron.db.quota_db.DbQuotaDriver'
QUOTA_CONF_DRIVER = 'neutron.quota.ConfDriver'
default_quota_items = ['network', 'subnet', 'port']

quota_opts = [
    cfg.ListOpt('quota_items',
                default=default_quota_items,
                deprecated_for_removal=True,
                help=_('Resource name(s) that are supported in quota '
                       'features. This option is now deprecated for '
                       'removal.')),
    cfg.IntOpt('default_quota',
               default=-1,
               help=_('Default number of resource allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_network',
               default=10,
               help=_('Number of networks allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_subnet',
               default=10,
               help=_('Number of subnets allowed per tenant, '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_port',
               default=50,
               help=_('Number of ports allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.StrOpt('quota_driver',
               default=QUOTA_DB_DRIVER,
               help=_('Default driver to use for quota checks')),
]
# Register the configuration options
cfg.CONF.register_opts(quota_opts, 'QUOTAS')


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
        :param tennant_id: The tenant_id to check quota.
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
            raise exceptions.OverQuota(overs=sorted(overs), quotas=quotas,
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


class QuotaEngine(object):
    """Represent the set of recognized quotas."""

    def __init__(self, quota_driver_class=None):
        """Initialize a Quota object."""

        self._resources = {}
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
                LOG.info(_LI("ConfDriver is used as quota_driver because the "
                             "loaded plugin does not support 'quotas' table."))
            if isinstance(_driver_class, six.string_types):
                _driver_class = importutils.import_object(_driver_class)
            if isinstance(_driver_class, ConfDriver):
                versionutils.report_deprecated_feature(
                    LOG, _LW("The quota driver neutron.quota.ConfDriver is "
                             "deprecated as of Liberty. "
                             "neutron.db.quota_db.DbQuotaDriver should be "
                             "used in its place"))
            self._driver = _driver_class
            LOG.info(_LI('Loaded quota_driver: %s.'), _driver_class)
        return self._driver

    def __contains__(self, resource):
        return resource in self._resources

    def register_resource(self, resource):
        """Register a resource."""
        if resource.name in self._resources:
            LOG.warn(_LW('%s is already registered.'), resource.name)
            return
        self._resources[resource.name] = resource

    def register_resource_by_name(self, resourcename):
        """Register a resource by name."""
        resource = CountableResource(resourcename, _count_resource,
                                     'quota_' + resourcename)
        self.register_resource(resource)

    def register_resources(self, resources):
        """Register a list of resources."""

        for resource in resources:
            self.register_resource(resource)

    def count(self, context, resource, *args, **kwargs):
        """Count a resource.

        For countable resources, invokes the count() function and
        returns its result.  Arguments following the context and
        resource are passed directly to the count function declared by
        the resource.

        :param context: The request context, for access checks.
        :param resource: The name of the resource, as a string.
        """

        # Get the resource
        res = self._resources.get(resource)
        if not res or not hasattr(res, 'count'):
            raise exceptions.QuotaResourceUnknown(unknown=[resource])

        return res.count(context, *args, **kwargs)

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
        # Verify that resources are managed by the quota engine
        requested_resources = set(values.keys())
        managed_resources = set([res for res in self._resources.keys()
                                 if res in requested_resources])

        # Make sure we accounted for all of them...
        unknown_resources = requested_resources - managed_resources
        if unknown_resources:
            raise exceptions.QuotaResourceUnknown(
                unknown=sorted(unknown_resources))

        return self.get_driver().limit_check(context, tenant_id,
                                             self._resources, values)

    @property
    def resources(self):
        return self._resources


QUOTAS = QuotaEngine()


def _count_resource(context, plugin, resources, tenant_id):
    count_getter_name = "get_%s_count" % resources

    # Some plugins support a count method for particular resources,
    # using a DB's optimized counting features. We try to use that one
    # if present. Otherwise just use regular getter to retrieve all objects
    # and count in python, allowing older plugins to still be supported
    try:
        obj_count_getter = getattr(plugin, count_getter_name)
        return obj_count_getter(context, filters={'tenant_id': [tenant_id]})
    except (NotImplementedError, AttributeError):
        obj_getter = getattr(plugin, "get_%s" % resources)
        obj_list = obj_getter(context, filters={'tenant_id': [tenant_id]})
        return len(obj_list) if obj_list else 0


def register_resources_from_config():
    # This operation is now deprecated. All the neutron core and extended
    # resource for which  quota limits are enforced explicitly register
    # themselves with the quota engine.
    versionutils.report_deprecated_feature(
        LOG, _LW("Registering resources to apply quota limits to using the "
                 "quota_items option is deprecated as of Liberty."
                 "Resource REST controllers should take care of registering "
                 "resources with the quota engine."))
    resources = []
    for resource_item in (set(cfg.CONF.QUOTAS.quota_items) -
                          set(default_quota_items)):
        resources.append(CountableResource(resource_item, _count_resource,
                                           'quota_' + resource_item))
    QUOTAS.register_resources(resources)


register_resources_from_config()
