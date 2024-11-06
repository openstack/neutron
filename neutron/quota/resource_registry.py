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

import functools

from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.quota import resource

LOG = log.getLogger(__name__)


# Wrappers for easing access to the ResourceRegistry singleton


def register_resource(resource):
    ResourceRegistry.get_instance().register_resource(resource)


def register_resource_by_name(resource_name, plural_name=None):
    ResourceRegistry.get_instance().register_resource_by_name(
        resource_name, plural_name)


def get_all_resources():
    return ResourceRegistry.get_instance().resources


def unregister_all_resources():
    if not ResourceRegistry._instance:
        return
    return ResourceRegistry.get_instance().unregister_resources()


def get_resource(resource_name):
    return ResourceRegistry.get_instance().get_resource(resource_name)


def is_tracked(resource_name):
    return ResourceRegistry.get_instance().is_tracked(resource_name)


# auxiliary functions and decorators


def set_resources_dirty(context):
    """Sets the dirty bit for resources with usage changes.

    This routine scans all registered resources, and, for those whose
    dirty status is True, sets the dirty bit to True in the database
    for the appropriate tenants.

    :param context: a Neutron request context with a DB session
    """
    if not cfg.CONF.QUOTAS.track_quota_usage:
        return

    for res in get_all_resources().values():
        with db_api.CONTEXT_WRITER.using(context):
            if is_tracked(res.name) and res.dirty:
                res.mark_dirty(context)


def resync_resource(context, resource_name, tenant_id):
    if not cfg.CONF.QUOTAS.track_quota_usage:
        return

    if is_tracked(resource_name):
        res = get_resource(resource_name)
        # If the resource is tracked count supports the resync_usage parameter
        res.resync(context, tenant_id)


def mark_resources_dirty(f):
    """Decorator for functions which alter resource usage.

    This decorator ensures set_resource_dirty is invoked after completion
    of the decorated function.
    """

    @functools.wraps(f)
    def wrapper(_self, context, *args, **kwargs):
        ret_val = f(_self, context, *args, **kwargs)
        set_resources_dirty(context)
        return ret_val

    return wrapper


class tracked_resources:
    """Decorator for specifying resources for which usage should be tracked.

    A plugin class can use this decorator to specify for which resources
    usage info should be tracked into an appropriate table rather than being
    explicitly counted.
    """

    def __init__(self, override=False, **kwargs):
        self._tracked_resources = kwargs
        self._override = override

    def __call__(self, f):

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            registry = ResourceRegistry.get_instance()
            for resource_name in self._tracked_resources:
                registry.set_tracked_resource(
                    resource_name,
                    self._tracked_resources[resource_name],
                    self._override)
            return f(*args, **kwargs)

        return wrapper


class ResourceRegistry:
    """Registry for resource subject to quota limits.

    This class keeps track of Neutron resources for which quota limits are
    enforced, regardless of whether their usage is being tracked or counted.

    For tracked-usage resources, that is to say those resources for which
    there are usage counters which are kept in sync with the actual number
    of rows in the database, this class allows the plugin to register their
    names either explicitly or through the @tracked_resources decorator,
    which should preferably be applied to the __init__ method of the class.
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._resources = {}
        # Map usage tracked resources to the correspondent db model class
        self._tracked_resource_mappings = {}

    def __contains__(self, resource):
        return resource in self._resources

    def _create_resource_instance(self, resource_name, plural_name):
        """Factory function for quota Resource.

        This routine returns a resource instance of the appropriate type
        according to system configuration.

        If QUOTAS.track_quota_usage is True, and there is a model mapping for
        the current resource, this function will return an instance of
        AccountedResource; otherwise an instance of CountableResource.
        """

        if (not cfg.CONF.QUOTAS.track_quota_usage or
                resource_name not in self._tracked_resource_mappings):
            LOG.info("Creating instance of CountableResource for "
                     "resource:%s", resource_name)
            return resource.CountableResource(
                resource_name, resource._count_resource,
                'quota_%s' % resource_name)
        LOG.info("Creating instance of TrackedResource for resource:%s",
                 resource_name)
        return resource.TrackedResource(
            resource_name, self._tracked_resource_mappings[resource_name],
            'quota_%s' % resource_name)

    def set_tracked_resource(self, resource_name, model_class, override=False):
        # Do not do anything if tracking is disabled by config
        if not cfg.CONF.QUOTAS.track_quota_usage:
            return

        if isinstance(self._resources.get(resource_name),
                      resource.CountableResource):
            raise RuntimeError(_("Resource %s is already registered as a "
                                 "countable resource.") % resource_name)
        current_model_class = self._tracked_resource_mappings.setdefault(
            resource_name, model_class)

        # Check whether setdefault also set the entry in the dict
        if current_model_class != model_class:
            LOG.debug("A model class is already defined for %(resource)s: "
                      "%(current_model_class)s. Override:%(override)s",
                      {'resource': resource_name,
                       'current_model_class': current_model_class,
                       'override': override})
            if override:
                self._tracked_resource_mappings[resource_name] = model_class
        LOG.debug("Tracking information for resource: %s configured",
                  resource_name)

    def is_tracked(self, resource_name):
        """Find out if a resource if tracked or not.

        :param resource_name: name of the resource.
        :returns: True if resource_name is registered and tracked, otherwise
                 False. Please note that here when False it returned it
                 simply means that resource_name is not a TrackedResource
                 instance, it does not necessarily mean that the resource
                 is not registered.
        """
        return resource_name in self._tracked_resource_mappings

    def register_resource(self, resource):
        if resource.name in self._resources:
            LOG.warning('%s is already registered', resource.name)
        if resource.name in self._tracked_resource_mappings:
            resource.register_events()
        self._resources[resource.name] = resource

    def register_resources(self, resources):
        for res in resources:
            self.register_resource(res)

    def register_resource_by_name(self, resource_name,
                                  plural_name=None):
        """Register a resource by name."""
        resource = self._create_resource_instance(
            resource_name, plural_name)
        self.register_resource(resource)

    def unregister_resources(self):
        """Unregister all resources."""
        for (res_name, res) in self._resources.items():
            if res_name in self._tracked_resource_mappings:
                res.unregister_events()
        self._resources.clear()
        self._tracked_resource_mappings.clear()

    def get_resource(self, resource_name):
        """Return a resource given its name.

        :returns: The resource instance or None if the resource is not found
        """
        return self._resources.get(resource_name)

    @property
    def resources(self):
        return self._resources
