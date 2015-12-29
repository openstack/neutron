# Copyright (c) 2015 Mirantis, Inc.
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

from oslo_log import log

from neutron._i18n import _LI, _LW
from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import router
from neutron import manager
from neutron.pecan_wsgi.controllers import resource as res_ctrl
from neutron.pecan_wsgi.controllers import utils
from neutron import policy
from neutron.quota import resource_registry

LOG = log.getLogger(__name__)


def _plugin_for_resource(collection):
    if collection in router.RESOURCES.values():
        # this is a core resource, return the core plugin
        return manager.NeutronManager.get_plugin()
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    # Multiple extensions can map to the same resource. This happens
    # because of 'attribute' extensions. These extensions may come from
    # various plugins and only one of them is the primary one responsible
    # for the resource while the others just append fields to the response
    # (e.g. timestamps). So we have to find the plugin that supports the
    # extension and has the getter for the collection.
    ext_res_mappings = dict((ext.get_alias(), collection) for
                            ext in ext_mgr.extensions.values() if
                            collection in ext.get_extended_resources('2.0'))
    LOG.debug("Extension mappings for: %(collection)s: %(aliases)s",
              {'collection': collection, 'aliases': ext_res_mappings.keys()})
    # find the plugin that supports this extension
    for plugin in ext_mgr.plugins.values():
        ext_aliases = ext_mgr.get_plugin_supported_extension_aliases(plugin)
        for alias in ext_aliases:
            if (alias in ext_res_mappings and
                    hasattr(plugin, 'get_%s' % collection)):
                # This plugin implements this resource
                return plugin
    LOG.warning(_LW("No plugin found for: %s"), collection)


def _handle_plurals(collection):
    resource = attributes.PLURALS.get(collection)
    if not resource:
        if collection.endswith('ies'):
            resource = "%sy" % collection[:-3]
        else:
            resource = collection[:-1]
    attributes.PLURALS[collection] = resource
    return resource


def initialize_legacy_extensions(legacy_extensions):
    leftovers = []
    for ext in legacy_extensions:
        ext_resources = ext.get_resources()
        for ext_resource in ext_resources:
            controller = ext_resource.controller.controller
            collection = ext_resource.collection
            resource = _handle_plurals(collection)
            if manager.NeutronManager.get_plugin_for_resource(resource):
                continue
            # NOTE(blogan): It is possible that a plugin is tied to the
            # collection rather than the resource.  An example of this is
            # the auto_allocated_topology extension.  All other extensions
            # created their legacy resources with the collection/plural form
            # except auto_allocated_topology.  Making that extension
            # conform with the rest of extensions could invalidate this, but
            # it's possible out of tree extensions did the same thing.  Since
            # the auto_allocated_topology resources have already been loaded
            # we definitely don't want to load them up with shim controllers,
            # so this will prevent that.
            if manager.NeutronManager.get_plugin_for_resource(collection):
                continue
            # NOTE(blogan): Since this does not have a plugin, we know this
            # extension has not been loaded and controllers for its resources
            # have not been created nor set.
            leftovers.append((collection, resource, controller))
    # NOTE(blogan): at this point we have leftover extensions that never
    # had a controller set which will force us to use shim controllers.
    for leftover in leftovers:
        shim_controller = utils.ShimCollectionsController(*leftover)
        manager.NeutronManager.set_controller_for_resource(
            shim_controller.collection, shim_controller)


def initialize_all():
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    ext_mgr.extend_resources("2.0", attributes.RESOURCE_ATTRIBUTE_MAP)
    # At this stage we have a fully populated resource attribute map;
    # build Pecan controllers and routes for every resource (both core
    # and extensions)
    pecanized_exts = [ext for ext in ext_mgr.extensions.values() if
                      hasattr(ext, 'get_pecan_controllers')]
    non_pecanized_exts = set(ext_mgr.extensions.values()) - set(pecanized_exts)
    pecan_controllers = {}
    for ext in pecanized_exts:
        LOG.info(_LI("Extension %s is pecan-aware. Fetching resources "
                     "and controllers"), ext.get_name())
        controllers = ext.get_pecan_controllers()
        # controllers is actually a list of pairs where the first element is
        # the collection name and the second the actual controller
        for (collection, coll_controller) in controllers:
            pecan_controllers[collection] = coll_controller

    for collection in attributes.RESOURCE_ATTRIBUTE_MAP:
        resource = _handle_plurals(collection)

        plugin = _plugin_for_resource(collection)
        if plugin:
            manager.NeutronManager.set_plugin_for_resource(
                resource, plugin)
        else:
            LOG.warning(_LW("No plugin found for resource:%s. API calls "
                            "may not be correctly dispatched"), resource)

        controller = pecan_controllers.get(collection)
        if not controller:
            LOG.debug("Building controller for resource:%s", resource)
            controller = res_ctrl.CollectionsController(collection, resource)
        else:
            LOG.debug("There are already controllers for resource: %s",
                      resource)

        manager.NeutronManager.set_controller_for_resource(
            controller.collection, controller)
        LOG.info(_LI("Added controller for resource %(resource)s "
                     "via URI path segment:%(collection)s"),
                 {'resource': resource,
                  'collection': collection})

    initialize_legacy_extensions(non_pecanized_exts)

    # NOTE(salv-orlando): If you are care about code quality, please read below
    # Hackiness is strong with the piece of code below. It is used for
    # populating resource plurals and registering resources with the quota
    # engine, but the method it calls were not conceived with this aim.
    # Therefore it only leverages side-effects from those methods. Moreover,
    # as it is really not advisable to load an instance of
    # neutron.api.v2.router.APIRouter just to register resources with the
    # quota  engine, core resources are explicitly registered here.
    # TODO(salv-orlando): The Pecan WSGI support should provide its own
    # solution to manage resource plurals and registration of resources with
    # the quota engine
    for resource in router.RESOURCES.keys():
        resource_registry.register_resource_by_name(resource)
    for ext in ext_mgr.extensions.values():
        # make each extension populate its plurals
        if hasattr(ext, 'get_resources'):
            ext.get_resources()
        if hasattr(ext, 'get_extended_resources'):
            ext.get_extended_resources('v2.0')
    # Certain policy checks require that the extensions are loaded
    # and the RESOURCE_ATTRIBUTE_MAP populated before they can be
    # properly initialized. This can only be claimed with certainty
    # once this point in the code has been reached. In the event
    # that the policies have been initialized before this point,
    # calling reset will cause the next policy check to
    # re-initialize with all of the required data in place.
    policy.reset()
