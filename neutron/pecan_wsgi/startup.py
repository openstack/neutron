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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import router
from neutron.i18n import _LI, _LW
from neutron import manager
from neutron.pecan_wsgi.controllers import root
from neutron import policy
from neutron.quota import resource_registry

LOG = log.getLogger(__name__)


def _plugin_for_resource(collection):
    if collection in router.RESOURCES.values():
        # this is a core resource, return the core plugin
        return manager.NeutronManager.get_plugin()
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    # Multiple extensions can map to the same resource. This happens
    # because of 'attribute' extensions. Due to the way in which neutron
    # plugins and request dispatching is constructed, it is impossible for
    # the same resource to be handled by more than one plugin. Therefore
    # all the extensions mapped to a given resource will necessarily be
    # implemented by the same plugin.
    ext_res_mappings = dict((ext.get_alias(), collection) for
                            ext in ext_mgr.extensions.values() if
                            collection in ext.get_extended_resources('2.0'))
    LOG.debug("Extension mappings for: %(collection)s: %(aliases)s",
              {'collection': collection, 'aliases': ext_res_mappings.keys()})
    # find the plugin that supports this extension
    for plugin in ext_mgr.plugins.values():
        ext_aliases = getattr(plugin, 'supported_extension_aliases', [])
        for alias in ext_aliases:
            if alias in ext_res_mappings:
                # This plugin implements this resource
                return plugin
    LOG.warn(_LW("No plugin found for:%s"), collection)


def _handle_plurals(collection):
    resource = attributes.PLURALS.get(collection)
    if not resource:
        if collection.endswith('ies'):
            resource = "%sy" % collection[:-3]
        else:
            resource = collection[:-1]
    attributes.PLURALS[collection] = resource
    return resource


def initialize_all():
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    ext_mgr.extend_resources("2.0", attributes.RESOURCE_ATTRIBUTE_MAP)
    # At this stage we have a fully populated resource attribute map;
    # build Pecan controllers and routes for every resource (both core
    # and extensions)
    pecanized_exts = [ext for ext in ext_mgr.extensions.values() if
                      hasattr(ext, 'get_pecan_controllers')]
    pecan_controllers = {}
    for ext in pecanized_exts:
        LOG.debug("Extension %s is pecan-enabled. Fetching resources "
                  "and controllers", ext.get_name())
        controllers = ext.get_pecan_controllers()
        # controllers is actually a list of pairs where the first element is
        # the collection name and the second the actual controller
        for (collection, coll_controller) in controllers:
            pecan_controllers[collection] = coll_controller

    for collection in attributes.RESOURCE_ATTRIBUTE_MAP:
        if collection not in pecan_controllers:
            resource = _handle_plurals(collection)
            LOG.debug("Building controller for resource:%s", resource)
            plugin = _plugin_for_resource(collection)
            if plugin:
                manager.NeutronManager.set_plugin_for_resource(
                    resource, plugin)
            controller = root.CollectionsController(collection, resource)
            manager.NeutronManager.set_controller_for_resource(
                collection, controller)
            LOG.info(_LI("Added controller for resource %(resource)s "
                         "via URI path segment:%(collection)s"),
                     {'resource': resource,
                      'collection': collection})
        else:
            LOG.debug("There are already controllers for resource:%s",
                      resource)

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
