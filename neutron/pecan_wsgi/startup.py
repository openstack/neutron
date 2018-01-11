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

from neutron_lib.api import attributes
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager
from neutron.pecan_wsgi.controllers import resource as res_ctrl
from neutron.pecan_wsgi.controllers import utils
from neutron import policy
from neutron.quota import resource_registry


# NOTE(blogan): This currently already exists in neutron.api.v2.router but
# instead of importing that module and creating circular imports elsewhere,
# it's easier to just copy it here.  The likelihood of it needing to be changed
# are slim to none.
RESOURCES = {'network': 'networks',
             'subnet': 'subnets',
             'subnetpool': 'subnetpools',
             'port': 'ports'}


def initialize_all():
    manager.init()
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    ext_mgr.extend_resources("2.0", attributes.RESOURCES)
    # At this stage we have a fully populated resource attribute map;
    # build Pecan controllers and routes for all core resources
    plugin = directory.get_plugin()
    for resource, collection in RESOURCES.items():
        resource_registry.register_resource_by_name(resource)
        new_controller = res_ctrl.CollectionsController(collection, resource,
                                                        plugin=plugin)
        manager.NeutronManager.set_controller_for_resource(
            collection, new_controller)
        manager.NeutronManager.set_plugin_for_resource(collection, plugin)

    pecanized_resources = ext_mgr.get_pecan_resources()
    for pec_res in pecanized_resources:
        manager.NeutronManager.set_controller_for_resource(
            pec_res.collection, pec_res.controller)
        manager.NeutronManager.set_plugin_for_resource(
            pec_res.collection, pec_res.plugin)

    # Now build Pecan Controllers and routes for all extensions
    resources = ext_mgr.get_resources()
    # Extensions controller is already defined, we don't need it.
    resources.pop(0)
    for ext_res in resources:
        path_prefix = ext_res.path_prefix.strip('/')
        collection = ext_res.collection
        # Retrieving the parent resource.  It is expected the format of
        # the parent resource to be:
        # {'collection_name': 'name-of-collection',
        #  'member_name': 'name-of-resource'}
        # collection_name does not appear to be used in the legacy code
        # inside the controller logic, so we can assume we do not need it.
        parent = ext_res.parent or {}
        parent_resource = parent.get('member_name')
        collection_key = collection
        if parent_resource:
            collection_key = '/'.join([parent_resource, collection])
        collection_actions = ext_res.collection_actions
        member_actions = ext_res.member_actions
        if manager.NeutronManager.get_controller_for_resource(collection_key):
            # This is a collection that already has a pecan controller, we
            # do not need to do anything else
            continue
        legacy_controller = getattr(ext_res.controller, 'controller',
                                    ext_res.controller)
        new_controller = None
        if isinstance(legacy_controller, base.Controller):
            resource = legacy_controller.resource
            plugin = legacy_controller.plugin
            attr_info = legacy_controller.attr_info
            member_actions = legacy_controller.member_actions
            pagination = legacy_controller.allow_pagination
            sorting = legacy_controller.allow_sorting
            # NOTE(blogan): legacy_controller and ext_res both can both have
            # member_actions.  the member_actions for ext_res are strictly for
            # routing, while member_actions for legacy_controller are used for
            # handling the request once the routing has found the controller.
            # They're always the same so we will just use the ext_res
            # member_action.
            new_controller = res_ctrl.CollectionsController(
                collection, resource, resource_info=attr_info,
                parent_resource=parent_resource, member_actions=member_actions,
                plugin=plugin, allow_pagination=pagination,
                allow_sorting=sorting, collection_actions=collection_actions)
            # new_controller.collection has replaced hyphens with underscores
            manager.NeutronManager.set_plugin_for_resource(
                new_controller.collection, plugin)
            if path_prefix:
                manager.NeutronManager.add_resource_for_path_prefix(
                    collection, path_prefix)
        else:
            new_controller = utils.ShimCollectionsController(
                collection, None, legacy_controller,
                collection_actions=collection_actions,
                member_actions=member_actions,
                action_status=ext_res.controller.action_status,
                collection_methods=ext_res.collection_methods)

        manager.NeutronManager.set_controller_for_resource(
            collection_key, new_controller)

    # Certain policy checks require that the extensions are loaded
    # and the RESOURCE_ATTRIBUTE_MAP populated before they can be
    # properly initialized. This can only be claimed with certainty
    # once this point in the code has been reached. In the event
    # that the policies have been initialized before this point,
    # calling reset will cause the next policy check to
    # re-initialize with all of the required data in place.
    policy.reset()
