# Copyright (c) 2019 Red Hat, Inc.
# All rights reserved.
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

import abc
import itertools

from neutron_lib.api.definitions import l3_conntrack_helper as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_consts
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
import six

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.conf.extensions import conntrack_helper as cth_conf


cth_conf.register_conntrack_helper_opts()


class L3_conntrack_helper(api_extensions.APIExtensionDescriptor):
    """Router conntrack helpers API extension."""

    api_definition = apidef

    @classmethod
    def get_plugin_interface(cls):
        return ConntrackHelperPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        special_mappings = {'routers': 'router'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, itertools.chain(
                apidef.RESOURCE_ATTRIBUTE_MAP,
                apidef.SUB_RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                plural_mappings,
                apidef.RESOURCE_ATTRIBUTE_MAP,
                plugin_consts.CONNTRACKHELPER,
                translate_name=True,
                allow_bulk=True)

        plugin = directory.get_plugin(plugin_consts.CONNTRACKHELPER)

        parent = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
            apidef.COLLECTION_NAME].get('parent')
        params = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[apidef.COLLECTION_NAME].get(
            'parameters')

        controller = base.create_resource(apidef.COLLECTION_NAME,
                                          apidef.RESOURCE_NAME,
                                          plugin, params,
                                          allow_bulk=True,
                                          parent=parent,
                                          allow_pagination=True,
                                          allow_sorting=True)

        resource = extensions.ResourceExtension(
            apidef.COLLECTION_NAME,
            controller, parent,
            attr_map=params)
        resources.append(resource)

        return resources


@six.add_metaclass(abc.ABCMeta)
class ConntrackHelperPluginBase(service_base.ServicePluginBase):

    path_prefix = apidef.API_PREFIX

    @classmethod
    def get_plugin_type(cls):
        return plugin_consts.CONNTRACKHELPER

    def get_plugin_description(self):
        return "Conntrack Helper Service Plugin"

    @abc.abstractmethod
    def create_router_conntrack_helper(self, context, router_id,
                                       conntrack_helper):
        pass

    @abc.abstractmethod
    def update_router_conntrack_helper(self, context, id, router_id,
                                       conntrack_helper):
        pass

    @abc.abstractmethod
    def get_router_conntrack_helper(self, context, id, router_id, fields=None):
        pass

    @abc.abstractmethod
    def get_router_conntrack_helpers(self, context, router_id=None,
                                     filters=None, fields=None, sorts=None,
                                     limit=None, marker=None,
                                     page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_router_conntrack_helper(self, context, id, router_id):
        pass
