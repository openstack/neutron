# Copyright 2021 Huawei, Inc.
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

from neutron_lib.api.definitions import local_ip as local_ip_apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base

from neutron.api import extensions
from neutron.api.v2 import base

PLUGIN_TYPE = 'LOCAL_IP'


class Local_ip(api_extensions.APIExtensionDescriptor):
    """Extension class supporting Local IPs."""
    api_definition = local_ip_apidef

    @classmethod
    def get_resources(cls):
        plugin = directory.get_plugin(PLUGIN_TYPE)
        collection_name = local_ip_apidef.COLLECTION_NAME.replace('_', '-')
        params = local_ip_apidef.RESOURCE_ATTRIBUTE_MAP.get(
            local_ip_apidef.COLLECTION_NAME, dict())
        controller = base.create_resource(collection_name,
                                          local_ip_apidef.RESOURCE_NAME,
                                          plugin, params,
                                          allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ext = extensions.ResourceExtension(collection_name, controller,
                                           attr_map=params)
        resources = [ext]

        for collection_name in local_ip_apidef.SUB_RESOURCE_ATTRIBUTE_MAP:
            resource_name = local_ip_apidef.LOCAL_IP_ASSOCIATION
            parent = local_ip_apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
                collection_name].get('parent')
            params = local_ip_apidef.SUB_RESOURCE_ATTRIBUTE_MAP[
                collection_name].get('parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent,
                                              allow_pagination=True,
                                              allow_sorting=True)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                attr_map=params)
            resources.append(resource)
        return resources


class LocalIPPluginBase(service_base.ServicePluginBase, metaclass=abc.ABCMeta):

    @classmethod
    def get_plugin_type(cls):
        return PLUGIN_TYPE

    def get_plugin_description(self):
        return "Local IP Service Plugin"

    @abc.abstractmethod
    def create_local_ip(self, context, local_ip):
        pass

    @abc.abstractmethod
    def update_local_ip(self, context, lip_id, local_ip):
        pass

    @abc.abstractmethod
    def get_local_ip(self, context, lip_id, fields=None):
        pass

    @abc.abstractmethod
    def get_local_ips(self, context, filters=None, fields=None,
                      sorts=None, limit=None, marker=None,
                      page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_local_ip(self, context, lip_id):
        pass

    @abc.abstractmethod
    def create_local_ip_port_association(self, context, local_ip_id,
                                         port_association):
        pass

    @abc.abstractmethod
    def get_local_ip_port_association(self, context, fixed_port_id,
                                      local_ip_id, fields=None):
        pass

    @abc.abstractmethod
    def get_local_ip_port_associations(self, context, local_ip_id,
                                       filters=None, fields=None,
                                       sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_local_ip_port_association(self, context, fixed_port_id,
                                         local_ip_id):
        pass
