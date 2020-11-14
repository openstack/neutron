# Copyright 2022 Troila
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

from neutron_lib.api.definitions import l3_ndp_proxy as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_consts
from neutron_lib.services import base as service_base

from neutron.api.v2 import resource_helper


class L3_ndp_proxy(api_extensions.APIExtensionDescriptor):
    """L3 NDP Proxy API extension"""

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        special_mappings = {'ndp_proxies': 'ndp_proxy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, apidef.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
                plural_mappings,
                apidef.RESOURCE_ATTRIBUTE_MAP,
                plugin_consts.NDPPROXY,
                translate_name=True,
                allow_bulk=True)


class NDPProxyBase(service_base.ServicePluginBase):

    @classmethod
    def get_plugin_type(cls):
        return plugin_consts.NDPPROXY

    def get_plugin_description(self):
        return "NDP Proxy Service Plugin"

    @abc.abstractmethod
    def create_ndp_proxy(self, context, ndp_proxy):
        pass

    @abc.abstractmethod
    def update_ndp_proxy(self, context, id, ndp_proxy):
        pass

    @abc.abstractmethod
    def get_ndp_proxy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ndp_proxies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_ndp_proxy(self, context, id):
        pass
