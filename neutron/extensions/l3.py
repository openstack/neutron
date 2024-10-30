# Copyright 2012 VMware, Inc.
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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api import extensions
from neutron_lib.plugins import constants

from neutron.api.v2 import resource_helper
from neutron.conf import quota


# Register the configuration options
quota.register_quota_opts(quota.l3_quota_opts)


class L3(extensions.APIExtensionDescriptor):
    api_definition = l3_apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, l3_apidef.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings, l3_apidef.RESOURCE_ATTRIBUTE_MAP,
            constants.L3, action_map=l3_apidef.ACTION_MAP,
            register_quota=True)


class RouterPluginBase(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_router(self, context, router):
        pass

    @abc.abstractmethod
    def update_router(self, context, id, router):
        pass

    @abc.abstractmethod
    def get_router(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_router(self, context, id):
        pass

    @abc.abstractmethod
    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def add_router_interface(self, context, router_id, interface_info=None):
        pass

    @abc.abstractmethod
    def remove_router_interface(self, context, router_id, interface_info):
        pass

    @abc.abstractmethod
    def create_floatingip(self, context, floatingip):
        pass

    @abc.abstractmethod
    def update_floatingip(self, context, id, floatingip):
        pass

    @abc.abstractmethod
    def get_floatingip(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_floatingip(self, context, id):
        pass

    @abc.abstractmethod
    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        pass

    def get_routers_count(self, context, filters=None):
        raise NotImplementedError()

    def get_floatingips_count(self, context, filters=None):
        raise NotImplementedError()
