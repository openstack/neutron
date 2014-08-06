# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager
from neutron import quota


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'net_partitions': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'description': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': '',
                        'validate': {'type:string_or_none': None}},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
}


class Netpartition(object):
    """Extension class supporting net_partition.
    """

    @classmethod
    def get_name(cls):
        return "NetPartition"

    @classmethod
    def get_alias(cls):
        return "net-partition"

    @classmethod
    def get_description(cls):
        return "NetPartition"

    @classmethod
    def get_namespace(cls):
        return "http://nuagenetworks.net/ext/net_partition/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        resource_name = 'net_partition'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        quota.QUOTAS.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=True)
        ex = extensions.ResourceExtension(collection_name,
                                          controller)
        exts.append(ex)

        return exts


class NetPartitionPluginBase(object):

    @abc.abstractmethod
    def create_net_partition(self, context, router):
        pass

    @abc.abstractmethod
    def update_net_partition(self, context, id, router):
        pass

    @abc.abstractmethod
    def get_net_partition(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_net_partition(self, context, id):
        pass

    @abc.abstractmethod
    def get_net_partitions(self, context, filters=None, fields=None):
        pass
