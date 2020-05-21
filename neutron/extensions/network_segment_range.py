# Copyright (c) 2019 Intel Corporation.
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

from neutron_lib.api.definitions import network_segment_range as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import base

LOG = logging.getLogger(__name__)


class Network_segment_range(api_extensions.APIExtensionDescriptor):
    """Extension class supporting Network segment ranges.

    This class is used by neutron's extension framework to make metadata
    about the network segment range extension available to clients.

    With admin rights, one will be able to create, update, read and delete the
    values.
    """

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns extension resources"""
        plugin = directory.get_plugin(plugin_constants.NETWORK_SEGMENT_RANGE)
        collection_name = apidef.COLLECTION_NAME.replace('_', '-')
        params = apidef.RESOURCE_ATTRIBUTE_MAP.get(apidef.COLLECTION_NAME,
                                                   dict())
        controller = base.create_resource(collection_name,
                                          apidef.RESOURCE_NAME,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ex = extensions.ResourceExtension(collection_name, controller,
                                          attr_map=params)

        return [ex]

    @classmethod
    def get_plugin_interface(cls):
        return NetworkSegmentRangePluginBase


class NetworkSegmentRangePluginBase(service_base.ServicePluginBase,
                                    metaclass=abc.ABCMeta):
    """REST API to manage network segment ranges.

    All methods must be in an admin context.
    """

    @classmethod
    def get_plugin_type(cls):
        return plugin_constants.NETWORK_SEGMENT_RANGE

    def get_plugin_description(self):
        return "Adds network segment ranges to Neutron resources"

    @abc.abstractmethod
    def create_network_segment_range(self, context, network_segment_range):
        """Create a network segment range.

        Create a network segment range, which represents the range of L2
        segments for tenant network allocation.

        :param context: neutron api request context
        :param network_segment_range: dictionary describing the network segment
            range, with keys as listed in the :obj:`RESOURCE_ATTRIBUTE_MAP`
            object in
            :file:`neutron_lib/api/definitions/network_segment_range.py`.
        """
        pass

    @abc.abstractmethod
    def delete_network_segment_range(self, context, id):
        """Delete a network segment range.

        :param context: neutron api request context
        :param id: UUID representing the network segment range to delete.
        """
        pass

    @abc.abstractmethod
    def update_network_segment_range(self, context, id, network_segment_range):
        """Update values of a network segment range.

        :param context: neutron api request context
        :param id: UUID representing the network segment range to update.
        :param network_segment_range: dictionary with keys indicating fields to
            update. valid keys are those that have a value of True for
            'allow_put' as listed in the :obj:`RESOURCE_ATTRIBUTE_MAP`
            object in
            :file:`neutron_lib/api/definitions/network_segment_range.py`.
        """
        pass

    @abc.abstractmethod
    def get_network_segment_ranges(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        """Retrieve a list of network segment ranges.

        The contents of the list depends on the filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a network segment range as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron_lib/api/definitions/
                        network_segment_range.py`.
                        Values in this dictionary are an iterable containing
                        values that will be used for an exact match
                        comparison for that value. Each result returned by
                        this function will have matched one of the values
                        for each key in filters.
        :param fields: a list of strings that are valid keys in a
                       network segment range dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron_lib/api/definitions/
                       network_segment_range.py`.
                       Only these fields will be returned.
        :param sorts: A list of (key, direction) tuples.
                      direction: True == ASC, False == DESC
        :param limit: maximum number of items to return
        :param marker: the last item of the previous page; when used, returns
                       next results after the marker resource.
        :param page_reverse: True if sort direction is reversed.
        """
        pass

    @abc.abstractmethod
    def get_network_segment_range(self, context, id, fields=None):
        """Retrieve a network segment range.

        :param context: neutron api request context
        :param id: UUID representing the network segment range to fetch.
        :param fields: a list of strings that are valid keys in a
                       network segment range dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron_lib/api/definitions/
                       network_segment_range.py`.
                       Only these fields will be returned.
        """
        pass
