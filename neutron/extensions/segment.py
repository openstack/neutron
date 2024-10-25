# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
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

from neutron_lib.api.definitions import segment as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base


class Segment(api_extensions.APIExtensionDescriptor):
    """Extension class supporting Segments."""

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        attr_map = apidef.RESOURCE_ATTRIBUTE_MAP[apidef.COLLECTION_NAME]
        controller = base.create_resource(
            apidef.COLLECTION_NAME,
            apidef.RESOURCE_NAME,
            directory.get_plugin(apidef.COLLECTION_NAME),
            attr_map,
            allow_pagination=True,
            allow_sorting=True)
        return [extensions.ResourceExtension(apidef.COLLECTION_NAME,
                                             controller,
                                             attr_map=attr_map)]


class SegmentPluginBase(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_segment(self, context, segment):
        """Create a segment.

        Create a segment, which represents an L2 segment of a network.

        :param context: neutron api request context
        :param segment: dictionary describing the segment, with keys
                        as listed in the  :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/extensions/segment.py`.  All keys
                        will be populated.

        """

    @abc.abstractmethod
    def update_segment(self, context, uuid, segment):
        """Update values of a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to update.
        :param segment: dictionary with keys indicating fields to update.
                        valid keys are those that have a value of True for
                        'allow_put' as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/extensions/segment.py`.
        """

    @abc.abstractmethod
    def get_segment(self, context, uuid, fields=None):
        """Retrieve a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to fetch.
        :param fields: a list of strings that are valid keys in a
                       segment dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/extensions/segment.py`. Only these fields
                       will be returned.
        """

    @abc.abstractmethod
    def get_segments(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        """Retrieve a list of segments.

        The contents of the list depends on the identity of the user making the
        request (as indicated by the context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a segment as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/extensions/segment.py`.  Values in this
                        dictionary are an iterable containing values that will
                        be used for an exact match comparison for that value.
                        Each result returned by this function will have matched
                        one of the values for each key in filters.
        :param fields: a list of strings that are valid keys in a
                       segment dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/extensions/segment.py`. Only these fields
                       will be returned.
        """

    @abc.abstractmethod
    def delete_segment(self, context, uuid):
        """Delete a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to delete.
        """

    @abc.abstractmethod
    def get_segments_count(self, context, filters=None):
        """Return the number of segments.

        The result depends on the identity
        of the user making the request (as indicated by the context) as well
        as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a segment as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/extensions/segment.py`. Values in
                        this dictionary are an iterable containing values that
                        will be used for an exact match comparison for that
                        value.  Each result returned by this function will have
                        matched one of the values for each key in filters.
        """

    def get_plugin_description(self):
        return "Network Segments"

    @classmethod
    def get_plugin_type(cls):
        return apidef.COLLECTION_NAME

    @classmethod
    def is_loaded(cls):
        return cls.get_plugin_type() in directory.get_plugins()
