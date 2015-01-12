# Copyright (c) 2013 OpenStack Foundation.
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

import webob.exc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from neutron.extensions import providernet as pnet

SEGMENTS = 'segments'


class SegmentsSetInConjunctionWithProviders(nexception.InvalidInput):
    message = _("Segments and provider values cannot both be set.")


class SegmentsContainDuplicateEntry(nexception.InvalidInput):
    message = _("Duplicate segment entry in request.")


def _convert_and_validate_segments(segments, valid_values=None):
    for segment in segments:
        segment.setdefault(pnet.NETWORK_TYPE, attr.ATTR_NOT_SPECIFIED)
        segment.setdefault(pnet.PHYSICAL_NETWORK, attr.ATTR_NOT_SPECIFIED)
        segmentation_id = segment.get(pnet.SEGMENTATION_ID)
        if segmentation_id:
            segment[pnet.SEGMENTATION_ID] = attr.convert_to_int(
                segmentation_id)
        else:
            segment[pnet.SEGMENTATION_ID] = attr.ATTR_NOT_SPECIFIED
        if len(segment.keys()) != 3:
            msg = (_("Unrecognized attribute(s) '%s'") %
                   ', '.join(set(segment.keys()) -
                             set([pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                                  pnet.SEGMENTATION_ID])))
            raise webob.exc.HTTPBadRequest(msg)


def check_duplicate_segments(segments, is_partial_func=None):
    """Helper function checking duplicate segments.

    If is_partial_funcs is specified and not None, then
    SegmentsContainDuplicateEntry is raised if two segments are identical and
    non partially defined (is_partial_func(segment) == False).
    Otherwise SegmentsContainDuplicateEntry is raised if two segment are
    identical.
    """
    if is_partial_func is not None:
        segments = [s for s in segments if not is_partial_func(s)]
    fully_specifieds = [tuple(sorted(s.items())) for s in segments]
    if len(set(fully_specifieds)) != len(fully_specifieds):
        raise SegmentsContainDuplicateEntry()


attr.validators['type:convert_segments'] = (
    _convert_and_validate_segments)


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        SEGMENTS: {'allow_post': True, 'allow_put': True,
                   'validate': {'type:convert_segments': None},
                   'convert_list_to': attr.convert_kvp_list_to_dict,
                   'default': attr.ATTR_NOT_SPECIFIED,
                   'enforce_policy': True,
                   'is_visible': True},
    }
}


class Multiprovidernet(extensions.ExtensionDescriptor):
    """Extension class supporting multiple provider networks.

    This class is used by neutron's extension framework to make
    metadata about the multiple provider network extension available to
    clients. No new resources are defined by this extension. Instead,
    the existing network resource's request and response messages are
    extended with 'segments' attribute.

    With admin rights, network dictionaries returned will also include
    'segments' attribute.
    """

    @classmethod
    def get_name(cls):
        return "Multi Provider Network"

    @classmethod
    def get_alias(cls):
        return "multi-provider"

    @classmethod
    def get_description(cls):
        return ("Expose mapping of virtual networks to multiple physical "
                "networks")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/multi-provider/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-06-27T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
