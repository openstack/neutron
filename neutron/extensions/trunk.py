# Copyright (c) 2016 ZTE Inc.
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

from oslo_log import log as logging

from neutron_lib.api import converters
from neutron_lib.api import validators

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper

LOG = logging.getLogger(__name__)


# TODO(armax): this validator was introduced in neutron-lib in
# https://review.openstack.org/#/c/319386/; remove it as soon
# as there is a new release.
def validate_subports(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for subports: '%s'") % data
        LOG.debug(msg)
        return msg

    subport_ids = set()
    segmentation_ids = set()
    for subport in data:
        if not isinstance(subport, dict):
            msg = _("Invalid data format for subport: '%s'") % subport
            LOG.debug(msg)
            return msg

        # Expect a non duplicated and valid port_id for the subport
        if 'port_id' not in subport:
            msg = _("A valid port UUID must be specified")
            LOG.debug(msg)
            return msg
        elif validators.validate_uuid(subport["port_id"]):
            msg = _("Invalid UUID for subport: '%s'") % subport["port_id"]
            return msg
        elif subport["port_id"] in subport_ids:
            msg = _("Non unique UUID for subport: '%s'") % subport["port_id"]
            return msg
        subport_ids.add(subport["port_id"])

        # Validate that both segmentation id and segmentation type are
        # specified, and that the client does not duplicate segmentation
        # ids
        segmentation_id = subport.get("segmentation_id")
        segmentation_type = subport.get("segmentation_type")
        if (not segmentation_id or not segmentation_type) and len(subport) > 1:
            msg = _("Invalid subport details '%s': missing segmentation "
                    "information. Must specify both segmentation_id and "
                    "segmentation_type") % subport
            LOG.debug(msg)
            return msg
        if segmentation_id in segmentation_ids:
            msg = _("Segmentation ID '%(seg_id)s' for '%(subport)s' is not "
                    "unique") % {"seg_id": segmentation_id,
                    "subport": subport["port_id"]}
            LOG.debug(msg)
            return msg
        if segmentation_id:
            segmentation_ids.add(segmentation_id)


validators.validators['type:subports'] = validate_subports


RESOURCE_ATTRIBUTE_MAP = {
    'trunks': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate':
                          {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
        'port_id': {'allow_post': True, 'allow_put': False,
                    'required_by_policy': True,
                    'validate': {'type:uuid': None},
                    'is_visible': True},
        'sub_ports': {'allow_post': True, 'allow_put': False,
                      'default': [],
                      'convert_list_to': converters.convert_kvp_list_to_dict,
                      'validate': {'type:subports': None},
                      'enforce_policy': True,
                      'is_visible': True}
    },
}


class Trunk(extensions.ExtensionDescriptor):
    """Trunk API extension."""

    @classmethod
    def get_name(cls):
        return "Trunk Extension"

    @classmethod
    def get_alias(cls):
        return "trunk"

    @classmethod
    def get_description(cls):
        return "Provides support for trunk ports"

    @classmethod
    def get_updated(cls):
        return "2016-01-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {'trunk': {'add_subports': 'PUT',
                                'remove_subports': 'PUT',
                                'get_subports': 'GET'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   'trunk',
                                                   action_map=action_map,
                                                   register_quota=True)

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Trunk, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_required_extensions(self):
        return ["binding"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
