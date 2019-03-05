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

from neutron_lib.api.definitions import network_segment_range as range_def
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import network_segment_range as range_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log
import six

from neutron._i18n import _
from neutron.db import segments_db
from neutron.extensions import network_segment_range as ext_range
from neutron.objects import base as base_obj
from neutron.objects import network_segment_range as obj_network_segment_range

LOG = log.getLogger(__name__)


def is_network_segment_range_enabled():
    network_segment_range_class = ('neutron.services.network_segment_range.'
                                   'plugin.NetworkSegmentRangePlugin')
    return any(p in cfg.CONF.service_plugins
               for p in ['network_segment_range', network_segment_range_class])


class NetworkSegmentRangePlugin(ext_range.NetworkSegmentRangePluginBase):
    """Implements Neutron Network Segment Range Service plugin."""

    supported_extension_aliases = [range_def.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(NetworkSegmentRangePlugin, self).__init__()
        self.type_manager = directory.get_plugin().type_manager
        self.type_manager.initialize_network_segment_range_support()

    def _get_network_segment_range(self, context, id):
        obj = obj_network_segment_range.NetworkSegmentRange.get_object(
            context, id=id)
        if obj is None:
            raise range_exc.NetworkSegmentRangeNotFound(range_id=id)
        return obj

    def _validate_network_segment_range_eligible(self, network_segment_range):
        range_data = (network_segment_range.get('minimum'),
                      network_segment_range.get('maximum'))
        # Currently, network segment range only supports VLAN, VxLAN,
        # GRE and Geneve.
        if network_segment_range.get('network_type') == const.TYPE_VLAN:
            plugin_utils.verify_vlan_range(range_data)
        else:
            plugin_utils.verify_tunnel_range(
                range_data, network_segment_range.get('network_type'))

    def _validate_network_segment_range_overlap(self, context,
                                                network_segment_range):
        filters = {
            'default': False,
            'network_type': network_segment_range['network_type'],
            'physical_network': (network_segment_range['physical_network']
                                 if network_segment_range['network_type'] ==
                                 const.TYPE_VLAN else None),
        }
        range_objs = obj_network_segment_range.NetworkSegmentRange.get_objects(
            context, **filters)
        overlapped_range_id = [
            obj.id for obj in range_objs if
            (network_segment_range['minimum'] <= obj.maximum and
             network_segment_range['maximum'] >= obj.minimum)]
        if overlapped_range_id:
            raise range_exc.NetworkSegmentRangeOverlaps(
                range_id=', '.join(overlapped_range_id))

    def _add_unchanged_range_attributes(self, updates, existing):
        """Adds data for unspecified fields on incoming update requests."""
        for key, value in six.iteritems(existing):
            updates.setdefault(key, value)
        return updates

    def _is_network_segment_range_referenced(self, context,
                                             network_segment_range):
        return segments_db.network_segments_exist_in_range(
            context, network_segment_range['network_type'],
            network_segment_range.get('physical_network'),
            network_segment_range)

    def _is_network_segment_range_type_supported(self, network_type):
        if not (self.type_manager.network_type_supported(network_type) and
                network_type in const.NETWORK_SEGMENT_RANGE_TYPES):
            # TODO(kailun): To use
            #  range_exc.NetworkSegmentRangeNetTypeNotSupported when the
            #  neutron-lib patch https://review.openstack.org/640777 is merged
            #  and released.
            message = _("Network type %s does not support "
                        "network segment ranges.") % network_type
            raise lib_exc.BadRequest(resource=range_def.RESOURCE_NAME,
                                     msg=message)

        return True

    def _are_allocated_segments_in_range_impacted(self, context,
                                                  existing_range,
                                                  updated_range):
        updated_range_min = updated_range.get('minimum',
                                              existing_range['minimum'])
        updated_range_max = updated_range.get('maximum',
                                              existing_range['maximum'])
        existing_range_min, existing_range_max = (
            segments_db.min_max_actual_segments_in_range(
                context, existing_range['network_type'],
                existing_range.get('physical_network'), existing_range))

        if existing_range_min and existing_range_max:
            return bool(updated_range_min >= existing_range_min or
                        updated_range_max <= existing_range_max)
        return False

    @log_helpers.log_method_call
    def create_network_segment_range(self, context, network_segment_range):
        """Check network types supported on network segment range creation."""
        range_data = network_segment_range['network_segment_range']
        if self._is_network_segment_range_type_supported(
                range_data['network_type']):
            with db_api.CONTEXT_WRITER.using(context):
                self._validate_network_segment_range_eligible(range_data)
                self._validate_network_segment_range_overlap(context,
                                                             range_data)
                network_segment_range = (
                    obj_network_segment_range.NetworkSegmentRange(
                        context, name=range_data['name'],
                        description=range_data.get('description'),
                        default=False,
                        shared=range_data['shared'],
                        project_id=(range_data['project_id']
                                    if not range_data['shared'] else None),
                        network_type=range_data['network_type'],
                        physical_network=(range_data['physical_network']
                                          if range_data['network_type'] ==
                                          const.TYPE_VLAN else None),
                        minimum=range_data['minimum'],
                        maximum=range_data['maximum'])
                )
                network_segment_range.create()

        self.type_manager.update_network_segment_range_allocations(
            network_segment_range['network_type'])
        return network_segment_range.to_dict()

    @log_helpers.log_method_call
    def get_network_segment_range(self, context, id, fields=None):
        network_segment_range = self._get_network_segment_range(
            context, id)
        return network_segment_range.to_dict(fields=fields)

    @log_helpers.log_method_call
    def get_network_segment_ranges(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        # TODO(kailun): Based on the current spec:
        #  https://review.openstack.org/599980, this method call may
        #  possibly return a large amount of data since ``available``
        #  segment list and ``used`` segment/project mapping will be also
        #  returned and they can be large sometimes. Considering that this
        #  API is admin-only and list operations won't be called often based
        #  on the use cases, we'll keep this open for now and evaluate the
        #  potential impacts. An alternative is to return the ``available``
        #  and ``used`` segment number or percentage.
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        network_segment_ranges = (
            obj_network_segment_range.NetworkSegmentRange.get_objects(
                context, _pager=pager, **filters))

        return [
            network_segment_range.to_dict(fields=fields)
            for network_segment_range in network_segment_ranges
        ]

    @log_helpers.log_method_call
    def update_network_segment_range(self, context, id, network_segment_range):
        """Check existing network segment range impact on range updates."""
        updated_range_data = network_segment_range['network_segment_range']
        with db_api.CONTEXT_WRITER.using(context):
            network_segment_range = self._get_network_segment_range(context,
                                                                    id)
            existing_range_data = network_segment_range.to_dict()

            if existing_range_data['default']:
                # TODO(kailun): To use
                #  range_exc.NetworkSegmentRangeDefaultReadOnly when the
                #  neutron-lib patch https://review.openstack.org/640777 is
                #  merged and released.
                message = _("Network Segment Range %s is a "
                            "default segment range which could not be "
                            "updated or deleted.") % id
                raise lib_exc.BadRequest(resource=range_def.RESOURCE_NAME,
                                         msg=message)

            if self._are_allocated_segments_in_range_impacted(
                    context,
                    existing_range=existing_range_data,
                    updated_range=updated_range_data):
                # TODO(kailun): To use
                #  range_exc.NetworkSegmentRangeReferencedByProject when the
                #  neutron-lib patch https://review.openstack.org/640777 is
                #  merged and released.
                message = _("Network Segment Range %s is referenced by "
                            "one or more tenant networks.") % id
                raise lib_exc.InUse(resource=range_def.RESOURCE_NAME,
                                    msg=message)

            new_range_data = self._add_unchanged_range_attributes(
                updated_range_data, existing_range_data)
            self._validate_network_segment_range_eligible(new_range_data)
            network_segment_range.update_fields(new_range_data)
            network_segment_range.update()

        self.type_manager.update_network_segment_range_allocations(
            network_segment_range['network_type'])
        return network_segment_range.to_dict()

    @log_helpers.log_method_call
    def delete_network_segment_range(self, context, id):
        """Check segment reference on network segment range deletion."""
        with db_api.CONTEXT_WRITER.using(context):
            network_segment_range = self._get_network_segment_range(context,
                                                                    id)
            range_data = network_segment_range.to_dict()

            if range_data['default']:
                # TODO(kailun): To use
                #  range_exc.NetworkSegmentRangeDefaultReadOnly when the
                #  neutron-lib patch https://review.openstack.org/640777 is
                #  merged and released.
                message = _("Network Segment Range %s is a "
                            "default segment range which could not be "
                            "updated or deleted.") % id
                raise lib_exc.BadRequest(resource=range_def.RESOURCE_NAME,
                                         msg=message)

            if self._is_network_segment_range_referenced(
                    context, range_data):
                # TODO(kailun): To use
                #  range_exc.NetworkSegmentRangeReferencedByProject when the
                #  neutron-lib patch https://review.openstack.org/640777 is
                #  merged and released.
                message = _("Network Segment Range %s is referenced by "
                            "one or more tenant networks.") % id
                raise lib_exc.InUse(resource=range_def.RESOURCE_NAME,
                                    msg=message)
            network_segment_range.delete()

        self.type_manager.update_network_segment_range_allocations(
            network_segment_range['network_type'])
