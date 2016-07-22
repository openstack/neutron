# All Rights Reserved.
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
from oslo_utils import uuidutils

from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_common
from neutron.db import db_base_plugin_v2
from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects
from neutron.services import service_base
from neutron.services.trunk import constants
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import rules

LOG = logging.getLogger(__name__)


def _extend_port_trunk_details(core_plugin, port_res, port_db):
    """Add trunk details to a port."""
    if port_db.trunk_port:
        subports = [{'segmentation_id': x.segmentation_id,
                     'segmentation_type': x.segmentation_type,
                     'port_id': x.port_id}
                    for x in port_db.trunk_port.sub_ports]
        trunk_details = {'trunk_id': port_db.trunk_port.id,
                         'sub_ports': subports}
        port_res['trunk_details'] = trunk_details

    return port_res


class TrunkPlugin(service_base.ServicePluginBase,
                  common_db_mixin.CommonDbMixin):

    supported_extension_aliases = ["trunk", "trunk-details"]

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
            attributes.PORTS, [_extend_port_trunk_details])
        self._segmentation_types = {}
        registry.notify(constants.TRUNK_PLUGIN, events.AFTER_INIT, self)
        LOG.debug('Trunk plugin loaded')

    def add_segmentation_type(self, segmentation_type, id_validator):
        self._segmentation_types[segmentation_type] = id_validator
        LOG.debug('Added support for segmentation type %s', segmentation_type)

    def validate(self, context, trunk):
        """Return a valid trunk or raises an error if unable to do so."""
        trunk_details = trunk

        trunk_validator = rules.TrunkPortValidator(trunk['port_id'])
        trunk_details['port_id'] = trunk_validator.validate(context)

        subports_validator = rules.SubPortsValidator(
            self._segmentation_types, trunk['sub_ports'], trunk['port_id'])
        trunk_details['sub_ports'] = subports_validator.validate(context)
        return trunk_details

    def get_plugin_description(self):
        return "Trunk port service plugin"

    @classmethod
    def get_plugin_type(cls):
        return "trunk"

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunk(self, context, trunk_id, fields=None):
        """Return information for the specified trunk."""
        return self._get_trunk(context, trunk_id)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunks(self, context, filters=None, fields=None,
                   sorts=None, limit=None, marker=None, page_reverse=False):
        """Return information for available trunks."""
        filters = filters or {}
        pager = objects_base.Pager(sorts=sorts, limit=limit,
                                   page_reverse=page_reverse, marker=marker)
        return trunk_objects.Trunk.get_objects(context, _pager=pager,
                                               **filters)

    @db_base_plugin_common.convert_result_to_dict
    def create_trunk(self, context, trunk):
        """Create a trunk."""
        trunk = self.validate(context, trunk['trunk'])
        sub_ports = [trunk_objects.SubPort(
                         context=context,
                         port_id=p['port_id'],
                         segmentation_id=p['segmentation_id'],
                         segmentation_type=p['segmentation_type'])
                     for p in trunk['sub_ports']]
        admin_state_up = trunk.get('admin_state_up', True)
        trunk_obj = trunk_objects.Trunk(context=context,
                                        admin_state_up=admin_state_up,
                                        id=uuidutils.generate_uuid(),
                                        name=trunk.get('name', ""),
                                        tenant_id=trunk['tenant_id'],
                                        port_id=trunk['port_id'],
                                        sub_ports=sub_ports)
        trunk_obj.create()
        return trunk_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_trunk(self, context, trunk_id, trunk):
        """Update information for the specified trunk."""
        trunk_data = trunk['trunk']
        with db_api.autonested_transaction(context.session):
            trunk_obj = self._get_trunk(context, trunk_id)
            trunk_obj.update_nonidentifying_fields(
                trunk_data, reset_changes=True)
            trunk_obj.update()
            return trunk_obj

    def delete_trunk(self, context, trunk_id):
        """Delete the specified trunk."""
        with db_api.autonested_transaction(context.session):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)
            trunk_port_validator = rules.TrunkPortValidator(trunk.port_id)
            if not trunk_port_validator.is_bound(context):
                trunk.delete()
            else:
                raise trunk_exc.TrunkInUse(trunk_id=trunk_id)

    @db_base_plugin_common.convert_result_to_dict
    def add_subports(self, context, trunk_id, subports):
        """Add one or more subports to trunk."""
        # Check for basic validation since the request body here is not
        # automatically validated by the API layer.
        subports = subports['sub_ports']
        subports_validator = rules.SubPortsValidator(
            self._segmentation_types, subports)
        subports = subports_validator.validate(context, basic_validation=True)
        added_subports = []

        with db_api.autonested_transaction(context.session):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)
            for subport in subports:
                obj = trunk_objects.SubPort(
                               context=context,
                               trunk_id=trunk_id,
                               port_id=subport['port_id'],
                               segmentation_type=subport['segmentation_type'],
                               segmentation_id=subport['segmentation_id'])
                obj.create()
                trunk['sub_ports'].append(obj)
                added_subports.append(obj)

        registry.notify(
            constants.SUBPORTS, events.AFTER_CREATE, self,
            added_subports=added_subports)
        return trunk

    @db_base_plugin_common.convert_result_to_dict
    def remove_subports(self, context, trunk_id, subports):
        """Remove one or more subports from trunk."""
        subports = subports['sub_ports']
        with db_api.autonested_transaction(context.session):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)

            subports_validator = rules.SubPortsValidator(
                self._segmentation_types, subports)
            # the subports are being removed, therefore we do not need to
            # enforce any specific trunk rules, other than basic validation
            # of the request body.
            subports = subports_validator.validate(
                context, basic_validation=True,
                trunk_validation=False)

            current_subports = {p.port_id: p for p in trunk.sub_ports}
            removed_subports = []

            for subport in subports:
                subport_obj = current_subports.pop(subport['port_id'], None)

                if not subport_obj:
                    raise trunk_exc.SubPortNotFound(trunk_id=trunk_id,
                                                    port_id=subport['port_id'])
                subport_obj.delete()
                removed_subports.append(subport_obj)

            trunk.sub_ports = list(current_subports.values())
            registry.notify(
                constants.SUBPORTS, events.AFTER_DELETE, self,
                removed_subports=removed_subports)
            return trunk

    @db_base_plugin_common.filter_fields
    def get_subports(self, context, trunk_id, fields=None):
        """Return subports for the specified trunk."""
        trunk = self.get_trunk(context, trunk_id)
        return {'sub_ports': trunk['sub_ports']}

    def _get_trunk(self, context, trunk_id):
        """Return the trunk object or raise if not found."""
        obj = trunk_objects.Trunk.get_object(context, id=trunk_id)
        if obj is None:
            raise trunk_exc.TrunkNotFound(trunk_id=trunk_id)

        return obj
