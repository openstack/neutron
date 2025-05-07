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

import copy

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import trunk as trunk_apidef
from neutron_lib.api.definitions import trunk_details
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.services.trunk import constants
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.db import db_base_plugin_common
from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import drivers
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import rules
from neutron.services.trunk.seg_types import validators

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class TrunkPlugin(service_base.ServicePluginBase):

    supported_extension_aliases = [trunk_apidef.ALIAS,
                                   trunk_details.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        self._rpc_backend = None
        self._drivers = []
        self._segmentation_types = {}
        self._interfaces = set()
        self._agent_types = set()
        drivers.register()
        registry.subscribe(rules.enforce_port_deletion_rules,
                           resources.PORT, events.BEFORE_DELETE)
        registry.publish(resources.TRUNK_PLUGIN, events.AFTER_INIT, self)
        for driver in self._drivers:
            LOG.debug('Trunk plugin loaded with driver %s', driver.name)
        self.check_compatibility()

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_trunk_details(port_res, port_db):
        """Add trunk details to a port."""
        if port_db.trunk_port:
            subports = {
                x.port_id: {'segmentation_id': x.segmentation_id,
                            'segmentation_type': x.segmentation_type,
                            'port_id': x.port_id}
                for x in port_db.trunk_port.sub_ports
            }
            if not port_res.get('bulk'):
                core_plugin = directory.get_plugin()
                ports = core_plugin.get_ports(
                    context.get_admin_context(), filters={'id': subports})
                for port in ports:
                    subports[port['id']]['mac_address'] = port['mac_address']
            trunk_details = {'trunk_id': port_db.trunk_port.id,
                             'sub_ports': list(subports.values())}
            port_res['trunk_details'] = trunk_details

        return port_res

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME_BULK])
    def _extend_port_trunk_details_bulk(ports_res, noop):
        """Add trunk subport details to a list of ports."""
        subport_ids = []
        trunk_ports = []
        for p in ports_res:
            if 'trunk_details' in p and 'subports' in p['trunk_details']:
                trunk_ports.append(p)
                for subp in p['trunk_details']['subports']:
                    subport_ids.append(subp['port_id'])
        if not subport_ids:
            return ports_res

        core_plugin = directory.get_plugin()
        subports = core_plugin.get_ports(
            context.get_admin_context(), filters={'id': subport_ids})
        subport_macs = {p['id']: p['mac_address'] for p in subports}

        for tp in trunk_ports:
            for subp in tp['trunk_details']['subports']:
                subp['mac_address'] = subport_macs[subp['port_id']]

        return ports_res

    def check_compatibility(self):
        """Verify the plugin can load correctly and fail otherwise."""
        self.check_driver_compatibility()
        self.check_segmentation_compatibility()

    def check_driver_compatibility(self):
        """Fail to load if no compatible driver is found."""
        if not any(driver.is_loaded for driver in self._drivers):
            raise trunk_exc.IncompatibleTrunkPluginConfiguration()

    def check_segmentation_compatibility(self):
        """Fail to load if segmentation type conflicts are found.

        In multi-driver deployments each loaded driver must support the same
        set of segmentation types consistently.
        """
        # Get list of segmentation types for the loaded drivers.
        list_of_driver_seg_types = [
            set(driver.segmentation_types) for driver in self._drivers
            if driver.is_loaded
        ]

        # If not empty, check that there is at least one we can use.
        compat_segmentation_types = set()
        if list_of_driver_seg_types:
            compat_segmentation_types = (
                set.intersection(*list_of_driver_seg_types))
        if not compat_segmentation_types:
            raise trunk_exc.IncompatibleDriverSegmentationTypes()

        # If there is at least one, make sure the validator is defined.
        try:
            for seg_type in compat_segmentation_types:
                self.add_segmentation_type(
                    seg_type, validators.get_validator(seg_type))
        except KeyError:
            raise trunk_exc.SegmentationTypeValidatorNotFound(
                seg_type=seg_type)

    def set_rpc_backend(self, backend):
        self._rpc_backend = backend

    def is_rpc_enabled(self):
        return self._rpc_backend is not None

    def register_driver(self, driver):
        """Register driver with trunk plugin."""
        if driver.agent_type:
            self._agent_types.add(driver.agent_type)
        self._interfaces = self._interfaces | set(driver.interfaces)
        self._drivers.append(driver)

    @property
    def registered_drivers(self):
        """The registered drivers."""
        return self._drivers

    @property
    def supported_interfaces(self):
        """A set of supported interfaces."""
        return self._interfaces

    @property
    def supported_agent_types(self):
        """A set of supported agent types."""
        return self._agent_types

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
        # NOTE(status_police): a trunk is created in DOWN status. Depending
        # on the nature of the create request, a driver may set the status
        # immediately to ACTIVE if no physical provisioning is required.
        # Otherwise a transition to BUILD (or ERROR) should be expected
        # depending on how the driver reacts. PRECOMMIT failures prevent the
        # trunk from being created altogether.
        trunk_description = trunk.get('description', "")
        trunk_obj = trunk_objects.Trunk(context=context,
                                        admin_state_up=admin_state_up,
                                        id=uuidutils.generate_uuid(),
                                        name=trunk.get('name', ""),
                                        description=trunk_description,
                                        project_id=trunk['project_id'],
                                        port_id=trunk['port_id'],
                                        status=constants.TRUNK_DOWN_STATUS,
                                        sub_ports=sub_ports)
        with db_api.CONTEXT_WRITER.using(context):
            trunk_obj.create()
            payload = events.DBEventPayload(
                context, resource_id=trunk_obj.id, desired_state=trunk_obj)
            registry.publish(
                resources.TRUNK, events.PRECOMMIT_CREATE, self,
                payload=payload)
        payload = events.DBEventPayload(
            context, resource_id=trunk_obj.id, states=(trunk_obj,))
        registry.publish(
            resources.TRUNK, events.AFTER_CREATE, self, payload=payload)
        return trunk_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_trunk(self, context, trunk_id, trunk):
        """Update information for the specified trunk."""
        trunk_data = trunk['trunk']
        with db_api.CONTEXT_WRITER.using(context):
            trunk_obj = self._get_trunk(context, trunk_id)
            original_trunk = copy.deepcopy(trunk_obj)
            # NOTE(status_police): a trunk status should not change during an
            # update_trunk(), even in face of PRECOMMIT failures. This is
            # because only name and admin_state_up are being affected, and
            # these are DB properties only.
            trunk_obj.update_fields(trunk_data, reset_changes=True)
            trunk_obj.update()
            payload = events.DBEventPayload(
                context, resource_id=trunk_id, states=(original_trunk,),
                desired_state=trunk_obj, request_body=trunk_data)
            registry.publish(resources.TRUNK, events.PRECOMMIT_UPDATE, self,
                             payload=payload)
        payload = events.DBEventPayload(
            context, resource_id=trunk_id, states=(original_trunk, trunk_obj,),
            request_body=trunk_data)
        registry.publish(resources.TRUNK, events.AFTER_UPDATE, self,
                         payload=payload)
        return trunk_obj

    def delete_trunk(self, context, trunk_id):
        """Delete the specified trunk."""
        with db_api.CONTEXT_WRITER.using(context):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)
            trunk_port_validator = rules.TrunkPortValidator(trunk.port_id)
            if trunk_port_validator.can_be_trunked_or_untrunked(context):
                # NOTE(status_police): when a trunk is deleted, the logical
                # object disappears from the datastore, therefore there is no
                # status transition involved. If PRECOMMIT failures occur,
                # the trunk remains in the status where it was.
                try:
                    trunk.delete()
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        LOG.warning('Trunk driver raised exception when '
                                    'deleting trunk port %s: %s', trunk_id,
                                    str(e))
                payload = events.DBEventPayload(context, resource_id=trunk_id,
                                                states=(trunk,))
                registry.publish(resources.TRUNK, events.PRECOMMIT_DELETE,
                                 self, payload=payload)
            else:
                LOG.info('Trunk driver does not consider trunk %s '
                         'untrunkable', trunk_id)
                raise trunk_exc.TrunkInUse(trunk_id=trunk_id)
        registry.publish(resources.TRUNK, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, resource_id=trunk_id,
                             states=(trunk,)))

    @db_base_plugin_common.convert_result_to_dict
    def add_subports(self, context, trunk_id, subports):
        """Add one or more subports to trunk."""
        with db_api.CONTEXT_WRITER.using(context):
            trunk = self._get_trunk(context, trunk_id)

            # Check for basic validation since the request body here is not
            # automatically validated by the API layer.
            subports = subports['sub_ports']
            subports_validator = rules.SubPortsValidator(
                self._segmentation_types, subports, trunk['port_id'])
            subports = subports_validator.validate(
                context, basic_validation=True)
            added_subports = []

            rules.trunk_can_be_managed(context, trunk)
            original_trunk = copy.deepcopy(trunk)
            # NOTE(status_police): the trunk status should transition to
            # DOWN (and finally in ACTIVE or ERROR), only if it is not in
            # ERROR status already. A user should attempt to resolve the ERROR
            # condition before adding more subports to the trunk. Should a
            # trunk be in DOWN or BUILD state (e.g. when dealing with
            # multiple concurrent requests), the status is still forced to
            # DOWN and thus can potentially overwrite an interleaving state
            # change to ACTIVE. Eventually the driver should bring the status
            # back to ACTIVE or ERROR.
            if trunk.status == constants.TRUNK_ERROR_STATUS:
                raise trunk_exc.TrunkInErrorState(trunk_id=trunk_id)
            trunk.update(status=constants.TRUNK_DOWN_STATUS)

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
            payload = events.DBEventPayload(context, resource_id=trunk_id,
                                            states=(original_trunk, trunk,),
                                            metadata={
                                                'subports': added_subports
                                            })
            if added_subports:
                registry.publish(resources.SUBPORTS, events.PRECOMMIT_CREATE,
                                 self, payload=payload)
        if added_subports:
            payload = events.DBEventPayload(context, resource_id=trunk_id,
                                            states=(original_trunk, trunk,),
                                            metadata={
                                                'subports': added_subports
                                            })
            registry.publish(
                resources.SUBPORTS, events.AFTER_CREATE, self, payload=payload)
        return trunk

    @db_base_plugin_common.convert_result_to_dict
    def remove_subports(self, context, trunk_id, subports):
        """Remove one or more subports from trunk."""
        subports = subports['sub_ports']
        with db_api.CONTEXT_WRITER.using(context):
            trunk = self._get_trunk(context, trunk_id)
            original_trunk = copy.deepcopy(trunk)
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

            del trunk.sub_ports[:]
            trunk.sub_ports.extend(current_subports.values())
            # NOTE(status_police): the trunk status should transition to
            # DOWN irrespective of the status in which it is in to allow
            # the user to resolve potential conflicts due to prior add_subports
            # operations.
            # Should a trunk be in DOWN or BUILD state (e.g. when dealing
            # with multiple concurrent requests), the status is still forced
            # to DOWN. See add_subports() for more details.
            trunk.update(status=constants.TRUNK_DOWN_STATUS)
            payload = events.DBEventPayload(context, resource_id=trunk_id,
                                            states=(original_trunk, trunk,),
                                            metadata={
                                                'subports': removed_subports
                                            })
            if removed_subports:
                registry.publish(resources.SUBPORTS, events.PRECOMMIT_DELETE,
                                 self, payload=payload)
        if removed_subports:
            payload = events.DBEventPayload(context, resource_id=trunk_id,
                                            states=(original_trunk, trunk,),
                                            metadata={
                                                'subports': removed_subports
                                            })
            registry.publish(
                resources.SUBPORTS, events.AFTER_DELETE, self, payload=payload)
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

    # NOTE(tidwellr) Consider keying off of PRECOMMIT_UPDATE if we find
    # AFTER_UPDATE to be problematic for setting trunk status when a
    # a parent port becomes unbound.
    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def _trigger_trunk_status_change(self, resource, event, trigger, payload):
        updated_port = payload.latest_state
        trunk_details = updated_port.get('trunk_details')
        # If no trunk_details, the port is not the parent of a trunk.
        if not trunk_details:
            return

        context = payload.context
        original_port = payload.states[0]
        orig_vif_type = original_port.get(portbindings.VIF_TYPE)
        new_vif_type = updated_port.get(portbindings.VIF_TYPE)
        vif_type_changed = orig_vif_type != new_vif_type
        if vif_type_changed and new_vif_type == portbindings.VIF_TYPE_UNBOUND:
            trunk_id = trunk_details['trunk_id']
            # NOTE(status_police) Trunk status goes to DOWN when the parent
            # port is unbound. This means there are no more physical resources
            # associated with the logical resource.
            self.update_trunk(
                context, trunk_id,
                {'trunk': {'status': constants.TRUNK_DOWN_STATUS}})
