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

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg
from oslo_log import log

from neutron.common.ovn import constants as ovn_const
from neutron.db import db_base_plugin_common
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.objects import ports as port_obj
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk.drivers import base as trunk_base
from neutron.services.trunk import exceptions as trunk_exc


SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)

LOG = log.getLogger(__name__)


class OVNTrunkHandler:
    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def _set_sub_ports(self, parent_port, subports):
        txn = self.plugin_driver.nb_ovn.transaction
        context = n_context.get_admin_context()
        db_parent_port = port_obj.Port.get_object(context, id=parent_port)
        parent_port_status = db_parent_port.status
        for subport in subports:
            with db_api.CONTEXT_WRITER.using(context), (
                    txn(check_error=True)) as ovn_txn:
                port = self._set_binding_profile(context, subport, parent_port,
                                                 parent_port_status, ovn_txn)
            db_rev.bump_revision(context, port, ovn_const.TYPE_PORTS)

    def _unset_sub_ports(self, subports):
        txn = self.plugin_driver.nb_ovn.transaction
        context = n_context.get_admin_context()
        for subport in subports:
            with db_api.CONTEXT_WRITER.using(context), (
                    txn(check_error=True)) as ovn_txn:
                port = self._unset_binding_profile(context, subport, ovn_txn)
            db_rev.bump_revision(context, port, ovn_const.TYPE_PORTS)

    @db_base_plugin_common.convert_result_to_dict
    def _set_binding_profile(self, context, subport, parent_port,
                             parent_port_status, ovn_txn):
        LOG.debug("Setting parent %s for subport %s",
                  parent_port, subport.port_id)
        db_port = port_obj.Port.get_object(context, id=subport.port_id)
        if not db_port:
            LOG.debug("Port not found while trying to set "
                      "binding_profile: %s",
                      subport.port_id)
            return
        check_rev_cmd = self.plugin_driver.nb_ovn.check_revision_number(
            db_port.id, db_port, ovn_const.TYPE_PORTS)
        ovn_txn.add(check_rev_cmd)
        try:
            # NOTE(flaviof): We expect binding's host to be set. Otherwise,
            # sub-port will not transition from DOWN to ACTIVE.
            db_port.device_owner = trunk_consts.TRUNK_SUBPORT_OWNER
            # NOTE(ksambor):  When sub-port was created and event was process
            # without binding profile this port will end forever in DOWN
            # status so we need to switch it here to the parent port status
            db_port.status = parent_port_status
            for binding in db_port.bindings:
                binding.profile['parent_name'] = parent_port
                binding.profile['tag'] = subport.segmentation_id
                # host + port_id is primary key
                port_obj.PortBinding.update_object(
                    context,
                    {'profile': binding.profile,
                     'vif_type': portbindings.VIF_TYPE_OVS},
                    port_id=subport.port_id,
                    host=binding.host)
            db_port.update()
        except n_exc.ObjectNotFound:
            LOG.debug("Port not found while trying to set "
                      "binding_profile: %s", subport.port_id)
            return
        ext_ids = {ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: db_port.device_owner}
        ovn_txn.add(self.plugin_driver.nb_ovn.set_lswitch_port(
            lport_name=subport.port_id,
            parent_name=parent_port,
            tag=subport.segmentation_id,
            external_ids_update=ext_ids,
        ))
        LOG.debug("Done setting parent %s for subport %s",
                  parent_port, subport.port_id)
        return db_port

    @db_base_plugin_common.convert_result_to_dict
    def _unset_binding_profile(self, context, subport, ovn_txn):
        LOG.debug("Unsetting parent for subport %s", subport.port_id)
        db_port = port_obj.Port.get_object(context, id=subport.port_id)
        if not db_port:
            LOG.debug("Port not found while trying to unset "
                      "binding_profile: %s",
                      subport.port_id)
            return
        check_rev_cmd = self.plugin_driver.nb_ovn.check_revision_number(
            db_port.id, db_port, ovn_const.TYPE_PORTS)
        ovn_txn.add(check_rev_cmd)
        try:
            db_port.device_owner = ''
            for binding in db_port.bindings:
                binding.profile.pop('tag', None)
                binding.profile.pop('parent_name', None)
                # host + port_id is primary key
                port_obj.PortBinding.update_object(
                    context,
                    {'profile': binding.profile,
                     'vif_type': portbindings.VIF_TYPE_UNBOUND},
                    port_id=subport.port_id,
                    host=binding.host)
                port_obj.PortBindingLevel.delete_objects(
                    context, port_id=subport.port_id, host=binding.host)
            db_port.update()
        except n_exc.ObjectNotFound:
            LOG.debug("Port not found while trying to unset "
                      "binding_profile: %s", subport.port_id)
            return
        ext_ids = {ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: db_port.device_owner}
        ovn_txn.add(self.plugin_driver.nb_ovn.set_lswitch_port(
            lport_name=subport.port_id,
            parent_name=[],
            up=False,
            tag=[],
            external_ids_update=ext_ids,
        ))
        LOG.debug("Done unsetting parent for subport %s", subport.port_id)
        return db_port

    def trunk_created(self, resource, event, trunk_plugin, payload):
        trunk = payload.states[0]
        # Check if parent port is handled by OVN.
        if not self.plugin_driver.nb_ovn.lookup('Logical_Switch_Port',
                                                trunk.port_id, default=None):
            return
        if trunk.sub_ports:
            self._set_sub_ports(trunk.port_id, trunk.sub_ports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def trunk_deleted(self, resource, event, trunk_plugin, payload):
        trunk = payload.states[0]
        if trunk.sub_ports:
            self._unset_sub_ports(trunk.sub_ports)

    def subports_added(self, resource, event, trunk_plugin, payload):
        trunk = payload.states[0]
        subports = payload.metadata['subports']
        # Check if parent port is handled by OVN.
        if not self.plugin_driver.nb_ovn.lookup('Logical_Switch_Port',
                                                trunk.port_id, default=None):
            return
        if subports:
            self._set_sub_ports(trunk.port_id, subports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def subports_deleted(self, resource, event, trunk_plugin, payload):
        trunk = payload.states[0]
        subports = payload.metadata['subports']
        # Check if parent port is handled by OVN.
        if not self.plugin_driver.nb_ovn.lookup('Logical_Switch_Port',
                                                trunk.port_id, default=None):
            return
        if subports:
            self._unset_sub_ports(subports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def port_updated(self, resource, event, trunk_plugin, payload):
        '''Propagate trunk parent port ACTIVE to trunk ACTIVE

        During a live migration with a trunk the only way we found to update
        the trunk to ACTIVE is to do this when the trunk's parent port gets
        updated to ACTIVE. This is clearly suboptimal, because the trunk's
        ACTIVE status should mean that all of its ports (parent and sub) are
        active. But in ml2/ovn the parent port's binding is not cascaded to the
        subports. Actually the subports' binding:host is left empty. This way
        here we don't know anything about the subports' state changes during a
        live migration. If we don't want to leave the trunk in DOWN this is
        what we have.

        Please note that this affects trunk create as well. Because of this we
        move ml2/ovn trunks to ACTIVE way early. But at least here we don't
        affect other mechanism drivers and their corresponding trunk drivers.

        See also:
        https://bugs.launchpad.net/neutron/+bug/1988549
        https://review.opendev.org/c/openstack/neutron/+/853779
        https://bugs.launchpad.net/neutron/+bug/2095152
        '''
        updated_port = payload.latest_state
        trunk_details = updated_port.get('trunk_details')
        # If no trunk_details, the port is not the parent of a trunk.
        if not trunk_details:
            return

        original_port = payload.states[0]
        orig_status = original_port.get('status')
        new_status = updated_port.get('status')
        context = payload.context
        trunk_id = trunk_details['trunk_id']
        if (new_status == constants.PORT_STATUS_ACTIVE and
                new_status != orig_status):
            trunk = trunk_objects.Trunk.get_object(context, id=trunk_id)
            if trunk is None:
                raise trunk_exc.TrunkNotFound(trunk_id=trunk_id)
            trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)


class OVNTrunkDriver(trunk_base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return (ovn_const.OVN_ML2_MECH_DRIVER_NAME in
                    cfg.CONF.ml2.mechanism_drivers)
        except cfg.NoSuchOptError:
            return False

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super().register(
            resource, event, trigger, payload=payload)
        self._handler = OVNTrunkHandler(self.plugin_driver)

        registry.subscribe(
            self._handler.trunk_created, resources.TRUNK, events.AFTER_CREATE)
        registry.subscribe(
            self._handler.trunk_deleted, resources.TRUNK, events.AFTER_DELETE)

        registry.subscribe(
            self._handler.subports_added,
            resources.SUBPORTS,
            events.AFTER_CREATE)
        registry.subscribe(
            self._handler.subports_deleted,
            resources.SUBPORTS,
            events.AFTER_DELETE)

        registry.subscribe(
            self._handler.port_updated,
            resources.PORT,
            events.AFTER_UPDATE)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(ovn_const.OVN_ML2_MECH_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)
