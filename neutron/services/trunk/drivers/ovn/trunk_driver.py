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
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg
from oslo_log import log

from neutron.common.ovn.constants import OVN_ML2_MECH_DRIVER_NAME
from neutron.objects import ports as port_obj
from neutron.services.trunk.drivers import base as trunk_base


SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)

LOG = log.getLogger(__name__)


class OVNTrunkHandler(object):
    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def _set_sub_ports(self, parent_port, subports):
        txn = self.plugin_driver._nb_ovn.transaction
        context = n_context.get_admin_context()
        for port in subports:
            with db_api.CONTEXT_WRITER.using(context), (
                    txn(check_error=True)) as ovn_txn:
                self._set_binding_profile(context, port, parent_port, ovn_txn)

    def _unset_sub_ports(self, subports):
        txn = self.plugin_driver._nb_ovn.transaction
        context = n_context.get_admin_context()
        for port in subports:
            with db_api.CONTEXT_WRITER.using(context), (
                    txn(check_error=True)) as ovn_txn:
                self._unset_binding_profile(context, port, ovn_txn)

    def _set_binding_profile(self, context, subport, parent_port, ovn_txn):
        LOG.debug("Setting parent %s for subport %s",
                  parent_port, subport.port_id)
        db_port = port_obj.Port.get_object(context, id=subport.port_id)
        if not db_port:
            LOG.debug("Port not found while trying to set "
                      "binding_profile: %s",
                      subport.port_id)
            return
        try:
            # NOTE(flaviof): We expect binding's host to be set. Otherwise,
            # sub-port will not transition from DOWN to ACTIVE.
            db_port.device_owner = trunk_consts.TRUNK_SUBPORT_OWNER
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
        ovn_txn.add(self.plugin_driver._nb_ovn.set_lswitch_port(
                    lport_name=subport.port_id,
                    parent_name=parent_port,
                    tag=subport.segmentation_id))
        LOG.debug("Done setting parent %s for subport %s",
                  parent_port, subport.port_id)

    def _unset_binding_profile(self, context, subport, ovn_txn):
        LOG.debug("Unsetting parent for subport %s", subport.port_id)
        db_port = port_obj.Port.get_object(context, id=subport.port_id)
        if not db_port:
            LOG.debug("Port not found while trying to unset "
                      "binding_profile: %s",
                      subport.port_id)
            return
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
        ovn_txn.add(self.plugin_driver._nb_ovn.set_lswitch_port(
                    lport_name=subport.port_id,
                    parent_name=[],
                    up=False,
                    tag=[]))
        LOG.debug("Done unsetting parent for subport %s", subport.port_id)

    def trunk_created(self, trunk):
        if trunk.sub_ports:
            self._set_sub_ports(trunk.port_id, trunk.sub_ports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def trunk_deleted(self, trunk):
        if trunk.sub_ports:
            self._unset_sub_ports(trunk.sub_ports)

    def subports_added(self, trunk, subports):
        if subports:
            self._set_sub_ports(trunk.port_id, subports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def subports_deleted(self, trunk, subports):
        if subports:
            self._unset_sub_ports(subports)
        trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(payload.original_trunk,
                                payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(payload.original_trunk,
                                  payload.subports)


class OVNTrunkDriver(trunk_base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return OVN_ML2_MECH_DRIVER_NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(OVNTrunkDriver, self).register(
            resource, event, trigger, payload=payload)
        self._handler = OVNTrunkHandler(self.plugin_driver)
        for trunk_event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               resources.TRUNK,
                               trunk_event)
            registry.subscribe(self._handler.subport_event,
                               resources.SUBPORTS,
                               trunk_event)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(OVN_ML2_MECH_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)
