# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import ovs_constants as agent_consts
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg
from oslo_log import log as logging

from neutron.objects import trunk as trunk_obj
from neutron.services.trunk.drivers import base
from neutron.services.trunk.drivers.openvswitch import utils
from neutron.services.trunk import exceptions as trunk_exc

LOG = logging.getLogger(__name__)

NAME = 'openvswitch'

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)

DRIVER = None


class OVSDriver(base.DriverBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._core_plugin = None

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @property
    def is_loaded(self):
        try:
            return NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        return OVSDriver(NAME,
                         SUPPORTED_INTERFACES,
                         SUPPORTED_SEGMENTATION_TYPES,
                         constants.AGENT_TYPE_OVS)

    @staticmethod
    def _get_trunk(context, trunk_id):
        """Return the trunk object or raise if not found."""
        obj = trunk_obj.Trunk.get_object(context, id=trunk_id)
        if obj is None:
            raise trunk_exc.TrunkNotFound(trunk_id=trunk_id)

        return obj

    def _update_subport_binding(self, context, trunk_id):
        """Update the subport binding host"""
        trunk_obj = self._get_trunk(context, trunk_id)
        trunk_port = self.core_plugin.get_port(context, trunk_obj.port_id)
        trunk_host = trunk_port.get(portbindings.HOST_ID)
        for subport in trunk_obj.sub_ports:
            port = self.core_plugin.update_port(
                context, subport.port_id,
                {'port': {portbindings.HOST_ID: trunk_host,
                          'device_owner': trunk_consts.TRUNK_SUBPORT_OWNER}})
            vif_type = port.get(portbindings.VIF_TYPE)
            if vif_type == portbindings.VIF_TYPE_BINDING_FAILED:
                raise trunk_exc.SubPortBindingError(
                    port_id=subport.port_id, trunk_id=trunk_obj.id)

    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def _subport_binding(self, resource, event, trigger, payload=None):
        """Bind the subports to the parent port host

        This method listen to the port after update events. If the parent port
        is updated and transitions from inactive to active, this method
        retrieves the port host ID and binds the subports to this host.

        :param resource: neutron_lib.callbacks.resources.PORT
        :param event: neutron_lib.callbacks.events.AFTER_UPDATE
        :param trigger: the specific driver plugin

        """
        updated_port = payload.latest_state
        trunk_details = updated_port.get('trunk_details')
        vif_details = updated_port.get(portbindings.VIF_DETAILS)
        driver = vif_details.get(portbindings.VIF_DETAILS_BOUND_DRIVERS,
                                 {}).get('0')
        # If no trunk_details, the port is not the parent of a trunk.
        # If this port is not bound to ML2/OVS, we skip this method.
        if not trunk_details or not driver == NAME:
            return

        context = payload.context
        orig_status = payload.states[0].get('status')
        new_status = updated_port.get('status')
        trunk_id = trunk_details['trunk_id']
        if (new_status == constants.PORT_STATUS_ACTIVE and
                new_status != orig_status):
            self._update_subport_binding(context, trunk_id)


def register():
    """Register the driver."""
    global DRIVER
    DRIVER = OVSDriver.create()
    # To set the bridge_name in a parent port's vif_details.
    registry.subscribe(vif_details_bridge_name_handler,
                       agent_consts.OVS_BRIDGE_NAME,
                       events.BEFORE_READ)
    LOG.debug('Open vSwitch trunk driver registered')


def vif_details_bridge_name_handler(resource, event, set_br_name,
                                    payload=None):
    """If port is a trunk port, generate a bridge_name for its vif_details."""
    port = payload.metadata['port']
    if 'trunk_details' in port:
        set_br_name(utils.gen_trunk_br_name(port['trunk_details']['trunk_id']))
