# Copyright (c) 2026 Red Hat Inc.
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

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import pvlan as apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib.db import resource_extend
from neutron_lib.plugins import constants as plugin_consts
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_log import log as logging

from neutron.objects import network as net_object
from neutron.objects import ports as port_object
from neutron.objects import pvlan as pvlan_objects
from neutron.services.pvlan import exceptions as pvlan_exc

LOG = logging.getLogger(__name__)

# TODO(elvira): Move PVLAN_PLUGIN to neutron_lib.callbacks.resources
PVLAN_PLUGIN = 'pvlan_plugin'


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class PVLANPlugin(service_base.ServicePluginBase):
    """Implementation of the Neutron PVLAN Plugin.

    This class implements the PVLAN plugin that provides Private VLAN
    functionality for Neutron networks and ports.
    """

    @classmethod
    def get_plugin_type(cls):
        return plugin_consts.PVLAN

    def get_plugin_description(self):
        return "PVLAN Service Plugin"

    required_service_plugins = []
    _rpc_notifications_required = False

    supported_extension_aliases = [apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super().__init__()
        self._driver = None
        self.core_plugin = directory.get_plugin()
        registry.publish(PVLAN_PLUGIN, events.BEFORE_SPAWN, self)

        registry.subscribe(self.pvlan_network_update, resources.NETWORK,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self.pvlan_network_update, resources.NETWORK,
                           events.PRECOMMIT_UPDATE)
        registry.subscribe(self.pvlan_port_update, resources.PORT,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self.pvlan_port_update, resources.PORT,
                           events.PRECOMMIT_UPDATE)
        registry.subscribe(self._pvlan_port_driver_update, resources.PORT,
                           events.AFTER_UPDATE)
        registry.subscribe(self._pvlan_port_driver_update, resources.PORT,
                           events.AFTER_DELETE)
        registry.subscribe(
            self._pvlan_network_driver_update,
            resources.NETWORK, events.AFTER_UPDATE)
        registry.subscribe(
            self._pvlan_network_driver_delete,
            resources.NETWORK, events.AFTER_DELETE)

    def register_driver(self, driver):
        self._driver = driver

    @property
    def driver(self):
        return self._driver

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_pvlan(result_dict, network_db):
        """Extend network dictionary with PVLAN information."""
        if hasattr(network_db, 'pvlan') and network_db.pvlan:
            result_dict[pvlan_const.PVLAN] = network_db.pvlan.pvlan
        else:
            result_dict[pvlan_const.PVLAN] = False
        return result_dict

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_pvlan(result_dict, port_db):
        """Extend port dictionary with PVLAN information."""
        if hasattr(port_db, 'pvlan') and port_db.pvlan:
            result_dict[pvlan_const.PVLAN_TYPE] = port_db.pvlan.pvlan_type
            result_dict[pvlan_const.PVLAN_COMMUNITY] = (
                port_db.pvlan.pvlan_community)
        else:
            result_dict[pvlan_const.PVLAN_TYPE] = None
            result_dict[pvlan_const.PVLAN_COMMUNITY] = None
        return result_dict

    def pvlan_network_update(self, resource, event, trigger, payload=None):
        """Handle network update events to manage PVLAN."""
        context = payload.context
        network_id = payload.resource_id
        enable_pvlan = payload.request_body.get(pvlan_const.PVLAN)

        if enable_pvlan is None:
            return

        LOG.debug("Handling network %s event for %s: pvlan=%s",
                  event, network_id, enable_pvlan)

        if enable_pvlan:
            net_dict = payload.desired_state or payload.states[0]
            # If port security is not explicitly set, it defaults to True.
            port_security = net_dict.get('port_security_enabled', True)
            if not port_security:
                raise pvlan_exc.PVLANNetworkPortSecurityDisabled(
                    network_id=network_id)

        network = net_object.Network.get_object(context, id=network_id)
        if network.pvlan is not None:
            pvlan_objects.NetworkPVLAN.update_objects(
                context, {'pvlan': enable_pvlan}, network_id=network_id)
        else:
            pvlan_objects.NetworkPVLAN(
                context, network_id=network_id, pvlan=enable_pvlan
            ).create()

    def _pvlan_port_driver_update(self, resource, event, trigger,
                                  payload=None, **kwargs):
        """Call the driver after the port is created, updated or deleted."""
        if not self._driver:
            return

        port_id = payload.resource_id

        if event == events.AFTER_DELETE:
            if not payload.states:
                return
            original_port = payload.states[0]
            prev_pvlan_type = original_port.get(pvlan_const.PVLAN_TYPE)
            if not prev_pvlan_type:
                return
            self._driver.delete_port(
                port_id,
                original_port['network_id'],
                prev_pvlan_type,
                pvlan_community=original_port.get(pvlan_const.PVLAN_COMMUNITY))
            return

        context = payload.context
        port = port_object.Port.get_object(context, id=port_id)
        if not port or not port.pvlan_type:
            return
        network = net_object.Network.get_object(context, id=port.network_id)
        self._check_port_security(network, port)
        prev_pvlan_type = None
        prev_pvlan_community = None
        if payload.states:
            original_port = payload.states[0]
            prev_pvlan_type = original_port.get(pvlan_const.PVLAN_TYPE)
            prev_pvlan_community = original_port.get(
                pvlan_const.PVLAN_COMMUNITY)
        self._driver.update_port(context, port,
                                 prev_pvlan_type, prev_pvlan_community)

    def _pvlan_network_driver_update(self, resource, event,
                                     trigger, payload=None):
        """Handle port update when a network is updated to use PVLAN."""
        context = payload.context
        network_id = payload.resource_id
        network = net_object.Network.get_object(context, id=network_id)

        if payload.states:
            original_network = payload.states[0]
            if (network.pvlan or False) == original_network.get(
                    pvlan_const.PVLAN):
                return

        if not self._driver:
            LOG.warning("No driver found for network %s", network_id)
            return

        if network.pvlan:
            self._driver.create_network_resources(network_id)
        else:
            self._driver.delete_network_resources(network_id, context)
        for port in port_object.Port.get_objects(
                context, network_id=network_id):
            prev_pvlan_type = port.pvlan_type
            prev_pvlan_community = port.pvlan_community
            updated_portpvlan = self._pvlan_port_update(
                port=port, network=network, context=context)
            if updated_portpvlan and self._driver:
                port = port_object.Port.get_object(context, id=port.id)
                self._driver.update_port(context, port,
                                         prev_pvlan_type,
                                         prev_pvlan_community)

    def _pvlan_network_driver_delete(self, resource, event, trigger,
                                     payload=None):
        """Clean up port groups when a PVLAN network is deleted."""
        if not self._driver:
            return
        network_id = payload.resource_id
        self._driver.delete_network_resources(network_id, payload.context)

    def pvlan_port_update(self, resource, event, trigger, payload=None,
                          port=None, context=None):
        """Event handler for port create/update events."""
        return self._pvlan_port_update(payload=payload, port=port,
                                       context=context)

    def _pvlan_port_update(self, payload=None, port=None, network=None,
                           context=None):
        context = payload.context if payload else context
        port_id = port.id if port else payload.resource_id
        port_data = (port if port else
                     port_object.Port.get_object(context, id=port_id))
        network = network or net_object.Network.get_object(
            context, id=port_data.network_id)
        self._check_port_security(network, port_data)

        LOG.debug("Handling PVLAN port update for %s", port_id)

        prev_pvlan_type = port_data.pvlan_type
        prev_pvlan_community = port_data.pvlan_community
        request_body = (payload.request_body
                        if payload and payload.request_body else {})
        pvlan_type = request_body.get(
            pvlan_const.PVLAN_TYPE, prev_pvlan_type)
        pvlan_community = request_body.get(
            pvlan_const.PVLAN_COMMUNITY, None)

        if not network.pvlan:
            if prev_pvlan_type is not None:
                pvlan_objects.PortPVLAN.delete_objects(
                    context, port_id=port_id)
            elif pvlan_type or pvlan_community:
                raise pvlan_exc.PVLANNotEnabledOnNetwork(
                    network_id=port_data.network_id)
            return

        if not pvlan_type:
            pvlan_type = pvlan_const.PROMISCUOUS_TYPE
        if pvlan_type != pvlan_const.COMMUNITY_TYPE:
            if pvlan_community:
                raise pvlan_exc.PVLANCannotSetCommunityName(
                    port_id=port_id)
            if prev_pvlan_type == pvlan_const.COMMUNITY_TYPE:
                pvlan_community = None
        if (pvlan_type == pvlan_const.COMMUNITY_TYPE and
                not pvlan_community and prev_pvlan_community):
            pvlan_community = prev_pvlan_community
        if (not pvlan_community and
                pvlan_type == pvlan_const.COMMUNITY_TYPE):
            raise pvlan_exc.PVLANCommunityNameRequired(
                port_id=port_id)
        if prev_pvlan_type is not None:
            pvlan_objects.PortPVLAN.update_objects(
                context, {'pvlan_type': pvlan_type,
                          'pvlan_community': pvlan_community},
                port_id=port_id)
        else:
            pvlan_objects.PortPVLAN(
                context, port_id=port_id,
                pvlan_type=pvlan_type,
                pvlan_community=pvlan_community,
            ).create()
        return True

    def _check_port_security(self, network, port_data):
        if port_data.device_owner and port_data.device_owner.startswith(
                lib_constants.DEVICE_OWNER_NETWORK_PREFIX):
            return
        # Default port_security_enabled is True so if no security is set,
        # it means we are enforcing port security.
        # Same goes for network.
        port_security = True
        network_security = True
        if port_data.security:
            port_security = port_data.security.port_security_enabled
        if network.security:
            network_security = network.security.port_security_enabled
        if (network.pvlan and (not network_security or not port_security)):
            raise pvlan_exc.PVLANPortSecurityDisabled(port_id=port_data.id)
