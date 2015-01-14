# Copyright (c) 2013 OpenStack Foundation
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

from oslo_log import log
import oslo_messaging
from sqlalchemy.orm import exc

from neutron.api.rpc.handlers import dvr_rpc
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as n_const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.extensions import portsecurity as psec
from neutron.i18n import _LE, _LW
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_tunnel
# REVISIT(kmestery): Allow the type and mechanism drivers to supply the
# mixins and eventually remove the direct dependencies on type_tunnel.

LOG = log.getLogger(__name__)


class RpcCallbacks(type_tunnel.TunnelRpcCallbackMixin):

    # history
    #   1.0 Initial version (from openvswitch/linuxbridge)
    #   1.1 Support Security Group RPC
    #   1.2 Support get_devices_details_list
    #   1.3 get_device_details rpc signature upgrade to obtain 'host' and
    #       return value to include fixed_ips and device_owner for
    #       the device port
    #   1.4 tunnel_sync rpc signature upgrade to obtain 'host'
    #   1.5 Support update_device_list and
    #       get_devices_details_list_and_failed_devices
    target = oslo_messaging.Target(version='1.5')

    def __init__(self, notifier, type_manager):
        self.setup_tunnel_callback_mixin(notifier, type_manager)
        super(RpcCallbacks, self).__init__()

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        # cached networks used for reducing number of network db calls
        # for server internal usage only
        cached_networks = kwargs.get('cached_networks')
        LOG.debug("Device %(device)s details requested by agent "
                  "%(agent_id)s with host %(host)s",
                  {'device': device, 'agent_id': agent_id, 'host': host})

        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        port_context = plugin.get_bound_port_context(rpc_context,
                                                     port_id,
                                                     host,
                                                     cached_networks)
        if not port_context:
            LOG.warning(_LW("Device %(device)s requested by agent "
                            "%(agent_id)s not found in database"),
                        {'device': device, 'agent_id': agent_id})
            return {'device': device}

        segment = port_context.bottom_bound_segment
        port = port_context.current
        # caching information about networks for future use
        if cached_networks is not None:
            if port['network_id'] not in cached_networks:
                cached_networks[port['network_id']] = (
                    port_context.network.current)

        if not segment:
            LOG.warning(_LW("Device %(device)s requested by agent "
                            "%(agent_id)s on network %(network_id)s not "
                            "bound, vif_type: %(vif_type)s"),
                        {'device': device,
                         'agent_id': agent_id,
                         'network_id': port['network_id'],
                         'vif_type': port_context.vif_type})
            return {'device': device}

        if (not host or host == port_context.host):
            new_status = (n_const.PORT_STATUS_BUILD if port['admin_state_up']
                          else n_const.PORT_STATUS_DOWN)
            if port['status'] != new_status:
                plugin.update_port_status(rpc_context,
                                          port_id,
                                          new_status,
                                          host,
                                          port_context.network.current)

        entry = {'device': device,
                 'network_id': port['network_id'],
                 'port_id': port['id'],
                 'mac_address': port['mac_address'],
                 'admin_state_up': port['admin_state_up'],
                 'network_type': segment[api.NETWORK_TYPE],
                 'segmentation_id': segment[api.SEGMENTATION_ID],
                 'physical_network': segment[api.PHYSICAL_NETWORK],
                 'fixed_ips': port['fixed_ips'],
                 'device_owner': port['device_owner'],
                 'allowed_address_pairs': port['allowed_address_pairs'],
                 'port_security_enabled': port.get(psec.PORTSECURITY, True),
                 'profile': port[portbindings.PROFILE]}
        LOG.debug("Returning: %s", entry)
        return entry

    def get_devices_details_list(self, rpc_context, **kwargs):
        # cached networks used for reducing number of network db calls
        cached_networks = {}
        return [
            self.get_device_details(
                rpc_context,
                device=device,
                cached_networks=cached_networks,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]

    def get_devices_details_list_and_failed_devices(self,
                                                    rpc_context,
                                                    **kwargs):
        devices = []
        failed_devices = []
        cached_networks = {}
        for device in kwargs.pop('devices', []):
            try:
                devices.append(self.get_device_details(
                               rpc_context,
                               device=device,
                               cached_networks=cached_networks,
                               **kwargs))
            except Exception:
                LOG.error(_LE("Failed to get details for device %s"),
                          device)
                failed_devices.append(device)

        return {'devices': devices,
                'failed_devices': failed_devices}

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        # TODO(garyk) - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug("Device %(device)s no longer exists at agent "
                  "%(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        port_exists = True
        if (host and not plugin.port_bound_to_host(rpc_context,
                                                   port_id, host)):
            LOG.debug("Device %(device)s not bound to the"
                      " agent host %(host)s",
                      {'device': device, 'host': host})
            return {'device': device,
                    'exists': port_exists}

        try:
            port_exists = bool(plugin.update_port_status(
                rpc_context, port_id, n_const.PORT_STATUS_DOWN, host))
        except exc.StaleDataError:
            port_exists = False
            LOG.debug("delete_port and update_device_down are being executed "
                      "concurrently. Ignoring StaleDataError.")

        return {'device': device,
                'exists': port_exists}

    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug("Device %(device)s up at agent %(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        if (host and not plugin.port_bound_to_host(rpc_context,
                                                   port_id, host)):
            LOG.debug("Device %(device)s not bound to the"
                      " agent host %(host)s",
                      {'device': device, 'host': host})
            return

        port_id = plugin.update_port_status(rpc_context, port_id,
                                            n_const.PORT_STATUS_ACTIVE,
                                            host)
        try:
            # NOTE(armax): it's best to remove all objects from the
            # session, before we try to retrieve the new port object
            rpc_context.session.expunge_all()
            port = plugin._get_port(rpc_context, port_id)
        except exceptions.PortNotFound:
            LOG.debug('Port %s not found during update', port_id)
        else:
            kwargs = {
                'context': rpc_context,
                'port': port,
                'update_device_up': True
            }
            registry.notify(
                resources.PORT, events.AFTER_UPDATE, plugin, **kwargs)

    def update_device_list(self, rpc_context, **kwargs):
        devices_up = []
        failed_devices_up = []
        devices_down = []
        failed_devices_down = []
        devices = kwargs.get('devices_up')
        if devices:
            for device in devices:
                try:
                    self.update_device_up(
                        rpc_context,
                        device=device,
                        **kwargs)
                except Exception:
                    failed_devices_up.append(device)
                    LOG.error(_LE("Failed to update device %s up"), device)
                else:
                    devices_up.append(device)

        devices = kwargs.get('devices_down')
        if devices:
            for device in devices:
                try:
                    dev = self.update_device_down(
                        rpc_context,
                        device=device,
                        **kwargs)
                except Exception:
                    failed_devices_down.append(device)
                    LOG.error(_LE("Failed to update device %s down"), device)
                else:
                    devices_down.append(dev)

        return {'devices_up': devices_up,
                'failed_devices_up': failed_devices_up,
                'devices_down': devices_down,
                'failed_devices_down': failed_devices_down}


class AgentNotifierApi(dvr_rpc.DVRAgentRpcApiMixin,
                       sg_rpc.SecurityGroupAgentRpcApiMixin,
                       type_tunnel.TunnelAgentRpcApiMixin):
    """Agent side of the openvswitch rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              update_dhcp_port, and removed get_dhcp_port methods.

    """

    def __init__(self, topic):
        self.topic = topic
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)
        self.topic_port_delete = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.DELETE)

        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def network_delete(self, context, network_id):
        cctxt = self.client.prepare(topic=self.topic_network_delete,
                                    fanout=True)
        cctxt.cast(context, 'network_delete', network_id=network_id)

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        cctxt = self.client.prepare(topic=self.topic_port_update,
                                    fanout=True)
        cctxt.cast(context, 'port_update', port=port,
                   network_type=network_type, segmentation_id=segmentation_id,
                   physical_network=physical_network)

    def port_delete(self, context, port_id):
        cctxt = self.client.prepare(topic=self.topic_port_delete,
                                    fanout=True)
        cctxt.cast(context, 'port_delete', port_id=port_id)
