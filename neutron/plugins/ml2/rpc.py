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

from neutron_lib.agent import topics
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import uplink_status_propagation as usp
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from osprofiler import profiler
from sqlalchemy.orm import exc

from neutron.api.rpc.handlers import dvr_rpc
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.db import l3_hamode_db
from neutron.db import provisioning_blocks
from neutron.plugins.ml2 import db as ml2_db
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
    #   1.6 Support get_network_details
    #   1.7 Support get_ports_by_vnic_type_and_host
    target = oslo_messaging.Target(version='1.7')

    def __init__(self, notifier, type_manager):
        self.setup_tunnel_callback_mixin(notifier, type_manager)
        super(RpcCallbacks, self).__init__()

    def _get_new_status(self, host, port_context):
        port = port_context.current
        if not host or host == port_context.host:
            new_status = (n_const.PORT_STATUS_BUILD if port['admin_state_up']
                          else n_const.PORT_STATUS_DOWN)
            if port['status'] != new_status:
                return new_status

    @staticmethod
    def _get_request_details(kwargs):
        return (kwargs.get('agent_id'),
                kwargs.get('host'),
                kwargs.get('device') or kwargs.get('network'))

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id, host, device = self._get_request_details(kwargs)

        # cached networks used for reducing number of network db calls
        # for server internal usage only
        cached_networks = kwargs.get('cached_networks')
        LOG.debug("Device %(device)s details requested by agent "
                  "%(agent_id)s with host %(host)s",
                  {'device': device, 'agent_id': agent_id, 'host': host})

        plugin = directory.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        port_context = plugin.get_bound_port_context(rpc_context,
                                                     port_id,
                                                     host,
                                                     cached_networks)
        if not port_context:
            LOG.debug("Device %(device)s requested by agent "
                      "%(agent_id)s not found in database",
                      {'device': device, 'agent_id': agent_id})
            return {'device': device}

        port = port_context.current
        # caching information about networks for future use
        if cached_networks is not None:
            if port['network_id'] not in cached_networks:
                cached_networks[port['network_id']] = (
                    port_context.network.current)
        result = self._get_device_details(rpc_context, agent_id=agent_id,
                                          host=host, device=device,
                                          port_context=port_context)
        if 'network_id' in result:
            # success so we update status
            new_status = self._get_new_status(host, port_context)
            if new_status:
                plugin.update_port_status(rpc_context,
                                          port_id,
                                          new_status,
                                          host,
                                          port_context.network.current)
        return result

    def _get_device_details(self, rpc_context, agent_id, host, device,
                            port_context):
        segment = port_context.bottom_bound_segment
        port = port_context.current

        if not segment:
            LOG.warning("Device %(device)s requested by agent "
                        "%(agent_id)s on network %(network_id)s not "
                        "bound, vif_type: %(vif_type)s",
                        {'device': device,
                         'agent_id': agent_id,
                         'network_id': port['network_id'],
                         'vif_type': port_context.vif_type})
            return {'device': device}

        if (port['device_owner'].startswith(
                n_const.DEVICE_OWNER_COMPUTE_PREFIX) and
                port[portbindings.HOST_ID] != host):
            LOG.debug("Device %(device)s has no active binding in host "
                      "%(host)s", {'device': device,
                                   'host': host})
            return {'device': device,
                    n_const.NO_ACTIVE_BINDING: True}

        network_qos_policy_id = port_context.network._network.get(
            qos_consts.QOS_POLICY_ID)
        entry = {'device': device,
                 'network_id': port['network_id'],
                 'port_id': port['id'],
                 'mac_address': port['mac_address'],
                 'admin_state_up': port['admin_state_up'],
                 'network_type': segment[api.NETWORK_TYPE],
                 'segmentation_id': segment[api.SEGMENTATION_ID],
                 'physical_network': segment[api.PHYSICAL_NETWORK],
                 'mtu': port_context.network._network.get('mtu'),
                 'fixed_ips': port['fixed_ips'],
                 'device_owner': port['device_owner'],
                 'allowed_address_pairs': port['allowed_address_pairs'],
                 'port_security_enabled': port.get(psec.PORTSECURITY, True),
                 'qos_policy_id': port.get(qos_consts.QOS_POLICY_ID),
                 'network_qos_policy_id': network_qos_policy_id,
                 'profile': port[portbindings.PROFILE],
                 'propagate_uplink_status': port.get(
                     usp.PROPAGATE_UPLINK_STATUS, False)}
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
        devices_to_fetch = kwargs.pop('devices', [])
        plugin = directory.get_plugin()
        host = kwargs.get('host')
        bound_contexts = plugin.get_bound_ports_contexts(rpc_context,
                                                         devices_to_fetch,
                                                         host)
        for device in devices_to_fetch:
            if not bound_contexts.get(device):
                # unbound bound
                LOG.debug("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database",
                          {'device': device,
                           'agent_id': kwargs.get('agent_id')})
                devices.append({'device': device})
                continue
            try:
                devices.append(self._get_device_details(
                               rpc_context,
                               agent_id=kwargs.get('agent_id'),
                               host=host,
                               device=device,
                               port_context=bound_contexts[device]))
            except Exception:
                LOG.exception("Failed to get details for device %s",
                              device)
                failed_devices.append(device)
        new_status_map = {ctxt.current['id']: self._get_new_status(host, ctxt)
                          for ctxt in bound_contexts.values() if ctxt}
        # filter out any without status changes
        new_status_map = {p: s for p, s in new_status_map.items() if s}
        try:
            plugin.update_port_statuses(rpc_context, new_status_map, host)
        except Exception:
            LOG.exception("Failure updating statuses, retrying all")
            failed_devices = devices_to_fetch
            devices = []

        return {'devices': devices,
                'failed_devices': failed_devices}

    def get_network_details(self, rpc_context, **kwargs):
        """Agent requests network details."""
        agent_id, host, network = self._get_request_details(kwargs)
        LOG.debug("Network %(network)s details requested by agent "
                  "%(agent_id)s with host %(host)s",
                  {'network': network, 'agent_id': agent_id, 'host': host})
        plugin = directory.get_plugin()
        return plugin.get_network(rpc_context, network)

    @profiler.trace("rpc")
    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        # TODO(garyk) - live migration and port status
        agent_id, host, device = self._get_request_details(kwargs)
        LOG.debug("Device %(device)s no longer exists at agent "
                  "%(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        plugin = directory.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        port_exists = True
        if (host and not plugin.port_bound_to_host(rpc_context,
                                                   port_id, host)):
            LOG.debug("Device %(device)s not bound to the"
                      " agent host %(host)s",
                      {'device': device, 'host': host})
        else:
            try:
                port_exists = bool(plugin.update_port_status(
                    rpc_context, port_id, n_const.PORT_STATUS_DOWN, host))
            except exc.StaleDataError:
                port_exists = False
                LOG.debug("delete_port and update_device_down are being "
                          "executed concurrently. Ignoring StaleDataError.")
                return {'device': device,
                        'exists': port_exists}
        self.notify_l2pop_port_wiring(port_id, rpc_context,
                                      n_const.PORT_STATUS_DOWN, host)

        return {'device': device,
                'exists': port_exists}

    @profiler.trace("rpc")
    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent."""
        agent_restarted = kwargs.pop('agent_restarted', False)
        agent_id, host, device = self._get_request_details(kwargs)
        LOG.debug("Device %(device)s up at agent %(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        plugin = directory.get_plugin()
        port_id = plugin._device_to_port_id(rpc_context, device)
        port = plugin.port_bound_to_host(rpc_context, port_id, host)
        if host and not port:
            LOG.debug("Device %(device)s not bound to the"
                      " agent host %(host)s",
                      {'device': device, 'host': host})
            # this might mean that a VM is in the process of live migration
            # and vif was plugged on the destination compute node;
            # need to notify nova explicitly
            port = ml2_db.get_port(rpc_context, port_id)
            # _device_to_port_id may have returned a truncated UUID if the
            # agent did not provide a full one (e.g. Linux Bridge case).
            if not port:
                LOG.debug("Port %s not found, will not notify nova.", port_id)
                return
            else:
                if port.device_owner.startswith(
                        n_const.DEVICE_OWNER_COMPUTE_PREFIX):
                    # NOTE(haleyb): It is possible for a test to override a
                    # config option after the plugin has been initialized so
                    # the nova_notifier attribute is not set on the plugin.
                    if (cfg.CONF.notify_nova_on_port_status_changes and
                            hasattr(plugin, 'nova_notifier')):
                        plugin.nova_notifier.notify_port_active_direct(port)
                    return
        else:
            self.update_port_status_to_active(port, rpc_context, port_id, host)
        self.notify_l2pop_port_wiring(port_id, rpc_context,
                                      n_const.PORT_STATUS_ACTIVE, host,
                                      agent_restarted)

    def update_port_status_to_active(self, port, rpc_context, port_id, host):
        plugin = directory.get_plugin()
        if port and port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE:
            # NOTE(kevinbenton): we have to special case DVR ports because of
            # the special multi-binding status update logic they have that
            # depends on the host
            plugin.update_port_status(rpc_context, port_id,
                                      n_const.PORT_STATUS_ACTIVE, host)
        else:
            # _device_to_port_id may have returned a truncated UUID if the
            # agent did not provide a full one (e.g. Linux Bridge case). We
            # need to look up the full one before calling provisioning_complete
            if not port:
                port = ml2_db.get_port(rpc_context, port_id)
            if not port:
                # port doesn't exist, no need to add a provisioning block
                return
            provisioning_blocks.provisioning_complete(
                rpc_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    def notify_l2pop_port_wiring(self, port_id, rpc_context,
                                 status, host, agent_restarted=False):
        """Notify the L2pop driver that a port has been wired/unwired.

        The L2pop driver uses this notification to broadcast forwarding
        entries to other agents on the same network as the port for port_id.
        """
        plugin = directory.get_plugin()
        l2pop_driver = plugin.mechanism_manager.mech_drivers.get(
                'l2population')
        if not l2pop_driver:
            return
        port = ml2_db.get_port(rpc_context, port_id)
        if not port:
            return
        port_context = plugin.get_bound_port_context(
                rpc_context, port_id, host)
        if not port_context:
            # port deleted
            return
        # NOTE: DVR ports are already handled and updated through l2pop
        # and so we don't need to update it again here. But, l2pop did not
        # handle DVR ports while restart neutron-*-agent, we need to handle
        # it here.
        if (port['device_owner'] == n_const.DEVICE_OWNER_DVR_INTERFACE and
                not agent_restarted):
            return
        port = port_context.current
        if (port['device_owner'] != n_const.DEVICE_OWNER_DVR_INTERFACE and
                status == n_const.PORT_STATUS_ACTIVE and
                port[portbindings.HOST_ID] != host and
                not l3_hamode_db.is_ha_router_port(rpc_context,
                                                   port['device_owner'],
                                                   port['device_id'])):
            # don't setup ACTIVE forwarding entries unless bound to this
            # host or if it's an HA or DVR port (which is special-cased in
            # the mech driver)
            return
        port_context.current['status'] = status
        port_context.current[portbindings.HOST_ID] = host
        if status == n_const.PORT_STATUS_ACTIVE:
            l2pop_driver.obj.update_port_up(port_context, agent_restarted)
        else:
            l2pop_driver.obj.update_port_down(port_context)

    @profiler.trace("rpc")
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
                    LOG.error("Failed to update device %s up", device)
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
                    LOG.error("Failed to update device %s down", device)
                else:
                    devices_down.append(dev)

        return {'devices_up': devices_up,
                'failed_devices_up': failed_devices_up,
                'devices_down': devices_down,
                'failed_devices_down': failed_devices_down}

    def get_ports_by_vnic_type_and_host(self, rpc_context, vnic_type, host):
        plugin = directory.get_plugin()
        return plugin.get_ports_by_vnic_type_and_host(
            rpc_context, vnic_type=vnic_type, host=host)


class AgentNotifierApi(dvr_rpc.DVRAgentRpcApiMixin,
                       sg_rpc.SecurityGroupAgentRpcApiMixin,
                       type_tunnel.TunnelAgentRpcApiMixin):
    """Agent side of the openvswitch rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              update_dhcp_port, and removed get_dhcp_port methods.
        1.4 - Added network_update
        1.5 - Added binding_activate and binding_deactivate
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
        self.topic_network_update = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.UPDATE)
        self.topic_port_binding_deactivate = topics.get_topic_name(
            topic, topics.PORT_BINDING, topics.DEACTIVATE)
        self.topic_port_binding_activate = topics.get_topic_name(
            topic, topics.PORT_BINDING, topics.ACTIVATE)

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

    def network_update(self, context, network):
        cctxt = self.client.prepare(topic=self.topic_network_update,
                                    fanout=True, version='1.4')
        cctxt.cast(context, 'network_update', network=network)

    def binding_deactivate(self, context, port_id, host, network_id):
        cctxt = self.client.prepare(topic=self.topic_port_binding_deactivate,
                                    fanout=True, version='1.5')
        cctxt.cast(context, 'binding_deactivate', port_id=port_id, host=host,
                   network_id=network_id)

    def binding_activate(self, context, port_id, host):
        cctxt = self.client.prepare(topic=self.topic_port_binding_activate,
                                    fanout=True, version='1.5')
        cctxt.cast(context, 'binding_activate', port_id=port_id, host=host)
