# Copyright (c) 2012 OpenStack Foundation.
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

from datetime import datetime
import itertools

import netaddr
from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings_extended as pb_ext
from neutron_lib.callbacks import events as callback_events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources as callback_resources
from neutron_lib import constants
from neutron_lib.plugins import utils
from neutron_lib import rpc as lib_rpc
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import uuidutils

from neutron.agent import resource_cache
from neutron.api.rpc.callbacks import resources
from neutron.common import _constants as n_const
from neutron import objects

LOG = logging.getLogger(__name__)
BINDING_DEACTIVATE = 'binding_deactivate'


def create_consumers(endpoints, prefix, topic_details, start_listening=True):
    """Create agent RPC consumers.

    :param endpoints: The list of endpoints to process the incoming messages.
    :param prefix: Common prefix for the plugin/agent message queues.
    :param topic_details: A list of topics. Each topic has a name, an
                          operation, and an optional host param keying the
                          subscription to topic.host for plugin calls.
    :param start_listening: if True, it starts the processing loop

    :returns: A common Connection.
    """

    connection = lib_rpc.Connection()
    for details in topic_details:
        topic, operation, node_name = itertools.islice(
            itertools.chain(details, [None]), 3)

        topic_name = topics.get_topic_name(prefix, topic, operation)
        connection.create_consumer(topic_name, endpoints, fanout=True)
        if node_name:
            node_topic_name = '%s.%s' % (topic_name, node_name)
            connection.create_consumer(node_topic_name,
                                       endpoints,
                                       fanout=False)
    if start_listening:
        connection.consume_in_threads()
    return connection


class PluginReportStateAPI(object):
    """RPC client used to report state back to plugin.

    This class implements the client side of an rpc interface.  The server side
    can be found in neutron.db.agents_db.AgentExtRpcCallback.  For more
    information on changing rpc interfaces, see
    doc/source/contributor/internals/rpc_api.rst.
    """
    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.2',
                                       namespace=constants.RPC_NAMESPACE_STATE)
        self.client = lib_rpc.get_client(target)

    def has_alive_neutron_server(self, context, **kwargs):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'has_alive_neutron_server', **kwargs)

    def report_state(self, context, agent_state, use_call=False):
        cctxt = self.client.prepare(
            timeout=lib_rpc.TRANSPORT.conf.rpc_response_timeout)
        # add unique identifier to a report
        # that can be logged on server side.
        # This create visible correspondence between events on
        # the agent and on the server
        agent_state['uuid'] = uuidutils.generate_uuid()
        kwargs = {
            'agent_state': {'agent_state': agent_state},
            'time': datetime.utcnow().strftime(constants.ISO8601_TIME_FORMAT),
        }
        method = cctxt.call if use_call else cctxt.cast
        return method(context, 'report_state', **kwargs)


class PluginApi(object):
    '''Agent side of the rpc API.

    API version history:
        1.0 - Initial version.
        1.3 - get_device_details rpc signature upgrade to obtain 'host' and
              return value to include fixed_ips and device_owner for
              the device port
        1.4 - tunnel_sync rpc signature upgrade to obtain 'host'
        1.5 - Support update_device_list and
              get_devices_details_list_and_failed_devices
        1.6 - Support get_network_details
        1.7 - Support get_ports_by_vnic_type_and_host
        1.8 - Rename agent_restarted to refresh_tunnels in
              update_device_list to reflect its expanded purpose
    '''

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = lib_rpc.get_client(target)

    def get_device_details(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_device_details', device=device,
                          agent_id=agent_id, host=host)

    def get_devices_details_list(self, context, devices, agent_id, host=None):
        cctxt = self.client.prepare(version='1.3')
        return cctxt.call(context, 'get_devices_details_list',
                          devices=devices, agent_id=agent_id, host=host)

    def get_devices_details_list_and_failed_devices(self, context, devices,
                                                    agent_id, host=None,
                                                    **kwargs):
        """Get devices details and the list of devices that failed.

        This method returns the devices details. If an error is thrown when
        retrieving the devices details, the device is put in a list of
        failed devices.
        """
        cctxt = self.client.prepare(version='1.5')
        return cctxt.call(
            context,
            'get_devices_details_list_and_failed_devices',
            devices=devices, agent_id=agent_id, host=host)

    def get_network_details(self, context, network, agent_id, host=None):
        cctxt = self.client.prepare(version='1.6')
        return cctxt.call(context, 'get_network_details', network=network,
                          agent_id=agent_id, host=host)

    def update_device_down(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_device_down', device=device,
                          agent_id=agent_id, host=host)

    def update_device_up(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_device_up', device=device,
                          agent_id=agent_id, host=host)

    def update_device_list(self, context, devices_up, devices_down,
                           agent_id, host, refresh_tunnels=False):
        cctxt = self.client.prepare(version='1.8')

        ret_devices_up = []
        failed_devices_up = []
        ret_devices_down = []
        failed_devices_down = []

        step = n_const.RPC_RES_PROCESSING_STEP
        devices_up = list(devices_up)
        devices_down = list(devices_down)
        for i in range(0, max(len(devices_up), len(devices_down)), step):
            # Divide-and-conquer RPC timeout
            ret = cctxt.call(context, 'update_device_list',
                             devices_up=devices_up[i:i + step],
                             devices_down=devices_down[i:i + step],
                             agent_id=agent_id, host=host,
                             refresh_tunnels=refresh_tunnels)
            ret_devices_up.extend(ret.get("devices_up", []))
            failed_devices_up.extend(ret.get("failed_devices_up", []))
            ret_devices_down.extend(ret.get("devices_down", []))
            failed_devices_down.extend(ret.get("failed_devices_down", []))

        return {'devices_up': ret_devices_up,
                'failed_devices_up': failed_devices_up,
                'devices_down': ret_devices_down,
                'failed_devices_down': failed_devices_down}

    def tunnel_sync(self, context, tunnel_ip, tunnel_type=None, host=None):
        cctxt = self.client.prepare(version='1.4')
        return cctxt.call(context, 'tunnel_sync', tunnel_ip=tunnel_ip,
                          tunnel_type=tunnel_type, host=host)

    def get_ports_by_vnic_type_and_host(self, context, vnic_type, host):
        cctxt = self.client.prepare(version='1.7')
        return cctxt.call(context, 'get_ports_by_vnic_type_and_host',
                          vnic_type=vnic_type, host=host)


class CacheBackedPluginApi(PluginApi):

    RESOURCE_TYPES = [resources.PORT,
                      resources.SECURITYGROUP,
                      resources.SECURITYGROUPRULE,
                      resources.NETWORK,
                      resources.SUBNET]

    def __init__(self, *args, **kwargs):
        super(CacheBackedPluginApi, self).__init__(*args, **kwargs)
        self.remote_resource_cache = None
        self._create_cache_for_l2_agent()

    def register_legacy_notification_callbacks(self, legacy_interface):
        """Emulates the server-side notifications from ml2 AgentNotifierApi.

        legacy_interface is an object with 'delete'/'update' methods for
        core resources.
        """
        self._legacy_interface = legacy_interface
        for e in (callback_events.AFTER_UPDATE, callback_events.AFTER_DELETE):
            for r in (resources.PORT, resources.NETWORK):
                registry.subscribe(self._legacy_notifier, r, e)

    def _legacy_notifier(self, rtype, event, trigger, context, resource_id,
                         **kwargs):
        """Checks if legacy interface is expecting calls for resource.

        looks for port_update, network_delete, etc and calls them with
        the payloads the handlers are expecting (an ID).
        """
        rtype = rtype.lower()  # all legacy handlers don't camelcase
        agent_restarted = kwargs.pop("agent_restarted", None)
        method, host_with_activation, host_with_deactivation = (
            self._get_method_host(rtype, event, **kwargs))
        if not hasattr(self._legacy_interface, method):
            # TODO(kevinbenton): once these notifications are stable, emit
            # a deprecation warning for legacy handlers
            return
        # If there is a binding deactivation, we must also notify the
        # corresponding activation
        if method == BINDING_DEACTIVATE:
            self._legacy_interface.binding_deactivate(
                context, port_id=resource_id, host=host_with_deactivation)
            self._legacy_interface.binding_activate(
                context, port_id=resource_id, host=host_with_activation)
        else:
            payload = {rtype: {'id': resource_id},
                       '%s_id' % rtype: resource_id}
            if method == "port_update" and agent_restarted is not None:
                # Mark ovs-agent restart for local port_update
                payload["agent_restarted"] = agent_restarted
            getattr(self._legacy_interface, method)(context, **payload)

    def _get_method_host(self, rtype, event, **kwargs):
        """Constructs the name of method to be called in the legacy interface.

        If the event received is a port update that contains a binding
        activation where a previous binding is deactivated, the method name
        is 'binding_deactivate' and the host where the binding has to be
        deactivated is returned. Otherwise, the method name is constructed from
        rtype and the event received and the host is None.
        """
        is_delete = event == callback_events.AFTER_DELETE
        suffix = 'delete' if is_delete else 'update'
        method = "%s_%s" % (rtype, suffix)
        host_with_activation = None
        host_with_deactivation = None
        if is_delete or rtype != callback_resources.PORT:
            return method, host_with_activation, host_with_deactivation

        # A port update was received. Find out if it is a binding activation
        # where a previous binding was deactivated
        BINDINGS = pb_ext.COLLECTION_NAME
        if BINDINGS in kwargs.get('changed_fields', set()):
            existing_active_binding = (
                utils.get_port_binding_by_status_and_host(
                    getattr(kwargs['existing'], 'bindings', []),
                    constants.ACTIVE))
            updated_active_binding = (
                utils.get_port_binding_by_status_and_host(
                    getattr(kwargs['updated'], 'bindings', []),
                    constants.ACTIVE))
            if (existing_active_binding and updated_active_binding and
                    existing_active_binding.host !=
                    updated_active_binding.host):
                if (utils.get_port_binding_by_status_and_host(
                        getattr(kwargs['updated'], 'bindings', []),
                        constants.INACTIVE,
                        host=existing_active_binding.host)):
                    method = BINDING_DEACTIVATE
                    host_with_activation = updated_active_binding.host
                    host_with_deactivation = existing_active_binding.host
        return method, host_with_activation, host_with_deactivation

    def get_devices_details_list_and_failed_devices(self, context, devices,
                                                    agent_id, host=None,
                                                    agent_restarted=False):
        result = {'devices': [], 'failed_devices': []}
        for device in devices:
            try:
                result['devices'].append(
                    self.get_device_details(context, device, agent_id, host,
                                            agent_restarted))
            except Exception:
                LOG.exception("Failed to get details for device %s", device)
                result['failed_devices'].append(device)
        return result

    def get_device_details(self, context, device, agent_id, host=None,
                           agent_restarted=False):
        port_obj = self.remote_resource_cache.get_resource_by_id(
            resources.PORT, device, agent_restarted)
        if not port_obj:
            LOG.debug("Device %s does not exist in cache.", device)
            return {'device': device}
        if not port_obj.binding_levels:
            LOG.warning("Device %s is not bound.", port_obj)
            return {'device': device}
        segment = port_obj.binding_levels[-1].segment
        if not segment:
            LOG.debug("Device %s is not bound to any segment.", port_obj)
            return {'device': device}
        binding = utils.get_port_binding_by_status_and_host(
            port_obj.bindings, constants.ACTIVE, raise_if_not_found=True,
            port_id=port_obj.id)
        if (port_obj.device_owner.startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX) and
                binding[pb_ext.HOST] != host):
            LOG.debug("Device %s has no active binding in this host",
                      port_obj)
            return {'device': device,
                    constants.NO_ACTIVE_BINDING: True}
        net = self.remote_resource_cache.get_resource_by_id(
            resources.NETWORK, port_obj.network_id)
        net_qos_policy_id = net.qos_policy_id
        # match format of old RPC interface
        mac_addr = str(netaddr.EUI(str(port_obj.mac_address),
                                   dialect=netaddr.mac_unix_expanded))
        entry = {
            'device': device,
            'device_id': port_obj.device_id,
            'network_id': port_obj.network_id,
            'port_id': port_obj.id,
            'mac_address': mac_addr,
            'admin_state_up': port_obj.admin_state_up,
            'network_type': segment.network_type,
            'segmentation_id': segment.segmentation_id,
            'physical_network': segment.physical_network,
            'fixed_ips': [{'subnet_id': o.subnet_id,
                           'ip_address': str(o.ip_address)}
                          for o in port_obj.fixed_ips],
            'device_owner': port_obj.device_owner,
            'allowed_address_pairs': [{'mac_address': o.mac_address,
                                       'ip_address': o.ip_address}
                                      for o in port_obj.allowed_address_pairs],
            'port_security_enabled': getattr(port_obj.security,
                                             'port_security_enabled', True),
            'qos_policy_id': port_obj.qos_policy_id,
            'network_qos_policy_id': net_qos_policy_id,
            'profile': binding.profile,
            'vif_type': binding.vif_type,
            'vnic_type': binding.vnic_type,
            'security_groups': list(port_obj.security_group_ids)
        }
        LOG.debug("Returning: %s", entry)
        return entry

    def get_devices_details_list(self, context, devices, agent_id, host=None):
        return [self.get_device_details(context, device, agent_id, host)
                for device in devices]

    def _create_cache_for_l2_agent(self):
        """Create a push-notifications cache for L2 agent related resources."""
        objects.register_objects()
        rcache = resource_cache.RemoteResourceCache(self.RESOURCE_TYPES)
        rcache.start_watcher()
        self.remote_resource_cache = rcache
