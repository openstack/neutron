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
from neutron_lib.callbacks import events as callback_events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import uuidutils

from neutron.agent import resource_cache
from neutron.api.rpc.callbacks import resources
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import objects

LOG = logging.getLogger(__name__)


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

    connection = n_rpc.create_connection()
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
        target = oslo_messaging.Target(topic=topic, version='1.0',
                                       namespace=n_const.RPC_NAMESPACE_STATE)
        self.client = n_rpc.get_client(target)

    def report_state(self, context, agent_state, use_call=False):
        cctxt = self.client.prepare(
            timeout=n_rpc.TRANSPORT.conf.rpc_response_timeout)
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
    '''

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_device_details(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_device_details', device=device,
                          agent_id=agent_id, host=host)

    def get_devices_details_list(self, context, devices, agent_id, host=None):
        cctxt = self.client.prepare(version='1.3')
        return cctxt.call(context, 'get_devices_details_list',
                          devices=devices, agent_id=agent_id, host=host)

    def get_devices_details_list_and_failed_devices(self, context, devices,
                                                    agent_id, host=None):
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

    def update_device_down(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_device_down', device=device,
                          agent_id=agent_id, host=host)

    def update_device_up(self, context, device, agent_id, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_device_up', device=device,
                          agent_id=agent_id, host=host)

    def update_device_list(self, context, devices_up, devices_down,
                           agent_id, host, agent_restarted=False):
        cctxt = self.client.prepare(version='1.5')

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
                             agent_restarted=agent_restarted)
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


def create_cache_for_l2_agent():
    """Create a push-notifications cache for L2 agent related resources."""

    objects.register_objects()
    resource_types = [
        resources.PORT,
        resources.SECURITYGROUP,
        resources.SECURITYGROUPRULE,
        resources.NETWORK,
        resources.SUBNET
    ]
    rcache = resource_cache.RemoteResourceCache(resource_types)
    rcache.start_watcher()
    return rcache


class CacheBackedPluginApi(PluginApi):

    def __init__(self, *args, **kwargs):
        super(CacheBackedPluginApi, self).__init__(*args, **kwargs)
        self.remote_resource_cache = create_cache_for_l2_agent()

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
        is_delete = event == callback_events.AFTER_DELETE
        suffix = 'delete' if is_delete else 'update'
        method = "%s_%s" % (rtype, suffix)
        if not hasattr(self._legacy_interface, method):
            # TODO(kevinbenton): once these notifications are stable, emit
            # a deprecation warning for legacy handlers
            return
        payload = {rtype: {'id': resource_id}, '%s_id' % rtype: resource_id}
        getattr(self._legacy_interface, method)(context, **payload)

    def get_devices_details_list_and_failed_devices(self, context, devices,
                                                    agent_id, host=None):
        result = {'devices': [], 'failed_devices': []}
        for device in devices:
            try:
                result['devices'].append(
                    self.get_device_details(context, device, agent_id, host))
            except Exception:
                LOG.exception("Failed to get details for device %s", device)
                result['failed_devices'].append(device)
        return result

    def get_device_details(self, context, device, agent_id, host=None):
        port_obj = self.remote_resource_cache.get_resource_by_id(
            resources.PORT, device)
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
        net = self.remote_resource_cache.get_resource_by_id(
            resources.NETWORK, port_obj.network_id)
        net_qos_policy_id = net.qos_policy_id
        # match format of old RPC interface
        mac_addr = str(netaddr.EUI(str(port_obj.mac_address),
                                   dialect=netaddr.mac_unix_expanded))
        entry = {
            'device': device,
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
            'profile': port_obj.binding.profile,
            'security_groups': list(port_obj.security_group_ids)
        }
        LOG.debug("Returning: %s", entry)
        return entry

    def get_devices_details_list(self, context, devices, agent_id, host=None):
        return [self.get_device_details(context, device, agent_id, host)
                for device in devices]
