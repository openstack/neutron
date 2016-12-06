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

from neutron_lib import constants
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import uuidutils

from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics


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
    information on changing rpc interfaces, see doc/source/devref/rpc_api.rst.
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
                           agent_id, host):
        cctxt = self.client.prepare(version='1.5')
        return cctxt.call(context, 'update_device_list',
                          devices_up=devices_up, devices_down=devices_down,
                          agent_id=agent_id, host=host)

    def tunnel_sync(self, context, tunnel_ip, tunnel_type=None, host=None):
        cctxt = self.client.prepare(version='1.4')
        return cctxt.call(context, 'tunnel_sync', tunnel_ip=tunnel_ip,
                          tunnel_type=tunnel_type, host=host)
