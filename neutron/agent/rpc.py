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

import itertools
from oslo import messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics

from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils


LOG = logging.getLogger(__name__)


def create_consumers(endpoints, prefix, topic_details):
    """Create agent RPC consumers.

    :param endpoints: The list of endpoints to process the incoming messages.
    :param prefix: Common prefix for the plugin/agent message queues.
    :param topic_details: A list of topics. Each topic has a name, an
                          operation, and an optional host param keying the
                          subscription to topic.host for plugin calls.

    :returns: A common Connection.
    """

    connection = n_rpc.create_connection(new=True)
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
    connection.consume_in_threads()
    return connection


class PluginReportStateAPI(n_rpc.RpcProxy):
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(PluginReportStateAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def report_state(self, context, agent_state, use_call=False):
        msg = self.make_msg('report_state',
                            agent_state={'agent_state':
                                         agent_state},
                            time=timeutils.strtime())
        if use_call:
            return self.call(context, msg)
        else:
            return self.cast(context, msg)


class PluginApi(n_rpc.RpcProxy):
    '''Agent side of the rpc API.

    API version history:
        1.0 - Initial version.
        1.3 - get_device_details rpc signature upgrade to obtain 'host' and
              return value to include fixed_ips and device_owner for
              the device port
    '''

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic):
        super(PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def get_device_details(self, context, device, agent_id, host=None):
        return self.call(context,
                         self.make_msg('get_device_details', device=device,
                                       agent_id=agent_id, host=host))

    def get_devices_details_list(self, context, devices, agent_id, host=None):
        res = []
        try:
            res = self.call(context,
                            self.make_msg('get_devices_details_list',
                                          devices=devices,
                                          agent_id=agent_id,
                                          host=host),
                            version='1.3')
        except messaging.UnsupportedVersion:
            # If the server has not been upgraded yet, a DVR-enabled agent
            # may not work correctly, however it can function in 'degraded'
            # mode, in that DVR routers may not be in the system yet, and
            # it might be not necessary to retrieve info about the host.
            LOG.warn(_('DVR functionality requires a server upgrade.'))
            res = [
                self.call(context,
                          self.make_msg('get_device_details', device=device,
                                        agent_id=agent_id, host=host))
                for device in devices
            ]
        return res

    def update_device_down(self, context, device, agent_id, host=None):
        return self.call(context,
                         self.make_msg('update_device_down', device=device,
                                       agent_id=agent_id, host=host))

    def update_device_up(self, context, device, agent_id, host=None):
        return self.call(context,
                         self.make_msg('update_device_up', device=device,
                                       agent_id=agent_id, host=host))

    def tunnel_sync(self, context, tunnel_ip, tunnel_type=None):
        return self.call(context,
                         self.make_msg('tunnel_sync', tunnel_ip=tunnel_ip,
                                       tunnel_type=tunnel_type))
