# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

import eventlet

from quantum.common import topics

from quantum.openstack.common import log as logging
from quantum.openstack.common.notifier import api
from quantum.openstack.common.notifier import rpc_notifier
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy


LOG = logging.getLogger(__name__)


def create_consumers(dispatcher, prefix, topic_details):
    """Create agent RPC consumers.

    :param dispatcher: The dispatcher to process the incoming messages.
    :param prefix: Common prefix for the plugin/agent message queues.
    :param topic_details: A list of topics. Each topic has a name and a
                          operation.

    :returns: A common Connection.
    """

    connection = rpc.create_connection(new=True)
    for topic, operation in topic_details:
        topic_name = topics.get_topic_name(prefix, topic, operation)
        connection.create_consumer(topic_name, dispatcher, fanout=True)
    connection.consume_in_thread()
    return connection


class PluginApi(proxy.RpcProxy):
    '''Agent side of the rpc API.

    API version history:
        1.0 - Initial version.

    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def get_device_details(self, context, device, agent_id):
        return self.call(context,
                         self.make_msg('get_device_details', device=device,
                                       agent_id=agent_id),
                         topic=self.topic)

    def update_device_down(self, context, device, agent_id):
        return self.call(context,
                         self.make_msg('update_device_down', device=device,
                                       agent_id=agent_id),
                         topic=self.topic)

    def tunnel_sync(self, context, tunnel_ip):
        return self.call(context,
                         self.make_msg('tunnel_sync', tunnel_ip=tunnel_ip),
                         topic=self.topic)


class NotificationDispatcher(object):
    def __init__(self):
        # Set the Queue size to 1 so that messages stay on server rather than
        # being buffered in the process.
        self.queue = eventlet.queue.Queue(1)
        self.connection = rpc.create_connection(new=True)
        topic = '%s.%s' % (rpc_notifier.CONF.notification_topics[0],
                           api.CONF.default_notification_level.lower())
        self.connection.declare_topic_consumer(topic=topic,
                                               callback=self._add_to_queue)
        self.connection.consume_in_thread()

    def _add_to_queue(self, msg):
        self.queue.put(msg)

    def run_dispatch(self, handler):
        while True:
            msg = self.queue.get()
            name = msg['event_type'].replace('.', '_')

            try:
                if hasattr(handler, name):
                    getattr(handler, name)(msg['payload'])
                else:
                    LOG.debug('Unknown event_type: %s.' % msg['event_type'])
            except Exception, e:
                LOG.warn('Error processing message. Exception: %s' % e)
