# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NETWORK = 'network'
SUBNET = 'subnet'
PORT = 'port'

CREATE = 'create'
DELETE = 'delete'
UPDATE = 'update'

AGENT = 'q-agent-notifier'
PLUGIN = 'q-plugin'
DHCP = 'q-dhcp-notifer'

L3_AGENT = 'l3_agent'


def get_topic_name(prefix, table, operation):
    """Create a topic name.

    The topic name needs to be synced between the agent and the
    plugin. The plugin will send a fanout message to all of the
    listening agents so that the agents in turn can perform their
    updates accordingly.

    :param prefix: Common prefix for the plugin/agent message queues.
    :param table: The table in question (NETWORK, SUBNET, PORT).
    :param operation: The operation that invokes notification (CREATE,
                      DELETE, UPDATE)
    :returns: The topic name.
    """
    return '%s-%s-%s' % (prefix, table, operation)
