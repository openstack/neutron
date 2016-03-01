# Copyright (c) 2012 OpenStack Foundation.
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
SECURITY_GROUP = 'security_group'
L2POPULATION = 'l2population'
DVR = 'dvr'
RESOURCES = 'resources'

CREATE = 'create'
DELETE = 'delete'
UPDATE = 'update'

AGENT = 'q-agent-notifier'
PLUGIN = 'q-plugin'
SERVER_RESOURCE_VERSIONS = 'q-server-resource-versions'
L3PLUGIN = 'q-l3-plugin'
REPORTS = 'q-reports-plugin'
DHCP = 'q-dhcp-notifer'
METERING_PLUGIN = 'q-metering-plugin'

L3_AGENT = 'l3_agent'
DHCP_AGENT = 'dhcp_agent'
METERING_AGENT = 'metering_agent'

RESOURCE_TOPIC_PATTERN = "neutron-vo-%(resource_type)s-%(version)s"


def get_topic_name(prefix, table, operation, host=None):
    """Create a topic name.

    The topic name needs to be synced between the agent and the
    plugin. The plugin will send a fanout message to all of the
    listening agents so that the agents in turn can perform their
    updates accordingly.

    :param prefix: Common prefix for the plugin/agent message queues.
    :param table: The table in question (NETWORK, SUBNET, PORT).
    :param operation: The operation that invokes notification (CREATE,
                      DELETE, UPDATE)
    :param host: Add host to the topic
    :returns: The topic name.
    """
    if host:
        return '%s-%s-%s.%s' % (prefix, table, operation, host)
    return '%s-%s-%s' % (prefix, table, operation)
