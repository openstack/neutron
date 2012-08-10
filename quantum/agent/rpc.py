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

from quantum.common import topics
from quantum.openstack.common import rpc


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
