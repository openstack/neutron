# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Mellanox Technologies, Ltd
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
from quantum.openstack.common import log as logging
from quantum.openstack.common.rpc import proxy

LOG = logging.getLogger(__name__)


class AgentNotifierApi(proxy.RpcProxy):
    """Agent side of the Embedded Switch RPC API.

       API version history:
       1.0 - Initial version.
    """
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def network_delete(self, context, network_id):
        LOG.debug(_("Sending delete network message"))
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, physical_network,
                    network_type, vlan_id):
        LOG.debug(_("Sending update port message"))
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       physical_network=physical_network,
                                       network_type=network_type,
                                       vlan_id=vlan_id),
                         topic=self.topic_port_update)
