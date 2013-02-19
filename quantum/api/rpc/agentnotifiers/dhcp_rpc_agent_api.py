# Copyright (c) 2013 OpenStack, LLC.
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


class DhcpAgentNotifyAPI(proxy.RpcProxy):
    """API for plugin to notify DHCP agent."""
    BASE_RPC_API_VERSION = '1.0'
    # It seems dhcp agent does not support bulk operation
    VALID_RESOURCES = ['network', 'subnet', 'port']
    VALID_METHOD_NAMES = ['network.create.end',
                          'network.update.end',
                          'network.delete.end',
                          'subnet.create.end',
                          'subnet.update.end',
                          'subnet.delete.end',
                          'port.create.end',
                          'port.update.end',
                          'port.delete.end']

    def __init__(self, topic=topics.DHCP_AGENT):
        super(DhcpAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _notification(self, context, method, payload):
        """Notify all the agents that are hosting the network"""
        # By now, we have no scheduling feature, so we fanout
        # to all of the DHCP agents
        self._notification_fanout(context, method, payload)

    def _notification_fanout(self, context, method, payload):
        """Fanout the payload to all dhcp agents"""
        self.fanout_cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic=topics.DHCP_AGENT)

    def notify(self, context, data, methodname):
        # data is {'key' : 'value'} with only one key
        if methodname not in self.VALID_METHOD_NAMES:
            return
        obj_type = data.keys()[0]
        if obj_type not in self.VALID_RESOURCES:
            return
        obj_value = data[obj_type]
        methodname = methodname.replace(".", "_")
        if methodname.endswith("_delete_end"):
            if 'id' in obj_value:
                self._notification(context, methodname,
                                   {obj_type + '_id': obj_value['id']})
        else:
            self._notification(context, methodname, data)
