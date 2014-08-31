# Copyright 2014 Cisco Systems, Inc.
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
#

from neutron.common import rpc as n_rpc
from neutron.common import topics


class RpcCallbacks(n_rpc.RpcCallback):

    RPC_API_VERSION = '1.1'

    def __init__(self, notifier):
        self._nofifier = notifier
        super(RpcCallbacks, self).__init__()


class MechDriversAgentNotifierApi(n_rpc.RpcProxy):
    """Agent side of the cisco DFA mechanism driver rpc API.

    API version history:
        1.0 - Initial version.
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, agt_topic_tbl):
        super(MechDriversAgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_dfa_update = topics.get_topic_name(topic,
                                                      agt_topic_tbl,
                                                      topics.UPDATE)

    def send_vm_info(self, context, vm_info):
        self.fanout_cast(context,
                         self.make_msg('send_vm_info', vm_info=vm_info),
                         topic=self.topic_dfa_update)
