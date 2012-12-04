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
from quantum.openstack.common import jsonutils
from quantum.openstack.common import log as logging
from quantum.openstack.common.rpc import proxy


LOG = logging.getLogger(__name__)


class L3AgentNotifyAPI(proxy.RpcProxy):
    """API for plugin to notify L3 agent."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.L3_AGENT):
        super(L3AgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def router_deleted(self, context, router_id):
        LOG.debug(_('Nofity agent the router %s is deleted'), router_id)
        self.cast(context,
                  self.make_msg('router_deleted',
                                router_id=router_id),
                  topic=self.topic)

    def routers_updated(self, context, routers):
        if routers:
            LOG.debug(_('Nofity agent routers were updated:\n %s'),
                      jsonutils.dumps(routers, indent=5))
            self.cast(context,
                      self.make_msg('routers_updated',
                                    routers=routers),
                      topic=self.topic)


L3AgentNofity = L3AgentNotifyAPI()
