# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
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
# @author: Bob Melander, Cisco Systems, Inc.

from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants as q_const
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import api as qdbapi
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.db import model_base
from neutron.openstack.common import importutils
from neutron.openstack.common import rpc
from neutron.plugins.common import constants


class L3RouterPluginRpcCallbacks(l3_rpc_base.L3RpcCallbackMixin):

    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return q_rpc.PluginRpcDispatcher([self])


class L3RouterPlugin(db_base_plugin_v2.CommonDbMixin,
                     extraroute_db.ExtraRoute_db_mixin,
                     l3_gwmode_db.L3_NAT_db_mixin,
                     l3_agentschedulers_db.L3AgentSchedulerDbMixin):

    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin and extraroute_db.ExtraRoute_db_mixin.
    """
    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute", "l3_agent_scheduler"]

    def __init__(self):
        qdbapi.register_models(base=model_base.BASEV2)
        self.setup_rpc()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotify})
        self.callbacks = L3RouterPluginRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.conn.consume_in_thread()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def create_floatingip(self, context, floatingip):
        """Create floating IP.

        :param context: Neutron request context
        :param floatingip: data fo the floating IP being created
        :returns: A floating IP object on success

        AS the l3 router plugin aysnchrounously creates floating IPs
        leveraging tehe l3 agent, the initial status fro the floating
        IP object will be DOWN.
        """
        return super(L3RouterPlugin, self).create_floatingip(
            context, floatingip,
            initial_status=q_const.FLOATINGIP_STATUS_DOWN)
