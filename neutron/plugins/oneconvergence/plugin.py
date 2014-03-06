# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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
# @author: Kedar Kulkarni, One Convergence, Inc.

"""Implementation of OneConvergence Neutron Plugin."""

from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants as q_const
from neutron.common import exceptions as nexception
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.db import portbindings_base
from neutron.db import quota_db  # noqa
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.common import constants as svc_constants
import neutron.plugins.oneconvergence.lib.config  # noqa
import neutron.plugins.oneconvergence.lib.exception as nvsdexception
from neutron.plugins.oneconvergence.lib import nvsdlib as nvsd_lib

LOG = logging.getLogger(__name__)
IPv6 = 6


class NVSDRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin):

    """Agent callback."""

    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager."""
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class OneConvergencePluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                             extraroute_db.ExtraRoute_db_mixin,
                             l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                             agentschedulers_db.DhcpAgentSchedulerDbMixin,
                             external_net_db.External_net_db_mixin,
                             l3_gwmode_db.L3_NAT_db_mixin,
                             portbindings_base.PortBindingBaseMixin):

    """L2 Virtual Network Plugin.

    OneConvergencePluginV2 is a Neutron plugin that provides L2 Virtual Network
    functionality.
    """

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ['agent',
                                   'binding',
                                   'dhcp_agent_scheduler',
                                   'ext-gw-mode',
                                   'external-net',
                                   'extraroute',
                                   'l3_agent_scheduler',
                                   'quotas',
                                   'router',
                                   ]

    def __init__(self):

        super(OneConvergencePluginV2, self).__init__()

        self.oneconvergence_init()

        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}

        portbindings_base.register_port_dict_function()

        self.setup_rpc()

        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)

    def oneconvergence_init(self):
        """Initialize the connections and set the log levels for the plugin."""

        self.nvsdlib = nvsd_lib.NVSDApi()
        self.nvsdlib.set_connection()

    def setup_rpc(self):
        # RPC support
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.conn = rpc.create_connection(new=True)
        self.agent_notifiers[q_const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.agent_notifiers[q_const.AGENT_TYPE_L3] = (
            l3_rpc_agent_api.L3AgentNotify
        )
        self.callbacks = NVSDRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.dispatcher, fanout=False)

        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def create_network(self, context, network):

        net = self.nvsdlib.create_network(network['network'])

        network['network']['id'] = net['id']

        try:
            neutron_net = super(OneConvergencePluginV2,
                                self).create_network(context, network)

            #following call checks whether the network is external or not and
            #if it is external then adds this network to externalnetworks
            #table of neutron db
            self._process_l3_create(context, neutron_net, network['network'])
        except nvsdexception.NVSDAPIException:
            with excutils.save_and_reraise_exception():
                self.nvsdlib.delete_network(net)

        return neutron_net

    def update_network(self, context, net_id, network):

        with context.session.begin(subtransactions=True):

            neutron_net = super(OneConvergencePluginV2,
                                self).update_network(context, net_id, network)

            self.nvsdlib.update_network(neutron_net, network['network'])
            # updates neutron database e.g. externalnetworks table.
            self._process_l3_update(context, neutron_net, network['network'])

        return neutron_net

    def delete_network(self, context, net_id):

        with context.session.begin(subtransactions=True):
            network = self._get_network(context, net_id)
            #get all the subnets under the network to delete them
            subnets = self._get_subnets_by_network(context, net_id)

            super(OneConvergencePluginV2, self).delete_network(context,
                                                               net_id)

            self.nvsdlib.delete_network(network, subnets)

    def create_subnet(self, context, subnet):

        if subnet['subnet']['ip_version'] == IPv6:
            raise nexception.InvalidInput(
                error_message="NVSDPlugin doesn't support IPv6.")

        neutron_subnet = super(OneConvergencePluginV2,
                               self).create_subnet(context, subnet)

        try:
            self.nvsdlib.create_subnet(neutron_subnet)
        except nvsdexception.NVSDAPIException:
            with excutils.save_and_reraise_exception():
                #Log the message and delete the subnet from the neutron
                super(OneConvergencePluginV2,
                      self).delete_subnet(context, neutron_subnet['id'])
                LOG.error(_("Failed to create subnet, "
                          "deleting it from neutron"))

        return neutron_subnet

    def delete_subnet(self, context, subnet_id):

        neutron_subnet = self._get_subnet(context, subnet_id)

        with context.session.begin(subtransactions=True):

            super(OneConvergencePluginV2, self).delete_subnet(context,
                                                              subnet_id)

            self.nvsdlib.delete_subnet(neutron_subnet)

    def update_subnet(self, context, subnet_id, subnet):

        with context.session.begin(subtransactions=True):

            neutron_subnet = super(OneConvergencePluginV2,
                                   self).update_subnet(context, subnet_id,
                                                       subnet)

            self.nvsdlib.update_subnet(neutron_subnet, subnet)
        return neutron_subnet

    def create_port(self, context, port):

        network = {}

        network_id = port['port']['network_id']

        with context.session.begin(subtransactions=True):

            # Invoke the Neutron  API for creating port
            neutron_port = super(OneConvergencePluginV2,
                                 self).create_port(context, port)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_port)

            if port['port']['device_owner'] in ('network:router_gateway',
                                                'network:floatingip'):
                # for l3 requests, tenant_id will be None/''
                network = self._get_network(context, network_id)

                tenant_id = network['tenant_id']
            else:
                tenant_id = port['port']['tenant_id']

        port_id = neutron_port['id']

        try:
            self.nvsdlib.create_port(tenant_id, neutron_port)
        except nvsdexception.NVSDAPIException:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Deleting newly created "
                          "neutron port %s"), port_id)
                super(OneConvergencePluginV2, self).delete_port(context,
                                                                port_id)

        return neutron_port

    def update_port(self, context, port_id, port):

        with context.session.begin(subtransactions=True):

            neutron_port = super(OneConvergencePluginV2,
                                 self).update_port(context, port_id, port)

            if neutron_port['tenant_id'] == '':
                network = self._get_network(context,
                                            neutron_port['network_id'])
                tenant_id = network['tenant_id']
            else:
                tenant_id = neutron_port['tenant_id']

            self.nvsdlib.update_port(tenant_id, neutron_port, port['port'])

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_port)
        return neutron_port

    def delete_port(self, context, port_id, l3_port_check=True):

        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)

        neutron_port = self._get_port(context, port_id)

        with context.session.begin(subtransactions=True):

            self.disassociate_floatingips(context, port_id)

            super(OneConvergencePluginV2, self).delete_port(context, port_id)

            network = self._get_network(context, neutron_port['network_id'])
            neutron_port['tenant_id'] = network['tenant_id']

            self.nvsdlib.delete_port(port_id, neutron_port)
