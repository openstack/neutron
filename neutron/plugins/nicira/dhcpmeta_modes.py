# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
# All Rights Reserved
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

from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as const
from neutron.common import topics
from neutron.openstack.common import importutils
from neutron.openstack.common import rpc
from neutron.plugins.nicira.common import config
from neutron.plugins.nicira.dhcp_meta import rpc as nvp_rpc


class DhcpMetadataAccess(object):

    def setup_dhcpmeta_access(self):
        """Initialize support for DHCP and Metadata services."""
        if cfg.CONF.NVP.agent_mode == config.AgentModes.AGENT:
            self._setup_rpc_dhcp_metadata()
            self.handle_network_dhcp_access_delegate = (
                nvp_rpc.handle_network_dhcp_access
            )
            self.handle_port_dhcp_access_delegate = (
                nvp_rpc.handle_port_dhcp_access
            )
            self.handle_port_metadata_access_delegate = (
                nvp_rpc.handle_port_metadata_access
            )
            self.handle_metadata_access_delegate = (
                nvp_rpc.handle_router_metadata_access
            )
        elif cfg.CONF.NVP.agent_mode == config.AgentModes.AGENTLESS:
            # In agentless mode the following extensions, and related
            # operations, are not supported; so do not publish them
            if "agent" in self.supported_extension_aliases:
                self.supported_extension_aliases.remove("agent")
            if "dhcp_agent_scheduler" in self.supported_extension_aliases:
                self.supported_extension_aliases.remove(
                    "dhcp_agent_scheduler")
            # TODO(armando-migliaccio): agentless support is not yet complete
            # so it's better to raise an exception for now, in case some admin
            # decides to jump the gun
            raise NotImplementedError()

    def _setup_rpc_dhcp_metadata(self):
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = nvp_rpc.NVPRpcCallbacks().create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        self.conn.consume_in_thread()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )

    def handle_network_dhcp_access(self, context, network, action):
        self.handle_network_dhcp_access_delegate(self, context,
                                                 network, action)

    def handle_port_dhcp_access(self, context, port_data, action):
        self.handle_port_dhcp_access_delegate(self, context, port_data, action)

    def handle_port_metadata_access(self, context, port, is_delete=False):
        self.handle_port_metadata_access_delegate(context, port, is_delete)

    def handle_router_metadata_access(self, context,
                                      router_id, do_create=True):
        self.handle_metadata_access_delegate(self, context,
                                             router_id, do_create)
