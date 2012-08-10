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

import logging

from quantum.api import api_common
from quantum.api.v2 import attributes
from quantum.common import topics
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import context
from quantum.openstack.common import cfg
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy
from quantum.plugins.linuxbridge.db import l2network_db as cdb
from quantum import policy


LOG = logging.getLogger(__name__)


class LinuxBridgeRpcCallbacks():

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'
    # Device names start with "tap"
    TAP_PREFIX_LEN = 3

    def __init__(self, context):
        self.context = context

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])

    def get_device_details(self, context, **kwargs):
        """Agent requests device details"""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %s details requested from %s", device, agent_id)
        port = cdb.get_port_from_device(device[self.TAP_PREFIX_LEN:])
        if port:
            vlan_binding = cdb.get_vlan_binding(port['network_id'])
            entry = {'device': device,
                     'vlan_id': vlan_binding['vlan_id'],
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up']}
            # Set the port status to UP
            cdb.set_port_status(port['id'], api_common.OperationalStatus.UP)
        else:
            entry = {'device': device}
            LOG.debug("%s can not be found in database", device)
        return entry

    def update_device_down(self, context, **kwargs):
        """Device no longer exists on agent"""
        # (TODO) garyk - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %s no longer exists on %s", device, agent_id)
        port = cdb.get_port_from_device(device[self.TAP_PREFIX_LEN:])
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            cdb.set_port_status(port['id'], api_common.OperationalStatus.DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug("%s can not be found in database", device)
        return entry


class AgentNotifierApi(proxy.RpcProxy):
    '''Agent side of the linux bridge rpc API.

    API version history:
        1.0 - Initial version.

    '''

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
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, vlan_id):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       vlan_id=vlan_id),
                         topic=self.topic_port_update)


class LinuxBridgePluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """Implement the Quantum abstractions using Linux bridging.

    A new VLAN is created for each network.  An agent is relied upon
    to perform the actual Linux bridge configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.
    """

    supported_extension_aliases = ["provider"]

    def __init__(self):
        cdb.initialize(base=models_v2.model_base.BASEV2)
        self.rpc = cfg.CONF.AGENT.rpc
        if cfg.CONF.AGENT.rpc and cfg.CONF.AGENT.target_v2_api:
            self.setup_rpc()
        if not cfg.CONF.AGENT.target_v2_api:
            self.rpc = False
        LOG.debug("Linux Bridge Plugin initialization complete")

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        self.conn = rpc.create_connection(new=True)
        self.callbacks = LinuxBridgeRpcCallbacks(self.context)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        self.notifier = AgentNotifierApi(topics.AGENT)

    # TODO(rkukura) Use core mechanism for attribute authorization
    # when available.

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
                            "extension:provider_network:view",
                            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:provider_network:set",
                              network)

    def _extend_network_dict(self, context, network):
        if self._check_provider_view_auth(context, network):
            vlan_binding = cdb.get_vlan_binding(network['id'])
            network['provider:vlan_id'] = vlan_binding['vlan_id']

    def create_network(self, context, network):
        net = super(LinuxBridgePluginV2, self).create_network(context,
                                                              network)
        try:
            vlan_id = network['network'].get('provider:vlan_id')
            if vlan_id not in (None, attributes.ATTR_NOT_SPECIFIED):
                self._enforce_provider_set_auth(context, net)
                cdb.reserve_specific_vlanid(int(vlan_id))
            else:
                vlan_id = cdb.reserve_vlanid()
            cdb.add_vlan_binding(vlan_id, net['id'])
            self._extend_network_dict(context, net)
        except:
            super(LinuxBridgePluginV2, self).delete_network(context,
                                                            net['id'])
            raise

        return net

    def update_network(self, context, id, network):
        net = super(LinuxBridgePluginV2, self).update_network(context, id,
                                                              network)
        self._extend_network_dict(context, net)
        return net

    def delete_network(self, context, id):
        vlan_binding = cdb.get_vlan_binding(id)
        result = super(LinuxBridgePluginV2, self).delete_network(context, id)
        cdb.release_vlanid(vlan_binding['vlan_id'])
        if self.rpc:
            self.notifier.network_delete(self.context, id)
        return result

    def get_network(self, context, id, fields=None, verbose=None):
        net = super(LinuxBridgePluginV2, self).get_network(context, id,
                                                           None, verbose)
        self._extend_network_dict(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        nets = super(LinuxBridgePluginV2, self).get_networks(context, filters,
                                                             None, verbose)
        for net in nets:
            self._extend_network_dict(context, net)
        # TODO(rkukura): Filter on extended attributes.
        return [self._fields(net, fields) for net in nets]

    def update_port(self, context, id, port):
        if self.rpc:
            original_port = super(LinuxBridgePluginV2, self).get_port(context,
                                                                      id)
        port = super(LinuxBridgePluginV2, self).update_port(context, id, port)
        if self.rpc:
            if original_port['admin_state_up'] != port['admin_state_up']:
                vlan_binding = cdb.get_vlan_binding(port['network_id'])
                self.notifier.port_update(self.context, port,
                                          vlan_binding['vlan_id'])
        return port
