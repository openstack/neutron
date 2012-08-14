# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Bob Kukura, Red Hat, Inc.

import logging
import os

from quantum.api import api_common
from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.common.utils import find_config_file
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import context
from quantum.openstack.common import cfg
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy
from quantum.plugins.openvswitch.common import config
from quantum.plugins.openvswitch import ovs_db_v2
from quantum import policy


LOG = logging.getLogger(__name__)


class OVSRpcCallbacks():

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, context, notifier):
        self.context = context
        self.notifier = notifier

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
        port = ovs_db_v2.get_port(device)
        if port:
            vlan_id = ovs_db_v2.get_vlan(port['network_id'])
            entry = {'device': device,
                     'vlan_id': vlan_id,
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up']}
            # Set the port status to UP
            ovs_db_v2.set_port_status(port['id'], api_common.PORT_STATUS_UP)
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
        port = ovs_db_v2.get_port(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            ovs_db_v2.set_port_status(port['id'], api_common.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug("%s can not be found in database", device)
        return entry

    def tunnel_sync(self, context, **kwargs):
        """Update new tunnel.

        Updates the datbase with the tunnel IP. All listening agents will also
        be notified about the new tunnel IP.
        """
        tunnel_ip = kwargs.get('tunnel_ip')
        # Update the database with the IP
        tunnel = ovs_db_v2.add_tunnel(tunnel_ip)
        tunnels = ovs_db_v2.get_tunnels()
        entry = dict()
        entry['tunnels'] = tunnels
        # Notify all other listening agents
        self.notifier.tunnel_update(self.context, tunnel.ip_address,
                                    tunnel.id)
        # Return the list of tunnels IP's to the agent
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
        self.topic_tunnel_update = topics.get_topic_name(topic,
                                                         config.TUNNEL,
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

    def tunnel_update(self, context, tunnel_ip, tunnel_id):
        self.fanout_cast(context,
                         self.make_msg('tunnel_update',
                                       tunnel_ip=tunnel_ip,
                                       tunnel_id=tunnel_id),
                         topic=self.topic_tunnel_update)


class OVSQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """Implement the Quantum abstractions using Open vSwitch.

    Depending on whether tunneling is enabled, either a GRE tunnel or
    a new VLAN is created for each network. An agent is relied upon to
    perform the actual OVS configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    supported_extension_aliases = ["provider"]

    def __init__(self, configfile=None):
        self.enable_tunneling = cfg.CONF.OVS.enable_tunneling
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
        options.update({"sql_max_retries": sql_max_retries})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        # update the vlan_id table based on current configuration
        ovs_db_v2.update_vlan_id_pool()
        self.rpc = cfg.CONF.AGENT.rpc
        if cfg.CONF.AGENT.rpc and cfg.CONF.AGENT.target_v2_api:
            self.setup_rpc()
        if not cfg.CONF.AGENT.target_v2_api:
            self.rpc = False

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = OVSRpcCallbacks(self.context, self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

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
            if not self.enable_tunneling:
                network['provider:vlan_id'] = ovs_db_v2.get_vlan(
                    network['id'], context.session)

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get('provider:network_type')
        physical_network = attrs.get('provider:physical_network')
        vlan_id = attrs.get('provider:vlan_id')

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        vlan_id_set = attributes.is_attr_set(vlan_id)

        if not (network_type_set or physical_network_set or vlan_id_set):
            return (None, None, None)

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        if not network_type_set:
            msg = _("provider:network_type required")
            raise q_exc.InvalidInput(error_message=msg)
        elif network_type == 'flat':
            msg = _("plugin does not support flat networks")
            raise q_exc.InvalidInput(error_message=msg)
        # REVISIT(rkukura) to be enabled in phase 3
        #    if vlan_id_set:
        #        msg = _("provider:vlan_id specified for flat network")
        #        raise q_exc.InvalidInput(error_message=msg)
        #    else:
        #        vlan_id = db.FLAT_VLAN_ID
        elif network_type == 'vlan':
            if not vlan_id_set:
                msg = _("provider:vlan_id required")
                raise q_exc.InvalidInput(error_message=msg)
        else:
            msg = _("invalid provider:network_type %s" % network_type)
            raise q_exc.InvalidInput(error_message=msg)

        if physical_network_set:
            msg = _("plugin does not support specifying physical_network")
            raise q_exc.InvalidInput(error_message=msg)
        # REVISIT(rkukura) to be enabled in phase 3
        #    if physical_network not in self.physical_networks:
        #        msg = _("unknown provider:physical_network %s" %
        #                physical_network)
        #        raise q_exc.InvalidInput(error_message=msg)
        #elif 'default' in self.physical_networks:
        #    physical_network = 'default'
        #else:
        #    msg = _("provider:physical_network required")
        #    raise q_exc.InvalidInput(error_message=msg)

        return (network_type, physical_network, vlan_id)

    def _check_provider_update(self, context, attrs):
        network_type = attrs.get('provider:network_type')
        physical_network = attrs.get('provider:physical_network')
        vlan_id = attrs.get('provider:vlan_id')

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        vlan_id_set = attributes.is_attr_set(vlan_id)

        if not (network_type_set or physical_network_set or vlan_id_set):
            return

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def create_network(self, context, network):
        (network_type, physical_network,
         vlan_id) = self._process_provider_create(context,
                                                  network['network'])

        net = super(OVSQuantumPluginV2, self).create_network(context, network)
        try:
            if not network_type:
                vlan_id = ovs_db_v2.reserve_vlan_id(context.session)
            else:
                ovs_db_v2.reserve_specific_vlan_id(vlan_id, context.session)
        except Exception:
            super(OVSQuantumPluginV2, self).delete_network(context, net['id'])
            raise

        LOG.debug("Created network: %s" % net['id'])
        ovs_db_v2.add_vlan_binding(vlan_id, str(net['id']), context.session)
        self._extend_network_dict(context, net)
        return net

    def update_network(self, context, id, network):
        self._check_provider_update(context, network['network'])

        net = super(OVSQuantumPluginV2, self).update_network(context, id,
                                                             network)
        self._extend_network_dict(context, net)
        return net

    def delete_network(self, context, id):
        vlan_id = ovs_db_v2.get_vlan(id)
        result = super(OVSQuantumPluginV2, self).delete_network(context, id)
        ovs_db_v2.release_vlan_id(vlan_id)
        if self.rpc:
            self.notifier.network_delete(self.context, id)
        return result

    def get_network(self, context, id, fields=None, verbose=None):
        net = super(OVSQuantumPluginV2, self).get_network(context, id,
                                                          None, verbose)
        self._extend_network_dict(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        nets = super(OVSQuantumPluginV2, self).get_networks(context, filters,
                                                            None, verbose)
        for net in nets:
            self._extend_network_dict(context, net)
        # TODO(rkukura): Filter on extended attributes.
        return [self._fields(net, fields) for net in nets]

    def update_port(self, context, id, port):
        if self.rpc:
            original_port = super(OVSQuantumPluginV2, self).get_port(context,
                                                                     id)
        port = super(OVSQuantumPluginV2, self).update_port(context, id, port)
        if self.rpc:
            if original_port['admin_state_up'] != port['admin_state_up']:
                vlan_id = ovs_db_v2.get_vlan(port['network_id'])
                self.notifier.port_update(self.context, port, vlan_id)
        return port
