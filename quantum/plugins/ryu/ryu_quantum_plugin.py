# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
#                               <yamahata at valinux co jp>
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
# @author: Isaku Yamahata

from oslo.config import cfg
from ryu.app import client
from ryu.app import rest_nw_id

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import extraroute_db
from quantum.db import l3_rpc_base
from quantum.db import models_v2
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.ryu.common import config  # noqa
from quantum.plugins.ryu.db import api_v2 as db_api_v2


LOG = logging.getLogger(__name__)


class RyuRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                      l3_rpc_base.L3RpcCallbackMixin,
                      sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    RPC_API_VERSION = '1.1'

    def __init__(self, ofp_rest_api_addr):
        self.ofp_rest_api_addr = ofp_rest_api_addr

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])

    def get_ofp_rest_api(self, context, **kwargs):
        LOG.debug(_("get_ofp_rest_api: %s"), self.ofp_rest_api_addr)
        return self.ofp_rest_api_addr

    @classmethod
    def get_port_from_device(cls, device):
        port = db_api_v2.get_port_from_device(device)
        if port:
            port['device'] = device
        return port


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def port_update(self, context, port):
        self.fanout_cast(context,
                         self.make_msg('port_update', port=port),
                         topic=self.topic_port_update)


class RyuQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                         extraroute_db.ExtraRoute_db_mixin,
                         sg_db_rpc.SecurityGroupServerRpcMixin):

    _supported_extension_aliases = ["router", "extraroute", "security-group"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_if_noop_driver(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self, configfile=None):
        db.configure_db()

        self.tunnel_key = db_api_v2.TunnelKey(
            cfg.CONF.OVS.tunnel_key_min, cfg.CONF.OVS.tunnel_key_max)
        self.ofp_api_host = cfg.CONF.OVS.openflow_rest_api
        if not self.ofp_api_host:
            raise q_exc.Invalid(_('Invalid configuration. check ryu.ini'))

        self.client = client.OFPClient(self.ofp_api_host)
        self.tun_client = client.TunnelClient(self.ofp_api_host)
        self.iface_client = client.QuantumIfaceClient(self.ofp_api_host)
        for nw_id in rest_nw_id.RESERVED_NETWORK_IDS:
            if nw_id != rest_nw_id.NW_ID_UNKNOWN:
                self.client.update_network(nw_id)
        self._setup_rpc()

        # register known all network list on startup
        self._create_all_tenant_network()

    def _setup_rpc(self):
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = RyuRpcCallbacks(self.ofp_api_host)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(topics.PLUGIN, self.dispatcher, fanout=False)
        self.conn.consume_in_thread()

    def _create_all_tenant_network(self):
        for net in db_api_v2.network_all_tenant_list():
            self.client.update_network(net.id)
        for tun in self.tunnel_key.all_list():
            self.tun_client.update_tunnel_key(tun.network_id, tun.tunnel_key)
        session = db.get_session()
        for port in session.query(models_v2.Port).all():
            self.iface_client.update_network_id(port.id, port.network_id)

    def _client_create_network(self, net_id, tunnel_key):
        self.client.create_network(net_id)
        self.tun_client.create_tunnel_key(net_id, tunnel_key)

    def _client_delete_network(self, net_id):
        client.ignore_http_not_found(
            lambda: self.client.delete_network(net_id))
        client.ignore_http_not_found(
            lambda: self.tun_client.delete_tunnel_key(net_id))

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            #set up default security groups
            tenant_id = self._get_tenant_id_for_create(
                context, network['network'])
            self._ensure_default_security_group(context, tenant_id)

            net = super(RyuQuantumPluginV2, self).create_network(context,
                                                                 network)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_l3(context, net)

            tunnel_key = self.tunnel_key.allocate(session, net['id'])
            try:
                self._client_create_network(net['id'], tunnel_key)
            except:
                self._client_delete_network(net['id'])
                raise

        return net

    def update_network(self, context, id, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(RyuQuantumPluginV2, self).update_network(context, id,
                                                                 network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        self._client_delete_network(id)
        session = context.session
        with session.begin(subtransactions=True):
            self.tunnel_key.delete(session, id)
            super(RyuQuantumPluginV2, self).delete_network(context, id)

    def get_network(self, context, id, fields=None):
        net = super(RyuQuantumPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(RyuQuantumPluginV2, self).get_networks(context, filters,
                                                            None)
        for net in nets:
            self._extend_network_dict_l3(context, net)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            port = super(RyuQuantumPluginV2, self).create_port(context, port)
            self._process_port_create_security_group(
                context, port['id'], sgids)
            self._extend_port_dict_security_group(context, port)
        self.notify_security_groups_member_updated(context, port)
        self.iface_client.create_network_id(port['id'], port['network_id'])
        return port

    def delete_port(self, context, id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router. If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, id)
            port = self.get_port(context, id)
            self._delete_port_security_group_bindings(context, id)
            super(RyuQuantumPluginV2, self).delete_port(context, id)

        self.notify_security_groups_member_updated(context, port)

    def update_port(self, context, id, port):
        deleted = port['port'].get('deleted', False)
        session = context.session

        need_port_update_notify = False
        with session.begin(subtransactions=True):
            original_port = super(RyuQuantumPluginV2, self).get_port(
                context, id)
            updated_port = super(RyuQuantumPluginV2, self).update_port(
                context, id, port)
            need_port_update_notify = self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        need_port_update_notify |= (original_port['admin_state_up'] !=
                                    updated_port['admin_state_up'])

        if need_port_update_notify:
            self.notifier.port_update(context, updated_port)

        if deleted:
            db_api_v2.set_port_status(session, id, q_const.PORT_STATUS_DOWN)
        return updated_port

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(RyuQuantumPluginV2, self).get_port(context, id,
                                                            fields)
            self._extend_port_dict_security_group(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(RyuQuantumPluginV2, self).get_ports(
                context, filters, fields)
            for port in ports:
                self._extend_port_dict_security_group(context, port)
        return [self._fields(port, fields) for port in ports]
