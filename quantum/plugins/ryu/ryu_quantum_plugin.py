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

from ryu.app import client
from ryu.app import rest_nw_id

from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db.dhcp_rpc_base import DhcpRpcCallbackMixin
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.ryu.common import config
from quantum.plugins.ryu.db import api_v2 as db_api_v2
from quantum.plugins.ryu import ofp_service_type


LOG = logging.getLogger(__name__)


class RyuQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                         l3_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router"]

    def __init__(self, configfile=None):
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        self.tunnel_key = db_api_v2.TunnelKey(
            cfg.CONF.OVS.tunnel_key_min, cfg.CONF.OVS.tunnel_key_max)
        ofp_con_host = cfg.CONF.OVS.openflow_controller
        ofp_api_host = cfg.CONF.OVS.openflow_rest_api

        if ofp_con_host is None or ofp_api_host is None:
            raise q_exc.Invalid(_('invalid configuration. check ryu.ini'))

        hosts = [(ofp_con_host, ofp_service_type.CONTROLLER),
                 (ofp_api_host, ofp_service_type.REST_API)]
        db_api_v2.set_ofp_servers(hosts)

        self.client = client.OFPClient(ofp_api_host)
        self.tun_client = client.TunnelClient(ofp_api_host)
        self.iface_client = client.QuantumIfaceClient(ofp_api_host)
        for nw_id in rest_nw_id.RESERVED_NETWORK_IDS:
            if nw_id != rest_nw_id.NW_ID_UNKNOWN:
                self.client.update_network(nw_id)
        self._setup_rpc()

        # register known all network list on startup
        self._create_all_tenant_network()

    def _setup_rpc(self):
        self.conn = rpc.create_connection(new=True)
        self.callback = DhcpRpcCallbackMixin()
        self.dispatcher = dispatcher.RpcDispatcher([self.callback])
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
        nets = self._filter_nets_l3(context, nets, filters)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        port = super(RyuQuantumPluginV2, self).create_port(context, port)
        self.iface_client.create_network_id(port['id'], port['network_id'])
        return port

    def delete_port(self, context, id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router. If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)
        return super(RyuQuantumPluginV2, self).delete_port(context, id)

    def update_port(self, context, id, port):
        deleted = port['port'].get('deleted', False)
        port = super(RyuQuantumPluginV2, self).update_port(context, id, port)
        if deleted:
            session = context.session
            db_api_v2.set_port_status(session, id, q_const.PORT_STATUS_DOWN)
        return port
