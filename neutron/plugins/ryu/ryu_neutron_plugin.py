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

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.db import models_v2
from neutron.db import portbindings_base
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.common import constants as svc_constants
from neutron.plugins.ryu.common import config  # noqa
from neutron.plugins.ryu.db import api_v2 as db_api_v2


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


class RyuNeutronPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                         external_net_db.External_net_db_mixin,
                         extraroute_db.ExtraRoute_db_mixin,
                         l3_gwmode_db.L3_NAT_db_mixin,
                         sg_db_rpc.SecurityGroupServerRpcMixin,
                         portbindings_base.PortBindingBaseMixin):

    _supported_extension_aliases = ["external-net", "router", "ext-gw-mode",
                                    "extraroute", "security-group",
                                    "binding", "quotas"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self, configfile=None):
        super(RyuNeutronPluginV2, self).__init__()
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases,
                portbindings.OVS_HYBRID_PLUG: True
            }
        }
        portbindings_base.register_port_dict_function()
        self.tunnel_key = db_api_v2.TunnelKey(
            cfg.CONF.OVS.tunnel_key_min, cfg.CONF.OVS.tunnel_key_max)
        self.ofp_api_host = cfg.CONF.OVS.openflow_rest_api
        if not self.ofp_api_host:
            raise n_exc.Invalid(_('Invalid configuration. check ryu.ini'))

        self.client = client.OFPClient(self.ofp_api_host)
        self.tun_client = client.TunnelClient(self.ofp_api_host)
        self.iface_client = client.NeutronIfaceClient(self.ofp_api_host)
        for nw_id in rest_nw_id.RESERVED_NETWORK_IDS:
            if nw_id != rest_nw_id.NW_ID_UNKNOWN:
                self.client.update_network(nw_id)
        self._setup_rpc()

        # register known all network list on startup
        self._create_all_tenant_network()

    def _setup_rpc(self):
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = RyuRpcCallbacks(self.ofp_api_host)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.dispatcher, fanout=False)
        self.conn.consume_in_thread()

    def _create_all_tenant_network(self):
        for net in db_api_v2.network_all_tenant_list():
            self.client.update_network(net.id)
        for tun in self.tunnel_key.all_list():
            self.tun_client.update_tunnel_key(tun.network_id, tun.tunnel_key)
        session = db.get_session()
        for port in session.query(models_v2.Port):
            self.iface_client.update_network_id(port.id, port.network_id)

    def _client_create_network(self, net_id, tunnel_key):
        self.client.create_network(net_id)
        self.tun_client.create_tunnel_key(net_id, tunnel_key)

    def _client_delete_network(self, net_id):
        RyuNeutronPluginV2._safe_client_delete_network(self.safe_reference,
                                                       net_id)

    @staticmethod
    def _safe_client_delete_network(safe_reference, net_id):
        # Avoid handing naked plugin references to the client.  When
        # the client is mocked for testing, such references can
        # prevent the plugin from being deallocated.
        client.ignore_http_not_found(
            lambda: safe_reference.client.delete_network(net_id))
        client.ignore_http_not_found(
            lambda: safe_reference.tun_client.delete_tunnel_key(net_id))

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            #set up default security groups
            tenant_id = self._get_tenant_id_for_create(
                context, network['network'])
            self._ensure_default_security_group(context, tenant_id)

            net = super(RyuNeutronPluginV2, self).create_network(context,
                                                                 network)
            self._process_l3_create(context, net, network['network'])

            tunnel_key = self.tunnel_key.allocate(session, net['id'])
            try:
                self._client_create_network(net['id'], tunnel_key)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._client_delete_network(net['id'])

        return net

    def update_network(self, context, id, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(RyuNeutronPluginV2, self).update_network(context, id,
                                                                 network)
            self._process_l3_update(context, net, network['network'])
        return net

    def delete_network(self, context, id):
        self._client_delete_network(id)
        session = context.session
        with session.begin(subtransactions=True):
            self.tunnel_key.delete(session, id)
            super(RyuNeutronPluginV2, self).delete_network(context, id)

    def create_port(self, context, port):
        session = context.session
        port_data = port['port']
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            port = super(RyuNeutronPluginV2, self).create_port(context, port)
            self._process_portbindings_create_and_update(context,
                                                         port_data,
                                                         port)
            self._process_port_create_security_group(
                context, port, sgids)
        self.notify_security_groups_member_updated(context, port)
        self.iface_client.create_network_id(port['id'], port['network_id'])
        return port

    def delete_port(self, context, id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router. If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        with context.session.begin(subtransactions=True):
            router_ids = self.disassociate_floatingips(
                context, id, do_notify=False)
            port = self.get_port(context, id)
            self._delete_port_security_group_bindings(context, id)
            super(RyuNeutronPluginV2, self).delete_port(context, id)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)
        self.notify_security_groups_member_updated(context, port)

    def update_port(self, context, id, port):
        deleted = port['port'].get('deleted', False)
        session = context.session

        need_port_update_notify = False
        with session.begin(subtransactions=True):
            original_port = super(RyuNeutronPluginV2, self).get_port(
                context, id)
            updated_port = super(RyuNeutronPluginV2, self).update_port(
                context, id, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         updated_port)
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
