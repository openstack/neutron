# Copyright 2016 Hewlett Packard Enterprise Development Company LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from netaddr import IPAddress
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.api.rpc.agentnotifiers import bgp_dr_rpc_agent_api
from neutron.api.rpc.handlers import bgp_speaker_rpc as bs_rpc
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db
from neutron.extensions import bgp as bgp_ext
from neutron.extensions import bgp_dragentscheduler as dras_ext
from neutron.services.bgp.common import constants as bgp_consts
from neutron.services import service_base

PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_svc_plugin'
LOG = logging.getLogger(__name__)


class BgpPlugin(service_base.ServicePluginBase,
                bgp_db.BgpDbMixin,
                bgp_dragentscheduler_db.BgpDrAgentSchedulerDbMixin):

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS,
                                   dras_ext.BGP_DRAGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        super(BgpPlugin, self).__init__()
        self.bgp_drscheduler = importutils.import_object(
            cfg.CONF.bgp_drscheduler_driver)
        self._setup_rpc()
        self._register_callbacks()

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for tenant networks, floating IP's, and DVR host routes.")

    def _setup_rpc(self):
        self.topic = bgp_consts.BGP_PLUGIN
        self.conn = n_rpc.create_connection()
        self.agent_notifiers[bgp_consts.AGENT_TYPE_BGP_ROUTING] = (
            bgp_dr_rpc_agent_api.BgpDrAgentNotifyApi()
        )
        self._bgp_rpc = self.agent_notifiers[bgp_consts.AGENT_TYPE_BGP_ROUTING]
        self.endpoints = [bs_rpc.BgpSpeakerRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def _register_callbacks(self):
        registry.subscribe(self.floatingip_update_callback,
                           resources.FLOATING_IP,
                           events.AFTER_UPDATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.BEFORE_CREATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_DELETE)

    def create_bgp_speaker(self, context, bgp_speaker):
        bgp_speaker = super(BgpPlugin, self).create_bgp_speaker(context,
                                                                bgp_speaker)
        return bgp_speaker

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        hosted_bgp_dragents = self.get_dragents_hosting_bgp_speakers(
                                                             context,
                                                             [bgp_speaker_id])
        super(BgpPlugin, self).delete_bgp_speaker(context, bgp_speaker_id)
        for agent in hosted_bgp_dragents:
            self._bgp_rpc.bgp_speaker_removed(context,
                                              bgp_speaker_id,
                                              agent.host)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        ret_value = super(BgpPlugin, self).add_bgp_peer(context,
                                                        bgp_speaker_id,
                                                        bgp_peer_info)
        hosted_bgp_dragents = self.get_dragents_hosting_bgp_speakers(
                                                             context,
                                                             [bgp_speaker_id])
        for agent in hosted_bgp_dragents:
            self._bgp_rpc.bgp_peer_associated(context, bgp_speaker_id,
                                              ret_value['bgp_peer_id'],
                                              agent.host)
        return ret_value

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        hosted_bgp_dragents = self.get_dragents_hosting_bgp_speakers(
            context, [bgp_speaker_id])

        ret_value = super(BgpPlugin, self).remove_bgp_peer(context,
                                                           bgp_speaker_id,
                                                           bgp_peer_info)

        for agent in hosted_bgp_dragents:
            self._bgp_rpc.bgp_peer_disassociated(context,
                                                 bgp_speaker_id,
                                                 ret_value['bgp_peer_id'],
                                                 agent.host)

    def floatingip_update_callback(self, resource, event, trigger, **kwargs):
        if event != events.AFTER_UPDATE:
            return

        ctx = context.get_admin_context()
        new_router_id = kwargs['router_id']
        last_router_id = kwargs['last_known_router_id']
        next_hop = kwargs['next_hop']
        dest = kwargs['floating_ip_address'] + '/32'
        bgp_speakers = self._bgp_speakers_for_gw_network_by_family(
            ctx,
            kwargs['floating_network_id'],
            n_const.IP_VERSION_4)

        if last_router_id and new_router_id != last_router_id:
            for bgp_speaker in bgp_speakers:
                self.stop_route_advertisements(ctx, self._bgp_rpc,
                                               bgp_speaker.id, [dest])

        if next_hop and new_router_id != last_router_id:
            new_host_route = {'destination': dest, 'next_hop': next_hop}
            for bgp_speaker in bgp_speakers:
                self.start_route_advertisements(ctx, self._bgp_rpc,
                                                bgp_speaker.id,
                                                [new_host_route])

    def router_interface_callback(self, resource, event, trigger, **kwargs):
        if event == events.AFTER_CREATE:
            self._handle_router_interface_after_create(**kwargs)
        if event == events.AFTER_DELETE:
            gw_network = kwargs['network_id']
            next_hops = self._next_hops_from_gateway_ips(
                                                        kwargs['gateway_ips'])
            ctx = context.get_admin_context()
            speakers = self._bgp_speakers_for_gateway_network(ctx, gw_network)
            for speaker in speakers:
                routes = self._route_list_from_prefixes_and_next_hop(
                                                kwargs['cidrs'],
                                                next_hops[speaker.ip_version])
                self._handle_router_interface_after_delete(gw_network, routes)

    def _handle_router_interface_after_create(self, **kwargs):
        gw_network = kwargs['network_id']
        if not gw_network:
            return

        ctx = context.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            speakers = self._bgp_speakers_for_gateway_network(ctx,
                                                              gw_network)
            next_hops = self._next_hops_from_gateway_ips(
                                                    kwargs['gateway_ips'])

            for speaker in speakers:
                prefixes = self._tenant_prefixes_by_router(
                                                      ctx,
                                                      kwargs['router_id'],
                                                      speaker.id)
                next_hop = next_hops.get(speaker.ip_version)
                if next_hop:
                    rl = self._route_list_from_prefixes_and_next_hop(prefixes,
                                                                     next_hop)
                    self.start_route_advertisements(ctx,
                                                    self._bgp_rpc,
                                                    speaker.id,
                                                    rl)

    def router_gateway_callback(self, resource, event, trigger, **kwargs):
        if event == events.AFTER_CREATE:
            self._handle_router_gateway_after_create(**kwargs)
        if event == events.AFTER_DELETE:
            gw_network = kwargs['network_id']
            router_id = kwargs['router_id']
            next_hops = self._next_hops_from_gateway_ips(
                                                        kwargs['gateway_ips'])
            ctx = context.get_admin_context()
            speakers = self._bgp_speakers_for_gateway_network(ctx, gw_network)
            for speaker in speakers:
                if speaker.ip_version in next_hops:
                    next_hop = next_hops[speaker.ip_version]
                    prefixes = self._tenant_prefixes_by_router(ctx,
                                                               router_id,
                                                               speaker.id)
                    routes = self._route_list_from_prefixes_and_next_hop(
                                                                     prefixes,
                                                                     next_hop)
                self._handle_router_interface_after_delete(gw_network, routes)

    def _handle_router_gateway_after_create(self, **kwargs):
        ctx = context.get_admin_context()
        gw_network = kwargs['network_id']
        router_id = kwargs['router_id']
        with ctx.session.begin(subtransactions=True):
            speakers = self._bgp_speakers_for_gateway_network(ctx,
                                                              gw_network)
            next_hops = self._next_hops_from_gateway_ips(kwargs['gw_ips'])

            for speaker in speakers:
                if speaker.ip_version in next_hops:
                    next_hop = next_hops[speaker.ip_version]
                    prefixes = self._tenant_prefixes_by_router(ctx,
                                                               router_id,
                                                               speaker.id)
                    routes = self._route_list_from_prefixes_and_next_hop(
                                                                     prefixes,
                                                                     next_hop)
                    self.start_route_advertisements(ctx, self._bgp_rpc,
                                                    speaker.id, routes)

    def _handle_router_interface_after_delete(self, gw_network, routes):
        if gw_network and routes:
            ctx = context.get_admin_context()
            speakers = self._bgp_speakers_for_gateway_network(ctx, gw_network)
            for speaker in speakers:
                self.stop_route_advertisements(ctx, self._bgp_rpc,
                                               speaker.id, routes)

    def _next_hops_from_gateway_ips(self, gw_ips):
        if gw_ips:
            return {IPAddress(ip).version: ip for ip in gw_ips}
        return {}

    def start_route_advertisements(self, ctx, bgp_rpc,
                                   bgp_speaker_id, routes):
        agents = self.list_dragent_hosting_bgp_speaker(ctx, bgp_speaker_id)
        for agent in agents['agents']:
            bgp_rpc.bgp_routes_advertisement(ctx,
                                             bgp_speaker_id,
                                             routes,
                                             agent['host'])

        msg = "Starting route advertisements for %s on BgpSpeaker %s"
        self._debug_log_for_routes(msg, routes, bgp_speaker_id)

    def stop_route_advertisements(self, ctx, bgp_rpc,
                                  bgp_speaker_id, routes):
        agents = self.list_dragent_hosting_bgp_speaker(ctx, bgp_speaker_id)
        for agent in agents['agents']:
            bgp_rpc.bgp_routes_withdrawal(ctx,
                                          bgp_speaker_id,
                                          routes,
                                          agent['host'])

        msg = "Stopping route advertisements for %s on BgpSpeaker %s"
        self._debug_log_for_routes(msg, routes, bgp_speaker_id)

    def _debug_log_for_routes(self, msg, routes, bgp_speaker_id):

        # Could have a large number of routes passed, check log level first
        if LOG.isEnabledFor(logging.DEBUG):
            for route in routes:
                LOG.debug(msg, route, bgp_speaker_id)
