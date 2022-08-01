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

from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron._i18n import _
from neutron.db import l3_hamode_db
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc

LOG = logging.getLogger(__name__)


class L2populationMechanismDriver(api.MechanismDriver):

    def __init__(self):
        super(L2populationMechanismDriver, self).__init__()
        self.L2populationAgentNotify = l2pop_rpc.L2populationAgentNotifyAPI()

    def initialize(self):
        LOG.debug("Experimental L2 population driver")
        self.rpc_ctx = n_context.get_admin_context_without_session()

    def _get_port_fdb_entries(self, port):
        # the port might be concurrently deleted
        if not port or not port.get('fixed_ips'):
            return []

        return [l2pop_rpc.PortInfo(mac_address=port['mac_address'],
                                   ip_address=ip['ip_address'])
                for ip in port['fixed_ips']]

    def _remove_flooding(self, fdb_entries):
        for network_fdb in fdb_entries.values():
            for agent_fdb in network_fdb.get('ports', {}).values():
                try:
                    agent_fdb.remove(const.FLOODING_ENTRY)
                except ValueError:
                    pass

    def check_vlan_transparency(self, context):
        """L2population driver vlan transparency support."""
        return True

    def _get_ha_port_agents_fdb(
            self, context, network_id, router_id):
        other_fdb_ports = {}
        for agent in l2pop_db.get_ha_agents_by_router_id(context, router_id):
            agent_active_ports = l2pop_db.get_agent_network_active_port_count(
                context, agent.host, network_id)
            if agent_active_ports == 0:
                ip = l2pop_db.get_agent_ip(agent)
                other_fdb_ports[ip] = [const.FLOODING_ENTRY]

        return other_fdb_ports

    def delete_port_postcommit(self, context):
        port = context.current
        agent_host = context.host
        plugin_context = context._plugin_context
        fdb_entries = self._get_agent_fdb(
            plugin_context, context.bottom_bound_segment, port, agent_host)
        if fdb_entries and l3_hamode_db.is_ha_router_port(
                plugin_context, port['device_owner'], port['device_id']):
            network_id = port['network_id']
            other_fdb_ports = self._get_ha_port_agents_fdb(
                plugin_context, network_id, port['device_id'])
            fdb_entries[network_id]['ports'] = other_fdb_ports

        self.L2populationAgentNotify.remove_fdb_entries(self.rpc_ctx,
                                                        fdb_entries)

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):
        # NOTE(cbrandily): let other mechanisms (openvswitch, linuxbridge, ...)
        # perform the filtering
        return set()

    def _get_diff_ips(self, orig, port):
        orig_ips = set([ip['ip_address'] for ip in orig['fixed_ips']])
        port_ips = set([ip['ip_address'] for ip in port['fixed_ips']])

        # check if an ip has been added or removed
        orig_chg_ips = orig_ips.difference(port_ips)
        port_chg_ips = port_ips.difference(orig_ips)

        if orig_chg_ips or port_chg_ips:
            return orig_chg_ips, port_chg_ips

    def _fixed_ips_changed(self, context, orig, port, diff_ips):
        orig_ips, port_ips = diff_ips

        if (port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE):
            agent_host = context.host
        else:
            agent_host = context.original_host

        if not agent_host:
            return

        # We should not add arp responder for non tunnel network type
        port_context = context._plugin_context
        agent = l2pop_db.get_agent_by_host(port_context, agent_host)
        segment = context.bottom_bound_segment
        if not self._validate_segment(segment, port['id'], agent):
            return

        agent_ip = l2pop_db.get_agent_ip_by_host(context._plugin_context,
                                                 agent_host)

        orig_mac_ip = [l2pop_rpc.PortInfo(mac_address=port['mac_address'],
                                          ip_address=ip)
                       for ip in orig_ips]
        port_mac_ip = [l2pop_rpc.PortInfo(mac_address=port['mac_address'],
                                          ip_address=ip)
                       for ip in port_ips]

        upd_fdb_entries = {port['network_id']: {agent_ip: {}}}

        ports = upd_fdb_entries[port['network_id']][agent_ip]
        if orig_mac_ip:
            ports['before'] = orig_mac_ip

        if port_mac_ip:
            ports['after'] = port_mac_ip

        self.L2populationAgentNotify.update_fdb_entries(
            self.rpc_ctx, {'chg_ip': upd_fdb_entries})

        return True

    def update_port_precommit(self, context):
        port = context.current
        orig = context.original

        if (orig['mac_address'] != port['mac_address'] and
                context.status == const.PORT_STATUS_ACTIVE):
            msg = _("unable to modify mac_address of ACTIVE port "
                    "%s") % port['id']
            raise exceptions.InvalidInput(error_message=msg)

    def update_port_postcommit(self, context):
        port = context.current
        orig = context.original
        plugin_context = context._plugin_context
        if l3_hamode_db.is_ha_router_port(plugin_context, port['device_owner'],
                                          port['device_id']):
            return
        diff_ips = self._get_diff_ips(orig, port)
        if diff_ips:
            self._fixed_ips_changed(context, orig, port, diff_ips)
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            if context.status == const.PORT_STATUS_ACTIVE:
                self.update_port_up(context)
            if context.status == const.PORT_STATUS_DOWN:
                agent_host = context.host
                fdb_entries = self._get_agent_fdb(
                    plugin_context, context.bottom_bound_segment, port,
                    agent_host)
                self.L2populationAgentNotify.remove_fdb_entries(
                    self.rpc_ctx, fdb_entries)
        elif (context.host != context.original_host and
              context.original_status == const.PORT_STATUS_ACTIVE and
              context.status == const.PORT_STATUS_DOWN):
            # The port has been migrated. Send notification about port
            # removal from old host.
            fdb_entries = self._get_agent_fdb(
                plugin_context, context.original_bottom_bound_segment,
                orig, context.original_host)
            self.L2populationAgentNotify.remove_fdb_entries(
                self.rpc_ctx, fdb_entries)
        elif context.status != context.original_status:
            if context.status == const.PORT_STATUS_ACTIVE:
                self.update_port_up(context)
            elif context.status == const.PORT_STATUS_DOWN:
                fdb_entries = self._get_agent_fdb(
                    plugin_context, context.bottom_bound_segment, port,
                    context.host)
                self.L2populationAgentNotify.remove_fdb_entries(
                    self.rpc_ctx, fdb_entries)

    def _validate_segment(self, segment, port_id, agent):
        if not segment:
            LOG.debug("Port %(port)s updated by agent %(agent)s isn't bound "
                      "to any segment", {'port': port_id, 'agent': agent})
            return False

        network_types = l2pop_db.get_agent_l2pop_network_types(agent)
        if network_types is None:
            network_types = l2pop_db.get_agent_tunnel_types(agent)
        if segment['network_type'] not in network_types:
            return False

        return True

    def _create_agent_fdb(self, context, agent, segment, network_id):
        agent_fdb_entries = {network_id:
                             {'segment_id': segment['segmentation_id'],
                              'network_type': segment['network_type'],
                              'ports': {}}}
        tunnel_network_ports = (
            l2pop_db.get_distributed_active_network_ports(context, network_id))
        fdb_network_ports = (
            l2pop_db.get_nondistributed_active_network_ports(context,
                                                             network_id))
        ports = agent_fdb_entries[network_id]['ports']
        ports.update(self._get_tunnels(
            fdb_network_ports + tunnel_network_ports,
            agent.host))
        for agent_ip, fdbs in ports.items():
            for binding, agent in fdb_network_ports:
                if l2pop_db.get_agent_ip(agent) == agent_ip:
                    fdbs.extend(self._get_port_fdb_entries(binding.port))

        return agent_fdb_entries

    def _get_tunnels(self, tunnel_network_ports, exclude_host):
        agents = {}
        for __, agent in tunnel_network_ports:
            if agent.host == exclude_host:
                continue

            ip = l2pop_db.get_agent_ip(agent)
            if not ip:
                LOG.debug("Unable to retrieve the agent ip, check "
                          "the agent %s configuration.", agent.host)
                continue

            if ip not in agents:
                agents[ip] = [const.FLOODING_ENTRY]

        return agents

    def update_port_down(self, context):
        port = context.current
        agent_host = context.host
        l3plugin = directory.get_plugin(plugin_constants.L3)
        # when agent transitions to backup, don't remove flood flows
        if agent_host and l3plugin and getattr(l3plugin,
                                               "list_router_ids_on_host",
                                               None):
            admin_context = n_context.get_admin_context()
            port_context = context._plugin_context
            fdb_entries = self._get_agent_fdb(
                port_context, context.bottom_bound_segment, port, agent_host,
                include_ha_router_ports=True)
            if (fdb_entries and
                l3plugin.list_router_ids_on_host(
                    admin_context, agent_host, [port['device_id']])):
                # NOTE(slaweq): in case this is HA router, remove unicast
                # entries to this port but don't remove flood entry
                self._remove_flooding(fdb_entries)
            self.L2populationAgentNotify.remove_fdb_entries(
                self.rpc_ctx, fdb_entries)

    def update_port_up(self, context, refresh_tunnels=False):
        port = context.current
        agent_host = context.host
        port_context = context._plugin_context
        agent = l2pop_db.get_agent_by_host(port_context, agent_host)
        if not agent:
            LOG.warning("Unable to retrieve active L2 agent on host %s",
                        agent_host)
            return

        segment = context.bottom_bound_segment
        if not self._validate_segment(segment, port['id'], agent):
            return

        network_id = port['network_id']

        agent_active_ports = l2pop_db.get_agent_network_active_port_count(
            port_context, agent_host, network_id)
        LOG.debug("host: %s, agent_active_ports: %s, refresh_tunnels: %s",
                  agent_host, agent_active_ports, refresh_tunnels)
        agent_ip = l2pop_db.get_agent_ip(agent)
        other_fdb_entries = self._get_fdb_entries_template(
            segment, agent_ip, network_id)
        other_fdb_ports = other_fdb_entries[network_id]['ports']

        # with high concurrency more than 1 port may be activated on an agent
        # at the same time (like VM port + a DVR port) so checking for 1 or 2
        is_first_port = agent_active_ports in (1, 2)
        if is_first_port or refresh_tunnels:
            # First port(s) activated on current agent in this network,
            # we have to provide it with the whole list of fdb entries
            agent_fdb_entries = self._create_agent_fdb(port_context,
                                                       agent,
                                                       segment,
                                                       network_id)

            # And notify other agents to add flooding entry
            other_fdb_ports[agent_ip].append(const.FLOODING_ENTRY)

            if agent_fdb_entries[network_id]['ports'].keys():
                self.L2populationAgentNotify.add_fdb_entries(
                    self.rpc_ctx, agent_fdb_entries, agent_host)

        # Notify other agents to add fdb rule for current port
        if (port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE and
            not l3_hamode_db.is_ha_router_port(
                port_context, port['device_owner'], port['device_id'])):
            other_fdb_ports[agent_ip] += self._get_port_fdb_entries(port)

        self.L2populationAgentNotify.add_fdb_entries(self.rpc_ctx,
                                                     other_fdb_entries)

    def _get_agent_fdb(self, context, segment, port, agent_host,
                       include_ha_router_ports=False):
        if not agent_host:
            return

        agent = l2pop_db.get_agent_by_host(context,
                                           agent_host)
        if not agent:
            LOG.warning("Unable to retrieve active L2 agent on host %s",
                        agent_host)
            return
        if not self._validate_segment(segment, port['id'], agent):
            return

        network_id = port['network_id']

        agent_active_ports = l2pop_db.get_agent_network_active_port_count(
            context, agent_host, network_id)

        agent_ip = l2pop_db.get_agent_ip(agent)
        other_fdb_entries = self._get_fdb_entries_template(
            segment, agent_ip, port['network_id'])
        if agent_active_ports == 0:
            # Agent is removing its last activated port in this network,
            # other agents needs to be notified to delete their flooding entry.
            other_fdb_entries[network_id]['ports'][agent_ip].append(
                const.FLOODING_ENTRY)
        # Notify other agents to remove fdb rules for current port
        if (port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE and
           (include_ha_router_ports or
            not l3_hamode_db.is_ha_router_port(context,
                                               port['device_owner'],
                                               port['device_id']))):
            fdb_entries = self._get_port_fdb_entries(port)
            other_fdb_entries[network_id]['ports'][agent_ip] += fdb_entries

        return other_fdb_entries

    @classmethod
    def _get_fdb_entries_template(cls, segment, agent_ip, network_id):
        return {
            network_id:
                {'segment_id': segment['segmentation_id'],
                 'network_type': segment['network_type'],
                 'ports': {agent_ip: []}}}
