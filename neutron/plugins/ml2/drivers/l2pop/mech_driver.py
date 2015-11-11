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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import constants as const
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.i18n import _LW
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.l2pop import config  # noqa
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc

LOG = logging.getLogger(__name__)


class L2populationMechanismDriver(api.MechanismDriver,
                                  l2pop_db.L2populationDbMixin):

    def __init__(self):
        super(L2populationMechanismDriver, self).__init__()
        self.L2populationAgentNotify = l2pop_rpc.L2populationAgentNotifyAPI()

    def initialize(self):
        LOG.debug("Experimental L2 population driver")
        self.rpc_ctx = n_context.get_admin_context_without_session()
        self.migrated_ports = {}

    def _get_port_fdb_entries(self, port):
        return [l2pop_rpc.PortInfo(mac_address=port['mac_address'],
                                   ip_address=ip['ip_address'])
                for ip in port['fixed_ips']]

    def delete_port_postcommit(self, context):
        port = context.current
        agent_host = context.host

        fdb_entries = self._update_port_down(context, port, agent_host)
        self.L2populationAgentNotify.remove_fdb_entries(self.rpc_ctx,
            fdb_entries)

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
        port_infos = self._get_port_infos(
            context, orig, agent_host)
        if not port_infos:
            return
        agent, agent_host, agent_ip, segment, port_fdb_entries = port_infos

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

    def update_port_postcommit(self, context):
        port = context.current
        orig = context.original

        if (orig['mac_address'] != port['mac_address'] and
            context.status == const.PORT_STATUS_ACTIVE):
            LOG.warning(_LW("unable to modify mac_address of ACTIVE port "
                            "%s"), port['id'])
            raise ml2_exc.MechanismDriverError(method='update_port_postcommit')
        diff_ips = self._get_diff_ips(orig, port)
        if diff_ips:
            self._fixed_ips_changed(context, orig, port, diff_ips)
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            if context.status == const.PORT_STATUS_ACTIVE:
                self._update_port_up(context)
            if context.status == const.PORT_STATUS_DOWN:
                agent_host = context.host
                fdb_entries = self._update_port_down(
                        context, port, agent_host)
                self.L2populationAgentNotify.remove_fdb_entries(
                    self.rpc_ctx, fdb_entries)
        elif (context.host != context.original_host
            and context.status == const.PORT_STATUS_ACTIVE
            and not self.migrated_ports.get(orig['id'])):
            # The port has been migrated. We have to store the original
            # binding to send appropriate fdb once the port will be set
            # on the destination host
            self.migrated_ports[orig['id']] = (
                (orig, context.original_host))
        elif context.status != context.original_status:
            if context.status == const.PORT_STATUS_ACTIVE:
                self._update_port_up(context)
            elif context.status == const.PORT_STATUS_DOWN:
                fdb_entries = self._update_port_down(
                    context, port, context.host)
                self.L2populationAgentNotify.remove_fdb_entries(
                    self.rpc_ctx, fdb_entries)
            elif context.status == const.PORT_STATUS_BUILD:
                orig = self.migrated_ports.pop(port['id'], None)
                if orig:
                    original_port = orig[0]
                    original_host = orig[1]
                    # this port has been migrated: remove its entries from fdb
                    fdb_entries = self._update_port_down(
                        context, original_port, original_host)
                    self.L2populationAgentNotify.remove_fdb_entries(
                        self.rpc_ctx, fdb_entries)

    def _get_port_infos(self, context, port, agent_host):
        if not agent_host:
            return

        session = db_api.get_session()
        agent = self.get_agent_by_host(session, agent_host)
        if not agent:
            return

        agent_ip = self.get_agent_ip(agent)
        if not agent_ip:
            LOG.warning(_LW("Unable to retrieve the agent ip, check the agent "
                            "configuration."))
            return

        segment = context.bottom_bound_segment
        if not segment:
            LOG.debug("Port %(port)s updated by agent %(agent)s isn't bound "
                      "to any segment", {'port': port['id'], 'agent': agent})
            return

        network_types = self.get_agent_l2pop_network_types(agent)
        if network_types is None:
            network_types = self.get_agent_tunnel_types(agent)
        if segment['network_type'] not in network_types:
            return

        fdb_entries = self._get_port_fdb_entries(port)

        return agent, agent_host, agent_ip, segment, fdb_entries

    def _create_agent_fdb(self, session, agent, segment, network_id):
        agent_fdb_entries = {network_id:
                             {'segment_id': segment['segmentation_id'],
                              'network_type': segment['network_type'],
                              'ports': {}}}
        tunnel_network_ports = (
            self.get_dvr_active_network_ports(session, network_id).all())
        fdb_network_ports = (
            self.get_nondvr_active_network_ports(session, network_id).all())
        ports = agent_fdb_entries[network_id]['ports']
        ports.update(self._get_tunnels(
            fdb_network_ports + tunnel_network_ports,
            agent.host))
        for agent_ip, fdbs in ports.items():
            for binding, agent in fdb_network_ports:
                if self.get_agent_ip(agent) == agent_ip:
                    fdbs.extend(self._get_port_fdb_entries(binding.port))

        return agent_fdb_entries

    def _get_tunnels(self, tunnel_network_ports, exclude_host):
        agents = {}
        for _, agent in tunnel_network_ports:
            if agent.host == exclude_host:
                continue

            ip = self.get_agent_ip(agent)
            if not ip:
                LOG.debug("Unable to retrieve the agent ip, check "
                          "the agent %s configuration.", agent.host)
                continue

            if ip not in agents:
                agents[ip] = [const.FLOODING_ENTRY]

        return agents

    def _update_port_up(self, context):
        port = context.current
        agent_host = context.host
        port_infos = self._get_port_infos(context, port, agent_host)
        if not port_infos:
            return
        agent, agent_host, agent_ip, segment, port_fdb_entries = port_infos

        network_id = port['network_id']

        session = db_api.get_session()
        agent_active_ports = self.get_agent_network_active_port_count(
            session, agent_host, network_id)

        other_fdb_entries = {network_id:
                             {'segment_id': segment['segmentation_id'],
                              'network_type': segment['network_type'],
                              'ports': {agent_ip: []}}}
        other_fdb_ports = other_fdb_entries[network_id]['ports']

        if agent_active_ports == 1 or (
                self.get_agent_uptime(agent) < cfg.CONF.l2pop.agent_boot_time):
            # First port activated on current agent in this network,
            # we have to provide it with the whole list of fdb entries
            agent_fdb_entries = self._create_agent_fdb(session,
                                                       agent,
                                                       segment,
                                                       network_id)

            # And notify other agents to add flooding entry
            other_fdb_ports[agent_ip].append(const.FLOODING_ENTRY)

            if agent_fdb_entries[network_id]['ports'].keys():
                self.L2populationAgentNotify.add_fdb_entries(
                    self.rpc_ctx, agent_fdb_entries, agent_host)

        # Notify other agents to add fdb rule for current port
        if port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE:
            other_fdb_ports[agent_ip] += port_fdb_entries

        self.L2populationAgentNotify.add_fdb_entries(self.rpc_ctx,
                                                     other_fdb_entries)

    def _update_port_down(self, context, port, agent_host):
        port_infos = self._get_port_infos(context, port, agent_host)
        if not port_infos:
            return
        agent, agent_host, agent_ip, segment, port_fdb_entries = port_infos

        network_id = port['network_id']

        session = db_api.get_session()
        agent_active_ports = self.get_agent_network_active_port_count(
            session, agent_host, network_id)

        other_fdb_entries = {network_id:
                             {'segment_id': segment['segmentation_id'],
                              'network_type': segment['network_type'],
                              'ports': {agent_ip: []}}}
        if agent_active_ports == 0:
            # Agent is removing its last activated port in this network,
            # other agents needs to be notified to delete their flooding entry.
            other_fdb_entries[network_id]['ports'][agent_ip].append(
                const.FLOODING_ENTRY)
        # Notify other agents to remove fdb rules for current port
        if port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE:
            fdb_entries = port_fdb_entries
            other_fdb_entries[network_id]['ports'][agent_ip] += fdb_entries

        return other_fdb_entries
