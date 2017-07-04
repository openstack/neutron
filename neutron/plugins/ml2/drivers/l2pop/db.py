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
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from sqlalchemy import orm

from neutron.db.models import agent as agent_model
from neutron.db.models import l3ha as l3ha_model
from neutron.db import models_v2
from neutron.plugins.ml2 import models as ml2_models


HA_ROUTER_PORTS = (const.DEVICE_OWNER_HA_REPLICATED_INT,
                   const.DEVICE_OWNER_ROUTER_SNAT)


def get_agent_ip_by_host(session, agent_host):
    agent = get_agent_by_host(session, agent_host)
    if agent:
        return get_agent_ip(agent)


def get_agent_ip(agent):
    configuration = jsonutils.loads(agent.configurations)
    return configuration.get('tunneling_ip')


def get_agent_uptime(agent):
    return timeutils.delta_seconds(agent.started_at,
                                   agent.heartbeat_timestamp)


def get_agent_tunnel_types(agent):
    configuration = jsonutils.loads(agent.configurations)
    return configuration.get('tunnel_types')


def get_agent_l2pop_network_types(agent):
    configuration = jsonutils.loads(agent.configurations)
    return configuration.get('l2pop_network_types')


def get_agent_by_host(session, agent_host):
    """Return a L2 agent on the host."""

    with session.begin(subtransactions=True):
        query = session.query(agent_model.Agent)
        query = query.filter(agent_model.Agent.host == agent_host)
    for agent in query:
        if get_agent_ip(agent):
            return agent


def _get_active_network_ports(session, network_id):
    with session.begin(subtransactions=True):
        query = session.query(ml2_models.PortBinding, agent_model.Agent)
        query = query.join(agent_model.Agent,
            agent_model.Agent.host == ml2_models.PortBinding.host)
        query = query.join(models_v2.Port)
        query = query.options(orm.subqueryload(ml2_models.PortBinding.port))
        query = query.filter(models_v2.Port.network_id == network_id,
                             models_v2.Port.status == const.PORT_STATUS_ACTIVE)
        return query


def _ha_router_interfaces_on_network_query(session, network_id):
    query = session.query(models_v2.Port)
    query = query.join(l3ha_model.L3HARouterAgentPortBinding,
        l3ha_model.L3HARouterAgentPortBinding.router_id ==
        models_v2.Port.device_id)
    return query.filter(
        models_v2.Port.network_id == network_id,
        models_v2.Port.device_owner.in_(HA_ROUTER_PORTS))


def _get_ha_router_interface_ids(session, network_id):
    query = _ha_router_interfaces_on_network_query(session, network_id)
    return query.from_self(models_v2.Port.id).distinct()


def get_nondistributed_active_network_ports(session, network_id):
    query = _get_active_network_ports(session, network_id)
    # Exclude DVR and HA router interfaces
    query = query.filter(models_v2.Port.device_owner !=
                         const.DEVICE_OWNER_DVR_INTERFACE)
    ha_iface_ids_query = _get_ha_router_interface_ids(session, network_id)
    query = query.filter(models_v2.Port.id.notin_(ha_iface_ids_query))
    return [(bind, agent) for bind, agent in query.all()
            if get_agent_ip(agent)]


def get_dvr_active_network_ports(session, network_id):
    with session.begin(subtransactions=True):
        query = session.query(ml2_models.DistributedPortBinding,
                              agent_model.Agent)
        query = query.join(agent_model.Agent,
                           agent_model.Agent.host ==
                           ml2_models.DistributedPortBinding.host)
        query = query.join(models_v2.Port)
        query = query.options(
            orm.subqueryload(ml2_models.DistributedPortBinding.port))
        query = query.filter(models_v2.Port.network_id == network_id,
                             models_v2.Port.status == const.PORT_STATUS_ACTIVE,
                             models_v2.Port.device_owner ==
                             const.DEVICE_OWNER_DVR_INTERFACE)
    return [(bind, agent) for bind, agent in query.all()
            if get_agent_ip(agent)]


def get_distributed_active_network_ports(session, network_id):
    return (get_dvr_active_network_ports(session, network_id) +
            get_ha_active_network_ports(session, network_id))


def get_ha_active_network_ports(session, network_id):
    agents = get_ha_agents(session, network_id=network_id)
    return [(None, agent) for agent in agents]


def get_ha_agents(session, network_id=None, router_id=None):
    query = session.query(agent_model.Agent.host).distinct()
    query = query.join(l3ha_model.L3HARouterAgentPortBinding,
                       l3ha_model.L3HARouterAgentPortBinding.l3_agent_id ==
                       agent_model.Agent.id)
    if router_id:
        query = query.filter(
            l3ha_model.L3HARouterAgentPortBinding.router_id == router_id)
    elif network_id:
        query = query.join(models_v2.Port, models_v2.Port.device_id ==
                           l3ha_model.L3HARouterAgentPortBinding.router_id)
        query = query.filter(models_v2.Port.network_id == network_id,
                             models_v2.Port.status == const.PORT_STATUS_ACTIVE,
                             models_v2.Port.device_owner.in_(HA_ROUTER_PORTS))
    else:
        return []
    # L3HARouterAgentPortBinding will have l3 agent ids of hosting agents.
    # But we need l2 agent(for tunneling ip) while creating FDB entries.
    agents_query = session.query(agent_model.Agent)
    agents_query = agents_query.filter(agent_model.Agent.host.in_(query))
    return [agent for agent in agents_query
            if get_agent_ip(agent)]


def get_ha_agents_by_router_id(session, router_id):
    return get_ha_agents(session, router_id=router_id)


def get_agent_network_active_port_count(session, agent_host,
                                        network_id):
    with session.begin(subtransactions=True):
        query = session.query(models_v2.Port)
        query1 = query.join(ml2_models.PortBinding)
        query1 = query1.filter(models_v2.Port.network_id == network_id,
                               models_v2.Port.status ==
                               const.PORT_STATUS_ACTIVE,
                               models_v2.Port.device_owner !=
                               const.DEVICE_OWNER_DVR_INTERFACE,
                               ml2_models.PortBinding.host == agent_host)

        ha_iface_ids_query = _get_ha_router_interface_ids(session, network_id)
        query1 = query1.filter(models_v2.Port.id.notin_(ha_iface_ids_query))
        ha_port_count = get_ha_router_active_port_count(
            session, agent_host, network_id)

        query2 = query.join(ml2_models.DistributedPortBinding)
        query2 = query2.filter(models_v2.Port.network_id == network_id,
                               ml2_models.DistributedPortBinding.status ==
                               const.PORT_STATUS_ACTIVE,
                               models_v2.Port.device_owner ==
                               const.DEVICE_OWNER_DVR_INTERFACE,
                               ml2_models.DistributedPortBinding.host ==
                               agent_host)
        return (query1.count() + query2.count() + ha_port_count)


def get_ha_router_active_port_count(session, agent_host, network_id):
    # Return num of HA router interfaces on the given network and host
    query = _ha_router_interfaces_on_network_query(session, network_id)
    query = query.filter(models_v2.Port.status == const.PORT_STATUS_ACTIVE)
    query = query.join(agent_model.Agent)
    query = query.filter(agent_model.Agent.host == agent_host)
    return query.count()
