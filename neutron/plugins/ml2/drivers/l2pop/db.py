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
from neutron_lib.db import api as db_api
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from sqlalchemy import orm

from neutron.db.models import agent as agent_model
from neutron.db.models import l3ha as l3ha_model
from neutron.db import models_v2
from neutron.objects import agent as agent_objs
from neutron.plugins.ml2 import models as ml2_models


HA_ROUTER_PORTS = (const.DEVICE_OWNER_HA_REPLICATED_INT,
                   const.DEVICE_OWNER_ROUTER_SNAT)


def get_agent_ip_by_host(context, agent_host):
    agent = get_agent_by_host(context, agent_host)
    if agent:
        return get_agent_ip(agent)


def _get_agent_conf_dict(agent):
    configuration = agent.configurations
    if not isinstance(configuration, dict):
        configuration = jsonutils.loads(configuration)
    return configuration


def get_agent_ip(agent):
    configuration = _get_agent_conf_dict(agent)
    return configuration.get('tunneling_ip')


def get_agent_uptime(agent):
    return timeutils.delta_seconds(agent.started_at,
                                   agent.heartbeat_timestamp)


def get_agent_tunnel_types(agent):
    configuration = _get_agent_conf_dict(agent)
    return configuration.get('tunnel_types')


def get_agent_l2pop_network_types(agent):
    configuration = _get_agent_conf_dict(agent)
    return configuration.get('l2pop_network_types')


def get_agent_by_host(context, agent_host):
    """Return a L2 agent on the host."""

    agents = agent_objs.Agent.get_objects(context, host=agent_host)
    for agent in agents:
        if get_agent_ip(agent):
            return agent


def _get_active_network_ports(context, network_id):
    query = context.session.query(ml2_models.PortBinding,
                                  agent_model.Agent)
    query = query.join(
        agent_model.Agent,
        agent_model.Agent.host == ml2_models.PortBinding.host)
    query = query.join(models_v2.Port)
    query = query.options(orm.selectinload(ml2_models.PortBinding.port))
    query = query.filter(models_v2.Port.network_id == network_id,
                         models_v2.Port.status == const.PORT_STATUS_ACTIVE)
    return query


def _ha_router_interfaces_on_network_query(context, network_id):
    query = context.session.query(models_v2.Port)
    query = query.join(
        l3ha_model.L3HARouterAgentPortBinding,
        l3ha_model.L3HARouterAgentPortBinding.router_id ==
        models_v2.Port.device_id)
    return query.filter(
        models_v2.Port.network_id == network_id,
        models_v2.Port.device_owner.in_(HA_ROUTER_PORTS))


def _get_ha_router_interface_ids_subquery(context, network_id):
    query = _ha_router_interfaces_on_network_query(context, network_id)

    port_entity = orm.aliased(models_v2.Port, query.subquery())

    return context.session.query(port_entity.id).distinct()


@db_api.CONTEXT_READER
def get_nondistributed_active_network_ports(context, network_id):
    query = _get_active_network_ports(context, network_id)
    # Exclude DVR and HA router interfaces
    query = query.filter(models_v2.Port.device_owner !=
                         const.DEVICE_OWNER_DVR_INTERFACE)
    ha_iface_ids_query = _get_ha_router_interface_ids_subquery(
        context, network_id
    )
    query = query.filter(models_v2.Port.id.notin_(ha_iface_ids_query))
    return [(bind, agent) for bind, agent in query.all()
            if get_agent_ip(agent)]


def _get_dvr_active_network_ports(context, network_id):
    query = context.session.query(ml2_models.DistributedPortBinding,
                                  agent_model.Agent)
    query = query.join(agent_model.Agent,
                       agent_model.Agent.host ==
                       ml2_models.DistributedPortBinding.host)
    query = query.join(models_v2.Port)
    query = query.options(
        orm.selectinload(ml2_models.DistributedPortBinding.port))
    query = query.filter(models_v2.Port.network_id == network_id,
                         models_v2.Port.status == const.PORT_STATUS_ACTIVE,
                         models_v2.Port.device_owner ==
                         const.DEVICE_OWNER_DVR_INTERFACE)
    return [(bind, agent) for bind, agent in query.all()
            if get_agent_ip(agent)]


@db_api.CONTEXT_READER
def get_distributed_active_network_ports(context, network_id):
    return (_get_dvr_active_network_ports(context, network_id) +
            _get_ha_active_network_ports(context, network_id))


def _get_ha_active_network_ports(context, network_id):
    agents = get_ha_agents(context, network_id=network_id)
    return [(None, agent) for agent in agents]


def get_ha_agents(context, network_id=None, router_id=None):
    agents = agent_objs.Agent.get_ha_agents(context,
                                            network_id=network_id,
                                            router_id=router_id)
    return [agent for agent in agents if get_agent_ip(agent)]


def get_ha_agents_by_router_id(context, router_id):
    return get_ha_agents(context, router_id=router_id)


@db_api.CONTEXT_READER
def get_agent_network_active_port_count(context, agent_host,
                                        network_id):
    query = context.session.query(models_v2.Port)
    query1 = query.join(ml2_models.PortBinding)
    query1 = query1.filter(models_v2.Port.network_id == network_id,
                           models_v2.Port.status ==
                           const.PORT_STATUS_ACTIVE,
                           models_v2.Port.device_owner !=
                           const.DEVICE_OWNER_DVR_INTERFACE,
                           ml2_models.PortBinding.host == agent_host)

    ha_iface_ids_query = _get_ha_router_interface_ids_subquery(
        context, network_id
    )
    query1 = query1.filter(models_v2.Port.id.notin_(ha_iface_ids_query))
    ha_port_count = _get_ha_router_active_port_count(
        context, agent_host, network_id)

    query2 = query.join(ml2_models.DistributedPortBinding)
    query2 = query2.filter(models_v2.Port.network_id == network_id,
                           ml2_models.DistributedPortBinding.status ==
                           const.PORT_STATUS_ACTIVE,
                           models_v2.Port.device_owner ==
                           const.DEVICE_OWNER_DVR_INTERFACE,
                           ml2_models.DistributedPortBinding.host ==
                           agent_host)
    return query1.count() + query2.count() + ha_port_count


def _get_ha_router_active_port_count(context, agent_host, network_id):
    # Return num of HA router interfaces on the given network and host
    query = _ha_router_interfaces_on_network_query(context, network_id)
    query = query.filter(models_v2.Port.status == const.PORT_STATUS_ACTIVE)
    query = query.join(agent_model.Agent)
    query = query.filter(agent_model.Agent.host == agent_host)
    return query.count()
