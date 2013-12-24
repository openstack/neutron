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
#
# @author: Sylvain Afchain, eNovance SAS
# @author: Francois Eleouet, Orange
# @author: Mathieu Rohon, Orange

from neutron.common import constants as const
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import models_v2
from neutron.openstack.common import jsonutils
from neutron.openstack.common import timeutils
from neutron.plugins.ml2.drivers.l2pop import constants as l2_const
from neutron.plugins.ml2 import models as ml2_models


class L2populationDbMixin(base_db.CommonDbMixin):

    def get_agent_ip_by_host(self, session, agent_host):
        agent = self.get_agent_by_host(session, agent_host)
        if agent:
            return self.get_agent_ip(agent)

    def get_agent_ip(self, agent):
        configuration = jsonutils.loads(agent.configurations)
        return configuration.get('tunneling_ip')

    def get_agent_uptime(self, agent):
        return timeutils.delta_seconds(agent.started_at,
                                       agent.heartbeat_timestamp)

    def get_agent_tunnel_types(self, agent):
        configuration = jsonutils.loads(agent.configurations)
        return configuration.get('tunnel_types')

    def get_agent_by_host(self, session, agent_host):
        with session.begin(subtransactions=True):
            query = session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.host == agent_host,
                                 agents_db.Agent.agent_type.in_(
                                     l2_const.SUPPORTED_AGENT_TYPES))
            return query.first()

    def get_network_ports(self, session, network_id):
        with session.begin(subtransactions=True):
            query = session.query(ml2_models.PortBinding,
                                  agents_db.Agent)
            query = query.join(agents_db.Agent,
                               agents_db.Agent.host ==
                               ml2_models.PortBinding.host)
            query = query.join(models_v2.Port)
            query = query.filter(models_v2.Port.network_id == network_id,
                                 models_v2.Port.admin_state_up == True,
                                 agents_db.Agent.agent_type.in_(
                                     l2_const.SUPPORTED_AGENT_TYPES))
            return query

    def get_agent_network_active_port_count(self, session, agent_host,
                                            network_id):
        with session.begin(subtransactions=True):
            query = session.query(models_v2.Port)

            query = query.join(ml2_models.PortBinding)
            query = query.filter(models_v2.Port.network_id == network_id,
                                 models_v2.Port.status ==
                                 const.PORT_STATUS_ACTIVE,
                                 ml2_models.PortBinding.host == agent_host)
            return query.count()
