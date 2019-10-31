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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import agent as agent_model


LOWEST_BINDING_INDEX = 1


class NetworkDhcpAgentBinding(model_base.BASEV2):
    """Represents binding between neutron networks and DHCP agents."""

    __table_args__ = (
        sa.UniqueConstraint(
            'network_id', 'binding_index',
            name='uniq_network_dhcp_agent_binding0network_id0binding_index0'),
        model_base.BASEV2.__table_args__
    )

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete='CASCADE'),
                           primary_key=True)
    dhcp_agent = orm.relation(agent_model.Agent, lazy='subquery')
    dhcp_agent_id = sa.Column(sa.String(36),
                              sa.ForeignKey("agents.id",
                                            ondelete='CASCADE'),
                              primary_key=True)
    binding_index = sa.Column(sa.Integer, nullable=False,
                              server_default=str(LOWEST_BINDING_INDEX))
