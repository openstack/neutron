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

import time

from neutron.scheduler import base_scheduler
from neutron.scheduler import dhcp_agent_scheduler


class AlwaysTheOtherAgentScheduler(base_scheduler.BaseChanceScheduler,
                                   dhcp_agent_scheduler.AutoScheduler):
    """Choose always different agent that the ones selected previously

    This dhcp agent scheduler intended use is only in fullstack tests.
    The goal is to ensure the concurrently running schedulings to select
    different agents so the over-scheduling becomes visible in the number
    of agents scheduled to the network.
    To use this scheduler initialize your EnvironmentDescription with
    dhcp_scheduler_class='neutron.tests.fullstack.test_dhcp_agent.'
                         'AlwaysTheOtherAgentScheduler'
    """

    def __init__(self):
        self.last_selected_agent_ids = []
        super(AlwaysTheOtherAgentScheduler, self).__init__(
            dhcp_agent_scheduler.DhcpFilter())

    def select(self, plugin, context, resource_hostable_agents,
               resource_hosted_agents, num_agents_needed):
        possible_agents = []
        for agent in resource_hostable_agents:
            if agent.id in self.last_selected_agent_ids:
                continue
            else:
                possible_agents.append(agent)
        num_agents = min(len(possible_agents), num_agents_needed)
        self.last_selected_agent_ids = [
            ag.id for ag in possible_agents[0:num_agents]]

        # Note(lajoskatona): To make the race window big enough let's delay
        # the actual scheduling.
        time.sleep(5)
        return possible_agents[0:num_agents_needed]
