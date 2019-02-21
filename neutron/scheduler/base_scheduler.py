# Copyright (c) 2015 OpenStack Foundation.
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

import abc
from operator import attrgetter
import random

import six


@six.add_metaclass(abc.ABCMeta)
class BaseScheduler(object):
    """The base scheduler (agnostic to resource type).
       Child classes of BaseScheduler must define the
       self.resource_filter to filter agents of
       particular type.
    """
    resource_filter = None

    @abc.abstractmethod
    def select(self, plugin, context, resource_hostable_agents,
               resource_hosted_agents, num_agents_needed):
        """Return a subset of agents based on the specific scheduling logic."""

    def schedule(self, plugin, context, resource):
        """Select and bind agents to a given resource."""
        if not self.resource_filter:
            return
        # filter the agents that can host the resource
        filtered_agents_dict = self.resource_filter.filter_agents(
            plugin, context, resource)
        num_agents = filtered_agents_dict['n_agents']
        hostable_agents = filtered_agents_dict['hostable_agents']
        hosted_agents = filtered_agents_dict['hosted_agents']
        chosen_agents = self.select(plugin, context, hostable_agents,
                                    hosted_agents, num_agents)
        # bind the resource to the agents
        self.resource_filter.bind(context, chosen_agents, resource['id'])
        return chosen_agents


class BaseChanceScheduler(BaseScheduler):
    """Choose agents randomly."""

    def __init__(self, resource_filter):
        self.resource_filter = resource_filter

    def select(self, plugin, context, resource_hostable_agents,
               resource_hosted_agents, num_agents_needed):
        chosen_agents = random.sample(resource_hostable_agents,
                                      num_agents_needed)
        return chosen_agents


class BaseWeightScheduler(BaseScheduler):
    """Choose agents based on load."""

    def __init__(self, resource_filter):
        self.resource_filter = resource_filter

    def select(self, plugin, context, resource_hostable_agents,
               resource_hosted_agents, num_agents_needed):
        chosen_agents = sorted(resource_hostable_agents,
                               key=attrgetter('load'))[0:num_agents_needed]
        return chosen_agents
