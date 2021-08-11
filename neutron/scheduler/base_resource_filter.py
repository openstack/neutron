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

from neutron_lib.db import api as db_api
from oslo_db import exception as db_exc

from neutron.common import utils as n_utils


class BaseResourceFilter(object, metaclass=abc.ABCMeta):
    """Encapsulate logic that is specific to the resource type."""
    @abc.abstractmethod
    def filter_agents(self, plugin, context, resource):
        """Return the agents that can host the resource."""

    @n_utils.skip_exceptions(db_exc.DBError)
    def bind(self, context, agents, resource_id, force_scheduling=False):
        """Bind the resource to the agents."""
        with db_api.CONTEXT_WRITER.using(context):
            for agent in agents:
                # Load is being incremented here to reflect latest agent load
                # even within the agent report interval. This will be very
                # much necessary when bulk resource creation happens within a
                # agent report interval time.
                # NOTE: The resource being bound might or might not be of the
                # same type which is accounted for the load. It isn't a
                # problem because "+ 1" here does not meant to predict
                # precisely what the load of the agent will be. The value will
                # be corrected by the agent on the next report interval.
                agent.load += 1
                agent.update()
