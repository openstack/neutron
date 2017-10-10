# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry


def notify_init_event(agent_type, agent):
    """Notify init event for the specified agent."""
    registry.publish(agent_type, events.AFTER_INIT, agent)


def register(callback, agent_type):
    """Subscribe callback to init event for the specified agent.

    :param agent_type: an agent type as defined in neutron_lib.constants.
    :param callback: a callback that can process the agent init event.
    """
    registry.subscribe(callback, agent_type, events.AFTER_INIT)
