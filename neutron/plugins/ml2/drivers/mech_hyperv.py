# Copyright (c) 2013 OpenStack Foundation
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

import re

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)


class HypervMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using hyperv L2 agent.

    The HypervMechanismDriver integrates the ml2 plugin with the
    hyperv L2 agent. Port binding with this driver requires the hyperv
    agent to be running on the port's host, and that agent to have
    connectivity to at least one segment of the port's network.
    """

    def __init__(self):
        super(HypervMechanismDriver, self).__init__(
            constants.AGENT_TYPE_HYPERV,
            portbindings.VIF_TYPE_HYPERV,
            {portbindings.CAP_PORT_FILTER: False})

    def get_allowed_network_types(self, agent=None):
        return [p_constants.TYPE_LOCAL, p_constants.TYPE_FLAT,
                p_constants.TYPE_VLAN]

    def get_mappings(self, agent):
        return agent['configurations'].get('vswitch_mappings', {})

    def physnet_in_mappings(self, physnet, mappings):
        return any(re.match(pattern, physnet) for pattern in mappings)
