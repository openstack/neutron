# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Based on openvswitch mechanism driver.
#
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
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)


class OfagentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using ofagent L2 agent.

    The OfagentMechanismDriver integrates the ml2 plugin with the
    ofagent L2 agent. Port binding with this driver requires the
    ofagent agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        super(OfagentMechanismDriver, self).__init__(
            constants.AGENT_TYPE_OFA,
            portbindings.VIF_TYPE_OVS,
            {portbindings.CAP_PORT_FILTER: True,
             portbindings.OVS_HYBRID_PLUG: True})

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('bridge_mappings', {})
        tunnel_types = agent['configurations'].get('tunnel_types', [])
        LOG.debug(_("Checking segment: %(segment)s "
                    "for mappings: %(mappings)s "
                    "with tunnel_types: %(tunnel_types)s"),
                  {'segment': segment, 'mappings': mappings,
                   'tunnel_types': tunnel_types})
        network_type = segment[api.NETWORK_TYPE]
        return (
            network_type == p_const.TYPE_LOCAL or
            network_type in tunnel_types or
            (network_type in [p_const.TYPE_FLAT, p_const.TYPE_VLAN] and
                segment[api.PHYSICAL_NETWORK] in mappings)
        )
