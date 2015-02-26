# Copyright (c) 2014 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from networking_mlnx.plugins.ml2.drivers.mlnx import constants
from oslo_config import cfg
from oslo_log import log

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers.mlnx import config  # noqa

LOG = log.getLogger(__name__)


class MlnxMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using Mellanox eSwitch L2 agent.

    The MellanoxMechanismDriver integrates the ml2 plugin with the
    Mellanox eswitch L2 agent. Port binding with this driver requires the
    Mellanox eswitch  agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        # REVISIT(irenab): update supported_vnic_types to contain
        # only VNIC_DIRECT and VNIC_MACVTAP once its possible to specify
        # vnic_type via nova API/GUI. Currently VNIC_NORMAL is included
        # to enable VM creation via GUI. It should be noted, that if
        # several MDs are capable to bing bind port on chosen host, the
        # first listed MD will bind the port for VNIC_NORMAL.
        super(MlnxMechanismDriver, self).__init__(
            n_const.AGENT_TYPE_MLNX,
            cfg.CONF.ESWITCH.vnic_type,
            {portbindings.CAP_PORT_FILTER: False},
            portbindings.VNIC_TYPES)

    def get_allowed_network_types(self, agent=None):
        return [p_constants.TYPE_LOCAL, p_constants.TYPE_FLAT,
                p_constants.TYPE_VLAN]

    def get_mappings(self, agent):
        return agent['configurations'].get('interface_mappings', {})

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            vif_type = constants.VNIC_TO_VIF_MAPPING.get(
                context.current[portbindings.VNIC_TYPE], self.vif_type)
            if (segment[api.NETWORK_TYPE] in
                    (p_constants.TYPE_FLAT, p_constants.TYPE_VLAN)):
                self.vif_details['physical_network'] = segment[
                    'physical_network']
            context.set_binding(segment[api.ID],
                                vif_type,
                                self.vif_details)
