# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.ml2 import ovsvapp_driver
from oslo_log import log

from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)


class OVSvAppAgentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using OVSvApp Agent.

    The OVSvAppAgentMechanismDriver integrates the ml2 plugin with the
    OVSvApp Agent. Port binding with this driver requires the
    OVSvApp Agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    def __init__(self):
        super(OVSvAppAgentMechanismDriver, self).__init__(
            ovsvapp_const.AGENT_TYPE_OVSVAPP,
            portbindings.VIF_TYPE_OTHER,
            {portbindings.CAP_PORT_FILTER: True})
        self.ovsvapp_driver = ovsvapp_driver.OVSvAppAgentDriver()
        self.ovsvapp_driver.initialize()

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [p_const.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})
