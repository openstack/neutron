# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
# All Rights Reserved.
#
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants

from neutron.agent import securitygroups_rpc
from neutron.plugins.ml2.drivers import mech_agent


class FakeAgentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """ML2 mechanism driver for testing.

    This is a ML2 mechanism driver used by UTs in test_l2population.
    This driver implements minimum requirements for L2pop mech driver.
    As there are some agent-based mechanism drivers and OVS agent
    mech driver is not the only one to support L2pop, it is useful to
    test L2pop with multiple drivers like this to check the minimum
    requirements.

    NOTE(yamamoto): This is a modified copy of ofagent mechanism driver as
    of writing this.  There's no need to keep this synced with the "real"
    ofagent mechansim driver or its agent.
    """

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                       portbindings.OVS_HYBRID_PLUG: sg_enabled,
                       portbindings.VIF_DETAILS_CONNECTIVITY:
                           portbindings.CONNECTIVITY_L2,
                       }
        super(FakeAgentMechanismDriver, self).__init__(
            # NOTE(yamamoto): l2pop driver has a hardcoded list of
            # supported agent types.
            constants.AGENT_TYPE_OFA,
            portbindings.VIF_TYPE_OVS,
            vif_details)

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [constants.TYPE_LOCAL, constants.TYPE_FLAT,
                 constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return dict(agent['configurations'].get('interface_mappings', {}))

    @property
    def connectivity(self):
        return portbindings.CONNECTIVITY_L2


class AnotherFakeAgentMechanismDriver(FakeAgentMechanismDriver):
    pass


class FakeAgentMechanismDriverL3(FakeAgentMechanismDriver):
    """ML2 mechanism driver for testing, with L3 connectivity only"""

    def __init__(self):
        super(FakeAgentMechanismDriverL3, self).__init__()
        self.vif_details[portbindings.VIF_DETAILS_CONNECTIVITY] = (
            portbindings.CONNECTIVITY_L3)

    @property
    def connectivity(self):
        return portbindings.CONNECTIVITY_L3
