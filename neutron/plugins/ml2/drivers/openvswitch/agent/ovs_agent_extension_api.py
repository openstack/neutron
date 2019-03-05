# Copyright 2016 Intel Corporation.
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


class OVSCookieBridge(object):
    '''Bridge restricting flow operations to its own distinct cookie

    This class creates a bridge derived from a bridge passed at init (which
    has to inherit from OVSBridgeCookieMixin), but that has its own cookie,
    registered to the underlying bridge, and that will use this cookie in all
    flow operations.
    '''

    def __new__(cls, bridge):
        cookie_bridge = bridge.clone()
        cookie_bridge.set_agent_uuid_stamp(bridge.request_cookie())

        return cookie_bridge

    def __init__(self, bridge):
        pass


class OVSAgentExtensionAPI(object):
    '''Implements the Agent API for Open vSwitch agent.

    Extensions can gain access to this API by overriding the consume_api
    method which has been added to the AgentExtension class.
    '''

    def __init__(self, int_br, tun_br, phys_brs=None):
        super(OVSAgentExtensionAPI, self).__init__()
        self.br_int = int_br
        self.br_tun = tun_br
        self.br_phys = phys_brs or {}

    def request_int_br(self):
        """Allows extensions to request an integration bridge to use for
        extension specific flows.
        """
        return OVSCookieBridge(self.br_int)

    def request_tun_br(self):
        """Allows extensions to request a tunnel bridge to use for
        extension specific flows.

        If tunneling is not enabled, this method will return None.
        """
        if not self.br_tun:
            return None

        return OVSCookieBridge(self.br_tun)

    def request_phy_brs(self):
        """Allows extensions to request all physical bridges to use for
        extension specific flows.

        This a generator function which returns all existing physical bridges
        in the switch.
        """
        for phy_br in self.br_phys.values():
            yield OVSCookieBridge(phy_br)
