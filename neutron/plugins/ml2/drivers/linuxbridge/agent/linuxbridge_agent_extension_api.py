# Copyright 2017 OVH SAS
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


class LinuxbridgeAgentExtensionAPI(object):
    '''Implements the Agent API for L2 agent.

    Extensions can gain access to this API by overriding the consume_api
    method which has been added to the AgentExtension class.
    '''

    def __init__(self, iptables_manager):
        super(LinuxbridgeAgentExtensionAPI, self).__init__()
        self.iptables_manager = iptables_manager

    def get_iptables_manager(self):
        """Allows extensions to get an iptables manager, used by agent,
        to use for managing extension specific iptables rules
        """
        return self.iptables_manager
