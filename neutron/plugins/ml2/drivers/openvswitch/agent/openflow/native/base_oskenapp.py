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

from os_ken.base import app_manager
from os_ken.controller import handler
from os_ken.controller import ofp_event
from os_ken.ofproto import ofproto_v1_3
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class BaseNeutronAgentOSKenApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    packet_in_handlers = []

    def register_packet_in_handler(self, caller):
        self.packet_in_handlers.append(caller)

    def unregister_packet_in_handler(self, caller):
        self.packet_in_handlers.remove(caller)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        for caller in self.packet_in_handlers:
            caller(ev)
