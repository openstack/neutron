# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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


from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import ofswitch


class OVSAgentBridge(ofswitch.OpenFlowSwitchMixin, ovs_lib.OVSBridge):
    """Common code for bridges used by OVS agent"""

    def setup_controllers(self, conf):
        self.set_protocols("[OpenFlow10]")
        self.del_controller()

    def drop_port(self, in_port):
        self.install_drop(priority=2, in_port=in_port)
