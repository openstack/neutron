# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
#                               <yamahata at valinux co jp>
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

from quantum.plugins.ryu import ovs_quantum_plugin_base


class FakePluginDriver(ovs_quantum_plugin_base.OVSQuantumPluginDriverBase):
    def __init__(self, config):
        super(FakePluginDriver, self).__init__()

    def create_network(self, net):
        pass

    def delete_network(self, net):
        pass


class FakePlugin(ovs_quantum_plugin_base.OVSQuantumPluginBase):
    def __init__(self, configfile=None):
        super(FakePlugin, self).__init__(None, __file__, configfile)
        self.driver = FakePluginDriver(self.config)
