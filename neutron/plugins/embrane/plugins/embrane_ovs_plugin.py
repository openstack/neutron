# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Embrane, Inc.
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
#
# @author: Ivar Lazzaro, Embrane, Inc.

from neutron.plugins.embrane import base_plugin as base
from neutron.plugins.embrane.l2base.openvswitch import openvswitch_support
from neutron.plugins.openvswitch import ovs_neutron_plugin as l2


class EmbraneOvsPlugin(base.EmbranePlugin, l2.OVSNeutronPluginV2):
    '''EmbraneOvsPlugin.

    This plugin uses OpenVSwitch specific L2 plugin for providing L2 networks
    and the base EmbranePlugin for L3.

    '''
    _plugin_support = openvswitch_support.OpenvswitchSupport()

    def __init__(self):
        '''First run plugin specific initialization, then Embrane's.'''
        self._supported_extension_aliases.remove("l3_agent_scheduler")
        l2.OVSNeutronPluginV2.__init__(self)
        self._run_embrane_config()
