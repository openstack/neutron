# Copyright 2012-2013 NEC Corporation.  All rights reserved.
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

from networking_nec.plugins.openflow import plugin

from neutron.plugins.nec import config as nec_config


class NECPluginV2(plugin.NECPluginV2Impl):

    _supported_extension_aliases = ["agent",
                                    "allowed-address-pairs",
                                    "binding",
                                    "dhcp_agent_scheduler",
                                    "external-net",
                                    "ext-gw-mode",
                                    "extraroute",
                                    "l3_agent_scheduler",
                                    "packet-filter",
                                    "quotas",
                                    "router",
                                    "router_provider",
                                    "security-group",
                                    ]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            self.setup_extension_aliases(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        nec_config.register_plugin_opts()
        super(NECPluginV2, self).__init__()
