# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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

from networking_plumgrid.neutron.plugins import plugin


class NeutronPluginPLUMgridV2(plugin.NeutronPluginPLUMgridV2):

    supported_extension_aliases = ["binding", "external-net", "extraroute",
                                   "provider", "quotas", "router",
                                   "security-group"]

    def __init__(self):
        super(NeutronPluginPLUMgridV2, self).__init__()
