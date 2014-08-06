# Copyright 2014 Embrane, Inc.
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

from neutron.db import extraroute_db
from neutron.db import l3_dvr_db
from neutron.db import l3_gwmode_db
from neutron.plugins.embrane import base_plugin as base
from neutron.plugins.embrane.l2base.ml2 import ml2_support
from neutron.plugins.ml2 import plugin as l2


class EmbraneMl2Plugin(base.EmbranePlugin, l2.Ml2Plugin,
                       l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                       l3_gwmode_db.L3_NAT_db_mixin,
                       extraroute_db.ExtraRoute_db_mixin):
    '''EmbraneMl2Plugin.

    This plugin uses Modular Layer 2 plugin for providing L2 networks
    and the base EmbranePlugin for L3.

    '''
    _plugin_support = ml2_support.Ml2Support()

    def __init__(self):
        '''First run plugin specific initialization, then Embrane's.'''
        self._supported_extension_aliases.extend(["router", "extraroute",
                                                  "ext-gw-mode"])
        l2.Ml2Plugin.__init__(self)
        self._run_embrane_config()
