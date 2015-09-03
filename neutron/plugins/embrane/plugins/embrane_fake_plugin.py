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

from neutron.db import extraroute_db
from neutron.plugins.embrane import base_plugin as base
from neutron.plugins.embrane.l2base.fake import fake_l2_plugin as l2
from neutron.plugins.embrane.l2base.fake import fakeplugin_support as sup


class EmbraneFakePlugin(base.EmbranePlugin, extraroute_db.ExtraRoute_db_mixin,
                        l2.FakeL2Plugin):
    _plugin_support = sup.FakePluginSupport()

    def __init__(self):
        '''First run plugin specific initialization, then Embrane's.'''
        self.supported_extension_aliases += ["extraroute", "router"]
        l2.FakeL2Plugin.__init__(self)
        self._run_embrane_config()
