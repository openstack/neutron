# Copyright (c) 2015 Cisco Systems, Inc.  All rights reserved.
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

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
from neutron.extensions import vlantransparent


class Vlantransparent_db_mixin(object):
    """Mixin class to add vlan transparent methods to db_base_plugin_v2."""

    def _extend_network_dict_vlan_transparent(self, network_res, network_db):
        network_res[vlantransparent.VLANTRANSPARENT] = (
            network_db.vlan_transparent)
        return network_res

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_vlan_transparent'])
