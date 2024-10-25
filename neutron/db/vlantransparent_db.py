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

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.db import resource_extend


@resource_extend.has_resource_extenders
class Vlantransparent_db_mixin:
    """Mixin class to add vlan transparent methods to db_base_plugin_v2."""

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_vlan_transparent(network_res, network_db):
        network_res[vlan_apidef.VLANTRANSPARENT] = (
            network_db.vlan_transparent)
        return network_res
