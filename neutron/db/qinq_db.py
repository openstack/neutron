# Copyright (c) 2024 Red Hat, Inc.
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
from neutron_lib.api.definitions import qinq as qinq_def
from neutron_lib.db import resource_extend


@resource_extend.has_resource_extenders
class Vlanqinq_db_mixin:
    """Mixin class to add vlan QinQ methods to db_base_plugin_v2."""

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_vlan_qinq(network_res, network_db):
        network_res[qinq_def.QINQ_FIELD] = network_db.qinq
        return network_res
