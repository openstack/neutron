# Copyright 2013 UnitedStack Inc.
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

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2


class PortBindingBaseMixin(object):
    base_binding_dict = None

    def _process_portbindings_create_and_update(self, context, port_data,
                                                port):
        self.extend_port_dict_binding(port, None)

    def extend_port_dict_binding(self, port_res, port_db):
        if self.base_binding_dict:
            port_res.update(self.base_binding_dict)


def _extend_port_dict_binding(plugin, port_res, port_db):
    if not isinstance(plugin, PortBindingBaseMixin):
        return
    plugin.extend_port_dict_binding(port_res, port_db)


def register_port_dict_function():
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, [_extend_port_dict_binding])
