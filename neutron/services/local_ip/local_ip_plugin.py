# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

from neutron_lib.api.definitions import local_ip as local_ip_apidef

from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.db import local_ip_db


class LocalIPPlugin(local_ip_db.LocalIPDbMixin):
    """Implementation of the Neutron logging api plugin."""

    supported_extension_aliases = [local_ip_apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super().__init__()
        self._resource_rpc = resources_rpc.ResourcesPushRpcApi()

    def create_local_ip_port_association(self, context, local_ip_id,
                                         port_association):
        lip_assoc = self._create_local_ip_port_association(
            context, local_ip_id, port_association)
        self._resource_rpc.push(context, [lip_assoc], rpc_events.CREATED)
        return self._make_local_ip_assoc_dict(lip_assoc)

    def delete_local_ip_port_association(self, context, fixed_port_id,
                                         local_ip_id):
        lip_assoc = super().delete_local_ip_port_association(
                context, fixed_port_id, local_ip_id)
        self._resource_rpc.push(context, [lip_assoc], rpc_events.DELETED)
