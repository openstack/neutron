# Copyright (c) 2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.common import rpc as n_rpc
from neutron import manager


class MetadataRpcCallback(n_rpc.RpcCallback):
    """Metadata agent RPC callback in plugin implementations."""

    # 1.0  MetadataPluginAPI BASE_RPC_API_VERSION
    RPC_API_VERSION = '1.0'

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    def get_ports(self, context, filters):
        return self.plugin.get_ports(context, filters=filters)
