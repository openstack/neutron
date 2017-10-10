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

from neutron_lib.plugins import directory
import oslo_messaging

from neutron.common import constants


class MetadataRpcCallback(object):
    """Metadata agent RPC callback in plugin implementations.

    This class implements the server side of an rpc interface used by the
    metadata service to make calls back into the Neutron plugin.  The client
    side is defined in neutron.agent.metadata.agent.MetadataPluginAPI.  For
    more information about changing rpc interfaces, see
    doc/source/contributor/internals/rpc_api.rst.
    """

    # 1.0  MetadataPluginAPI BASE_RPC_API_VERSION
    target = oslo_messaging.Target(version='1.0',
                                   namespace=constants.RPC_NAMESPACE_METADATA)

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = directory.get_plugin()
        return self._plugin

    def get_ports(self, context, filters):
        return self.plugin.get_ports(context, filters=filters)
