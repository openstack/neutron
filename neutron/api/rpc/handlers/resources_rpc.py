# Copyright (c) 2015 Mellanox Technologies, Ltd
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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron.api.rpc.callbacks import registry
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics


LOG = logging.getLogger(__name__)


class ResourcesServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    This class implements the client side of an rpc interface.  The server side
    can be found below: ResourcesServerRpcCallback.  For more information on
    changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    def __init__(self):
        target = oslo_messaging.Target(
            topic=topics.PLUGIN, version='1.0',
            namespace=constants.RPC_NAMESPACE_RESOURCES)
        self.client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_info(self, context, resource_type, resource_id):
        cctxt = self.client.prepare()
        #TODO(Qos): add deserialize version object
        return cctxt.call(context, 'get_info',
            resource_type=resource_type, resource_id=resource_id)


class ResourcesServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction.

    This class implements the server side of an rpc interface.  The client side
    can be found above: ResourcesServerRpcApi.  For more information on
    changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(
        version='1.0', namespace=constants.RPC_NAMESPACE_RESOURCES)

    def get_info(self, context, resource_type, resource_id):
        kwargs = {'context': context}
        #TODO(Qos): add serialize  version object
        return registry.get_info(
            resource_type,
            resource_id,
            **kwargs)
