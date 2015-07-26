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
from neutron.api.rpc.callbacks import resources
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics


LOG = logging.getLogger(__name__)


class ResourcesRpcError(exceptions.NeutronException):
    pass


class InvalidResourceTypeClass(ResourcesRpcError):
    message = _("Invalid resource type %(resource_type)s")


class ResourceNotFound(ResourcesRpcError):
    message = _("Resource %(resource_id)s of type %(resource_type)s "
                "not found")


def _validate_resource_type(resource_type):
    if not resources.is_valid_resource_type(resource_type):
        raise InvalidResourceTypeClass(resource_type=resource_type)


class ResourcesServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    This class implements the client side of an rpc interface.  The server side
    can be found below: ResourcesServerRpcCallback.  For more information on
    this RPC interface, see doc/source/devref/rpc_callbacks.rst.
    """

    def __init__(self):
        target = oslo_messaging.Target(
            topic=topics.PLUGIN, version='1.0',
            namespace=constants.RPC_NAMESPACE_RESOURCES)
        self.client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_info(self, context, resource_type, resource_id):
        _validate_resource_type(resource_type)

        # we've already validated the resource type, so we are pretty sure the
        # class is there => no need to validate it specifically
        resource_type_cls = resources.get_resource_cls(resource_type)

        cctxt = self.client.prepare()
        primitive = cctxt.call(context, 'get_info',
            resource_type=resource_type,
            version=resource_type_cls.VERSION, resource_id=resource_id)

        if primitive is None:
            raise ResourceNotFound(resource_type=resource_type,
                                   resource_id=resource_id)

        obj = resource_type_cls.obj_from_primitive(primitive)
        obj.obj_reset_changes()
        return obj


class ResourcesServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction.

    This class implements the server side of an rpc interface.  The client side
    can be found above: ResourcesServerRpcApi.  For more information on
    this RPC interface, see doc/source/devref/rpc_callbacks.rst.
    """

    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(
        version='1.0', namespace=constants.RPC_NAMESPACE_RESOURCES)

    def get_info(self, context, resource_type, version, resource_id):
        _validate_resource_type(resource_type)

        obj = registry.get_info(
            resource_type,
            resource_id,
            context=context)

        if obj:
            return obj.obj_to_primitive(target_version=version)
