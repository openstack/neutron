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

from neutron.api.rpc.callbacks.consumer import registry as cons_registry
from neutron.api.rpc.callbacks.producer import registry as prod_registry
from neutron.api.rpc.callbacks import resources
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.objects import base as obj_base


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


def resource_type_versioned_topic(resource_type):
    _validate_resource_type(resource_type)
    cls = resources.get_resource_cls(resource_type)
    return topics.RESOURCE_TOPIC_PATTERN % {'resource_type': resource_type,
                                            'version': cls.VERSION}


class ResourcesPullRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    This class implements the client side of an rpc interface.  The server side
    can be found below: ResourcesPullRpcCallback.  For more information on
    this RPC interface, see doc/source/devref/rpc_callbacks.rst.
    """

    def __new__(cls):
        # make it a singleton
        if not hasattr(cls, '_instance'):
            cls._instance = super(ResourcesPullRpcApi, cls).__new__(cls)
            target = oslo_messaging.Target(
                topic=topics.PLUGIN, version='1.0',
                namespace=constants.RPC_NAMESPACE_RESOURCES)
            cls._instance.client = n_rpc.get_client(target)
        return cls._instance

    @log_helpers.log_method_call
    def pull(self, context, resource_type, resource_id):
        _validate_resource_type(resource_type)

        # we've already validated the resource type, so we are pretty sure the
        # class is there => no need to validate it specifically
        resource_type_cls = resources.get_resource_cls(resource_type)

        cctxt = self.client.prepare()
        primitive = cctxt.call(context, 'pull',
            resource_type=resource_type,
            version=resource_type_cls.VERSION, resource_id=resource_id)

        if primitive is None:
            raise ResourceNotFound(resource_type=resource_type,
                                   resource_id=resource_id)

        return resource_type_cls.clean_obj_from_primitive(primitive)


class ResourcesPullRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction.

    This class implements the server side of an rpc interface.  The client side
    can be found above: ResourcesPullRpcApi.  For more information on
    this RPC interface, see doc/source/devref/rpc_callbacks.rst.
    """

    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(
        version='1.0', namespace=constants.RPC_NAMESPACE_RESOURCES)

    def pull(self, context, resource_type, version, resource_id):
        obj = prod_registry.pull(resource_type, resource_id, context=context)
        if obj:
            return obj.obj_to_primitive(target_version=version)


class ResourcesPushRpcApi(object):
    """Plugin-side RPC for plugin-to-agents interaction.

    This interface is designed to push versioned object updates to interested
    agents using fanout topics.

    This class implements the caller side of an rpc interface.  The receiver
    side can be found below: ResourcesPushRpcCallback.
    """

    def __init__(self):
        target = oslo_messaging.Target(
            version='1.0',
            namespace=constants.RPC_NAMESPACE_RESOURCES)
        self.client = n_rpc.get_client(target)

    def _prepare_object_fanout_context(self, obj):
        """Prepare fanout context, one topic per object type."""
        obj_topic = resource_type_versioned_topic(obj.obj_name())
        return self.client.prepare(fanout=True, topic=obj_topic)

    @log_helpers.log_method_call
    def push(self, context, resource, event_type):
        resource_type = resources.get_resource_type(resource)
        _validate_resource_type(resource_type)
        cctxt = self._prepare_object_fanout_context(resource)
        #TODO(QoS): Push notifications for every known version once we have
        #           multiple of those
        dehydrated_resource = resource.obj_to_primitive()
        cctxt.cast(context, 'push',
                   resource=dehydrated_resource,
                   event_type=event_type)


class ResourcesPushRpcCallback(object):
    """Agent-side RPC for plugin-to-agents interaction.

    This class implements the receiver for notification about versioned objects
    resource updates used by neutron.api.rpc.callbacks. You can find the
    caller side in ResourcesPushRpcApi.
    """
    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(version='1.0',
                                   namespace=constants.RPC_NAMESPACE_RESOURCES)

    def push(self, context, resource, event_type):
        resource_obj = obj_base.NeutronObject.clean_obj_from_primitive(
            resource)
        LOG.debug("Resources notification (%(event_type)s): %(resource)s",
                  {'event_type': event_type, 'resource': repr(resource_obj)})
        resource_type = resources.get_resource_type(resource_obj)
        cons_registry.push(resource_type, resource_obj, event_type)
