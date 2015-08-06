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

from oslo_log import log as logging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import registry as rpc_registry
from neutron.api.rpc.callbacks import resources
from neutron.i18n import _LW
from neutron.objects.qos import policy as policy_object
from neutron.services.qos.notification_drivers import qos_base


LOG = logging.getLogger(__name__)


def _get_qos_policy_cb(resource, policy_id, **kwargs):
    context = kwargs.get('context')
    if context is None:
        LOG.warning(_LW(
            'Received %(resource)s %(policy_id)s without context'),
            {'resource': resource, 'policy_id': policy_id}
        )
        return

    policy = policy_object.QosPolicy.get_by_id(context, policy_id)
    return policy


class RpcQosServiceNotificationDriver(
    qos_base.QosServiceNotificationDriverBase):
    """RPC message queue service notification driver for QoS."""

    def __init__(self):
        rpc_registry.register_provider(
            _get_qos_policy_cb,
            resources.QOS_POLICY)

    def get_description(self):
        return "Message queue updates"

    def create_policy(self, policy):
        #No need to update agents on create
        pass

    def update_policy(self, policy):
        # TODO(QoS): this is temporary until we get notify() implemented
        try:
            rpc_registry.notify(resources.QOS_POLICY,
                                events.UPDATED,
                                policy)
        except NotImplementedError:
            pass

    def delete_policy(self, policy):
        # TODO(QoS): this is temporary until we get notify() implemented
        try:
            rpc_registry.notify(resources.QOS_POLICY,
                                events.DELETED,
                                policy)
        except NotImplementedError:
            pass
