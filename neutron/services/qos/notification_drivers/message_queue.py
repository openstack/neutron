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

from neutron._i18n import _LW
from neutron.services.qos.notification_drivers import qos_base


LOG = logging.getLogger(__name__)


class RpcQosServiceNotificationDriver(
    qos_base.QosServiceNotificationDriverBase):
    """RPC message queue service notification driver for QoS."""

    def __init__(self):
        LOG.warning(_LW("The QoS message_queue notification driver "
                        "has been ignored, since rpc push is implemented "
                        "for any QoS driver that requests it."))

    def get_description(self):
        return "Message queue updates"

    def create_policy(self, context, policy):
        pass

    def update_policy(self, context, policy):
        pass

    def delete_policy(self, context, policy):
        pass
