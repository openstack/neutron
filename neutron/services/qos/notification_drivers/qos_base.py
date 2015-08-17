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
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class QosServiceNotificationDriverBase(object):
    """QoS service notification driver base class."""

    @abc.abstractmethod
    def get_description(self):
        """Get the notification driver description.
        """

    @abc.abstractmethod
    def create_policy(self, context, policy):
        """Create the QoS policy."""

    @abc.abstractmethod
    def update_policy(self, context, policy):
        """Update the QoS policy.

        Apply changes to the QoS policy.
        """

    @abc.abstractmethod
    def delete_policy(self, context, policy):
        """Delete the QoS policy.

        Remove all rules for this policy and free up all the resources.
        """
