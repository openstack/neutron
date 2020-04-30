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


# TODO(flaviof): remove this once moved over to neutron-lib payloads
class PortForwardingPayload(object):
    """Payload for port-forwarding-related callback registry notifications."""

    def __init__(self, context, current_pf=None, original_pf=None):
        self.context = context
        self.current_pf = current_pf
        self.original_pf = original_pf

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)
