# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.services.trunk.rpc import agent

LOG = logging.getLogger(__name__)

TRUNK_SKELETON = None


class OVSTrunkSkeleton(agent.TrunkSkeleton):

    def __init__(self):
        super(OVSTrunkSkeleton, self).__init__()
        registry.unsubscribe(self.handle_trunks, resources.TRUNK)

    def handle_trunks(self, trunk, event_type):
        """This method is not required by the OVS Agent driver.

        Trunk notifications are handled via local OVSDB events.
        """
        raise NotImplementedError()

    def handle_subports(self, subports, event_type):
        # TODO(armax): call into TrunkManager to wire the subports
        LOG.debug("Event %s for subports: %s", event_type, subports)


def init_handler(resource, event, trigger, agent=None):
    """Handler for agent init event."""
    # Set up agent-side RPC for receiving trunk events; we may want to
    # make this setup conditional based on server-side capabilities.
    global TRUNK_SKELETON
    TRUNK_SKELETON = OVSTrunkSkeleton()
