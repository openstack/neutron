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

from neutron_lib.callbacks import events as local_events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources as local_resources
from oslo_log import log as logging
import oslo_messaging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.services.trunk import constants as t_const
from neutron.services.trunk.drivers.linuxbridge.agent import trunk_plumber
from neutron.services.trunk.rpc import agent as trunk_rpc


LOG = logging.getLogger(__name__)


def init_handler(resource, event, trigger, payload=None):
    """Handler for agent init event."""
    LinuxBridgeTrunkDriver()


@registry.has_registry_receivers
class LinuxBridgeTrunkDriver(trunk_rpc.TrunkSkeleton):
    """Driver responsible for handling trunk/subport/port events.

    Receives data model events from the server and VIF events
    from the agent and uses these to drive a Plumber instance
    to wire up VLAN subinterfaces for any trunks.
    """

    def __init__(self, plumber=None, trunk_api=None):
        self._plumber = plumber or trunk_plumber.Plumber()
        self._tapi = trunk_api or _TrunkAPI(trunk_rpc.TrunkStub())
        super(LinuxBridgeTrunkDriver, self).__init__()

    def handle_trunks(self, context, resource_type, trunks, event_type):
        """Trunk data model change from the server."""
        for trunk in trunks:
            if event_type in (events.UPDATED, events.CREATED):
                self._tapi.put_trunk(trunk.port_id, trunk)
                self.wire_trunk(context, trunk)
            elif event_type == events.DELETED:
                self._tapi.put_trunk(trunk.port_id, None)
                self._plumber.delete_trunk_subports(trunk)

    def handle_subports(self, context, resource_type, subports, event_type):
        """Subport data model change from the server."""
        affected_trunks = set()
        if event_type == events.DELETED:
            method = self._tapi.delete_trunk_subport
        else:
            method = self._tapi.put_trunk_subport
        for s in subports:
            affected_trunks.add(s['trunk_id'])
            method(s['trunk_id'], s)
        for trunk_id in affected_trunks:
            trunk = self._tapi.get_trunk_by_id(context, trunk_id)
            if not trunk:
                continue
            self.wire_trunk(context, trunk)

    @registry.receives(local_resources.PORT_DEVICE,
                       [local_events.AFTER_DELETE])
    def agent_port_delete(self, resource, event, trigger, context, port_id,
                          **kwargs):
        """Agent informed us a VIF was removed."""
        # NOTE(kevinbenton): we don't need to do anything to cleanup VLAN
        # interfaces if a trunk was removed because the kernel will do that
        # for us. We also don't update the trunk status to DOWN because we
        # don't want to race with another agent that the trunk may have been
        # moved to.

    @registry.receives(local_resources.PORT_DEVICE,
                       [local_events.AFTER_UPDATE])
    def agent_port_change(self, resource, event, trigger, context,
                          device_details, **kwargs):
        """The agent hath informed us thusly of a port update or create."""
        trunk = self._tapi.get_trunk(context, device_details['port_id'])
        if trunk:
            # a wild trunk has appeared! make its children
            self.wire_trunk(context, trunk)
            return
        # clear any VLANs in case this was a trunk that changed status while
        # agent was offline.
        self._plumber.delete_subports_by_port_id(device_details['port_id'])

    def wire_trunk(self, context, trunk):
        """Wire up subports while keeping the server trunk status apprised."""
        if not self._plumber.trunk_on_host(trunk):
            LOG.debug("Trunk %s not present on this host", trunk.port_id)
            return
        self._tapi.bind_subports_to_host(context, trunk)
        try:
            self._plumber.ensure_trunk_subports(trunk)
            self._tapi.set_trunk_status(context, trunk, t_const.ACTIVE_STATUS)
        except Exception:
            if not self._plumber.trunk_on_host(trunk):
                LOG.debug("Trunk %s removed during wiring", trunk.port_id)
                return
            # something broke
            LOG.exception("Failure setting up subports for %s", trunk.port_id)
            self._tapi.set_trunk_status(context, trunk,
                                        t_const.DEGRADED_STATUS)


class _TrunkAPI(object):
    """Our secret stash of trunks stored by port ID. Tell no one."""

    def __init__(self, trunk_stub):
        self.server_api = trunk_stub
        self._trunk_by_port_id = {}
        self._trunk_by_id = {}
        self._sub_port_id_to_trunk_port_id = {}

    def _fetch_trunk(self, context, port_id):
        try:
            t = self.server_api.get_trunk_details(context, port_id)
            LOG.debug("Found trunk %(t)s for port %(p)s", dict(p=port_id, t=t))
            return t
        except resources_rpc.ResourceNotFound:
            return None
        except oslo_messaging.RemoteError as e:
            if e.exc_type != 'CallbackNotFound':
                raise
            LOG.debug("Trunk plugin disabled on server. Assuming port %s is "
                      "not a trunk.", port_id)
            return None

    def set_trunk_status(self, context, trunk, status):
        self.server_api.update_trunk_status(context, trunk.id, status)

    def bind_subports_to_host(self, context, trunk):
        self.server_api.update_subport_bindings(context, trunk.sub_ports)

    def put_trunk_subport(self, trunk_id, subport):
        LOG.debug("Adding subport %(sub)s to trunk %(trunk)s",
                  dict(sub=subport, trunk=trunk_id))
        if trunk_id not in self._trunk_by_id:
            # not on this agent
            return
        trunk = self._trunk_by_id[trunk_id]
        trunk.sub_ports = [s for s in trunk.sub_ports
                           if s.port_id != subport.port_id] + [subport]

    def delete_trunk_subport(self, trunk_id, subport):
        LOG.debug("Removing subport %(sub)s from trunk %(trunk)s",
                  dict(sub=subport, trunk=trunk_id))
        if trunk_id not in self._trunk_by_id:
            # not on this agent
            return
        trunk = self._trunk_by_id[trunk_id]
        trunk.sub_ports = [s for s in trunk.sub_ports
                           if s.port_id != subport.port_id]

    def put_trunk(self, port_id, trunk):
        if port_id in self._trunk_by_port_id:
            # already existed. expunge sub_port cross ref
            self._sub_port_id_to_trunk_port_id = {
                s: p for s, p in self._sub_port_id_to_trunk_port_id.items()
                if p != port_id}
        self._trunk_by_port_id[port_id] = trunk
        if not trunk:
            return
        self._trunk_by_id[trunk.id] = trunk
        for sub in trunk.sub_ports:
            self._sub_port_id_to_trunk_port_id[sub.port_id] = trunk.port_id

    def get_trunk_by_id(self, context, trunk_id):
        """Gets trunk object based on trunk_id. None if not in cache."""
        return self._trunk_by_id.get(trunk_id)

    def get_trunk(self, context, port_id):
        """Gets trunk object for port_id. None if not trunk."""
        if port_id not in self._trunk_by_port_id:
            # TODO(kevinbenton): ask the server for *all* trunk port IDs on
            # start and eliminate asking the server if every port is a trunk
            # TODO(kevinbenton): clear this on AMQP reconnect
            LOG.debug("Cache miss for port %s, fetching from server", port_id)
            self.put_trunk(port_id, self._fetch_trunk(context, port_id))
            return self.get_trunk(context, port_id)
        return self._trunk_by_port_id[port_id]

    def get_trunk_for_subport(self, context, port_id):
        """Returns trunk if port_id is a subport, else None."""
        trunk_port = self._sub_port_id_to_trunk_port_id.get(port_id)
        if trunk_port:
            return self.get_trunk(context, trunk_port)
