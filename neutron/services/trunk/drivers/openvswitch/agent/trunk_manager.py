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

from neutron_lib import constants
from neutron_lib import exceptions
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.common import ovs_lib
from neutron.services.trunk.drivers.openvswitch.agent import exceptions as exc
from neutron.services.trunk.drivers.openvswitch import utils

LOG = logging.getLogger(__name__)


class TrunkManagerError(exceptions.NeutronException):
    message = _("Error while communicating with OVSDB: %(error)s")


def get_br_int_port_name(prefix, port_id):
    """Return the OVS port name for the given port ID.

    The port name is the one that plumbs into the integration bridge.
    """
    return ("%si-%s" % (prefix, port_id))[:constants.DEVICE_NAME_MAX_LEN]


def get_br_trunk_port_name(prefix, port_id):
    """Return the OVS port name for the given port ID.

    The port name is the one that plumbs into the trunk bridge.
    """
    return ("%st-%s" % (prefix, port_id))[:constants.DEVICE_NAME_MAX_LEN]


def get_patch_peer_attrs(peer_name, port_mac=None, port_id=None):
    external_ids = {}
    if port_mac:
        external_ids['attached-mac'] = port_mac
    if port_id:
        external_ids['iface-id'] = port_id
    attrs = [('type', 'patch'),
            ('options', {'peer': peer_name})]
    if external_ids:
        attrs.append(
            ('external_ids', external_ids))
    return attrs


class TrunkBridge(ovs_lib.OVSBridge):
    """An OVS trunk bridge.

    A trunk bridge has a name that follows a specific naming convention.
    """
    def __init__(self, trunk_id):
        name = utils.gen_trunk_br_name(trunk_id)
        super(TrunkBridge, self).__init__(name)

    def exists(self):
        return self.bridge_exists(self.br_name)


class TrunkParentPort(object):
    """An OVS trunk parent port.

    A trunk parent port is represented in OVS with two patch ports that
    connect a trunk bridge and the integration bridge respectively.
    These patch ports follow strict naming conventions: tpi-<hash> for
    the patch port that goes into the integration bridge, and tpt-<hash>
    for the patch port that goes into the trunk bridge.
    """
    DEV_PREFIX = 'tp'

    def __init__(self, trunk_id, port_id, port_mac=None):
        self.trunk_id = trunk_id
        self.port_id = port_id
        self.port_mac = port_mac
        self.bridge = TrunkBridge(self.trunk_id)
        self.patch_port_int_name = get_br_int_port_name(
            self.DEV_PREFIX, port_id)
        self.patch_port_trunk_name = get_br_trunk_port_name(
            self.DEV_PREFIX, port_id)
        self._transaction = None

    def plug(self, br_int):
        """Plug patch ports between trunk bridge and given bridge.

        The method plugs one patch port on the given bridge side using
        port MAC and ID as external IDs.  The other endpoint of patch port is
        attached to the trunk bridge.  Everything is done in a single
        OVSDB transaction so either all operations succeed or fail.

        :param br_int: an integration bridge where peer endpoint of patch port
                       will be created.
        """
        # NOTE(jlibosva): OVSDB is an api so it doesn't matter whether we
        # use self.bridge or br_int
        ovsdb = self.bridge.ovsdb
        # Once the bridges are connected with the following patch ports,
        # the ovs agent will recognize the ports for processing and it will
        # take over the wiring process and everything that entails.
        # REVISIT(rossella_s): revisit this integration part, should tighter
        # control over the wiring logic for trunk ports be required.
        patch_int_attrs = get_patch_peer_attrs(
            self.patch_port_trunk_name, self.port_mac, self.port_id)
        patch_trunk_attrs = get_patch_peer_attrs(self.patch_port_int_name,
                                                 self.port_mac, self.port_id)

        with ovsdb.transaction() as txn:
            txn.add(ovsdb.add_port(br_int.br_name,
                                   self.patch_port_int_name))
            txn.add(ovsdb.db_set('Interface', self.patch_port_int_name,
                                 *patch_int_attrs))
            txn.add(ovsdb.add_port(self.bridge.br_name,
                                   self.patch_port_trunk_name))
            txn.add(ovsdb.db_set('Interface', self.patch_port_trunk_name,
                                 *patch_trunk_attrs))

    def unplug(self, bridge):
        """Unplug the trunk from bridge.

        Method unplugs in single OVSDB transaction the trunk bridge and patch
        port on provided bridge.

        :param bridge: bridge that has peer side of patch port for this
                       subport.
        """
        ovsdb = self.bridge.ovsdb
        with ovsdb.transaction() as txn:
            txn.add(ovsdb.del_br(self.bridge.br_name))
            txn.add(ovsdb.del_port(self.patch_port_int_name,
                                   bridge.br_name))


class SubPort(TrunkParentPort):
    """An OVS trunk subport.

    A subport is represented in OVS with two patch ports that
    connect a trunk bridge and the integration bridge respectively.
    These patch ports follow strict naming conventions: spi-<hash> for
    the patch port that goes into the integration bridge, and spt-<hash>
    for the patch port that goes into the trunk bridge.
    """
    DEV_PREFIX = 'sp'

    def __init__(self, trunk_id, port_id, port_mac=None, segmentation_id=None):
        super(SubPort, self).__init__(trunk_id, port_id, port_mac)
        self.segmentation_id = segmentation_id

    def plug(self, br_int):
        """Unplug patch ports between trunk bridge and given bridge.

        The method unplugs one patch port on the given bridge side using
        port MAC and ID as external IDs.  The other endpoint of patch port is
        attached to the trunk bridge.  Then it sets vlan tag represented by
        segmentation_id.  Everything is done in a single OVSDB transaction so
        either all operations succeed or fail.

        :param br_int: an integration bridge where peer endpoint of patch port
                       will be created.
        """
        ovsdb = self.bridge.ovsdb
        with ovsdb.transaction() as txn:
            super(SubPort, self).plug(br_int)
            txn.add(ovsdb.db_set(
                "Port", self.patch_port_trunk_name,
                ("tag", self.segmentation_id)))

    def unplug(self, bridge):
        """Unplug the sub port from the bridge.

        Method unplugs in single OVSDB transaction both endpoints of patch
        ports that represents the subport.

        :param bridge: bridge that has peer side of patch port for this
                       subport.
        """
        ovsdb = self.bridge.ovsdb
        with ovsdb.transaction() as txn:
            txn.add(ovsdb.del_port(self.patch_port_trunk_name,
                                   self.bridge.br_name))
            txn.add(ovsdb.del_port(self.patch_port_int_name,
                                   bridge.br_name))


class TrunkManager(object):
    """It implements the OVS trunk dataplane.

    It interfaces with the OVSDB server to execute OVS commands.
    """

    def __init__(self, br_int):
        self.br_int = br_int

    def create_trunk(self, trunk_id, port_id, port_mac):
        """Create the trunk.

        This patches the bridge for trunk_id with the integration bridge
        by means of parent port identified by port_id.

        :param trunk_id: ID of the trunk.
        :param port_id: ID of the parent port.
        :param port_mac: the MAC address of the parent port.
        :raises:
             TrunkBridgeNotFound: in case trunk bridge does not exist.
        """
        trunk = TrunkParentPort(trunk_id, port_id, port_mac)
        try:
            if not trunk.bridge.exists():
                raise exc.TrunkBridgeNotFound(bridge=trunk.bridge.br_name)
            trunk.plug(self.br_int)
        except RuntimeError as e:
            raise TrunkManagerError(error=e)

    def remove_trunk(self, trunk_id, port_id):
        """Remove the trunk bridge."""
        trunk = TrunkParentPort(trunk_id, port_id)
        try:
            if trunk.bridge.exists():
                trunk.unplug(self.br_int)
            else:
                LOG.debug("Trunk bridge with ID %s does not exist.", trunk_id)
        except RuntimeError as e:
            raise TrunkManagerError(error=e)

    def dispose_trunk(self, trunk_bridge):
        """Clean up all the OVS resources associated to trunk_bridge."""
        ovsdb = trunk_bridge.ovsdb
        patch_peers = []
        try:
            patch_peers = trunk_bridge.get_ports_attributes(
                'Interface', columns=['options'])
            with trunk_bridge.ovsdb.transaction() as txn:
                for patch_peer in patch_peers:
                    peer_name = patch_peer['options'].get('peer')
                    if peer_name:
                        txn.add(ovsdb.del_port(peer_name, self.br_int.br_name))
                txn.add(ovsdb.del_br(trunk_bridge.br_name))
            LOG.debug("Deleted bridge '%s' and patch peers '%s'.",
                      trunk_bridge.br_name, patch_peers)
        except RuntimeError as e:
            LOG.error("Could not delete '%(peers)s' associated to "
                      "trunk bridge %(name)s. Reason: %(reason)s.",
                      {'peers': patch_peers,
                       'name': trunk_bridge.br_name,
                       'reason': e})

    def add_sub_port(self, trunk_id, port_id, port_mac, segmentation_id):
        """Create a sub_port.

        :param trunk_id: ID of the trunk.
        :param port_id: ID of the subport.
        :param segmentation_id: segmentation ID associated with this subport.
        :param port_mac: MAC address of the subport.
        """
        sub_port = SubPort(trunk_id, port_id, port_mac, segmentation_id)
        # If creating of parent trunk bridge takes longer than API call for
        # creating subport then bridge doesn't exist yet.
        try:
            if not sub_port.bridge.exists():
                raise exc.TrunkBridgeNotFound(bridge=sub_port.bridge.br_name)
            sub_port.plug(self.br_int)
        except RuntimeError as e:
            raise TrunkManagerError(error=e)

    def remove_sub_port(self, trunk_id, port_id):
        """Remove a sub_port.

        :param trunk_id: ID of the trunk.
        :param port_id: ID of the subport.
        """
        sub_port = SubPort(trunk_id, port_id)

        # Trunk bridge might have been deleted by calling delete_trunk() before
        # remove_sub_port().
        try:
            if sub_port.bridge.exists():
                sub_port.unplug(self.br_int)
            else:
                LOG.debug("Trunk bridge with ID %s does not exist.", trunk_id)
        except RuntimeError as e:
            raise TrunkManagerError(error=e)

    def get_port_uuid_from_external_ids(self, port):
        """Return the port UUID from the port metadata."""
        try:
            return self.br_int.portid_from_external_ids(
                port['external_ids'])
        except RuntimeError as e:
            raise TrunkManagerError(error=e)
