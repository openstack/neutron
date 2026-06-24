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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.objects import ports as port_objects
from neutron.services.pvlan import exceptions as pvlan_exc

LOG = logging.getLogger(__name__)

# TODO(elvira): Move PVLAN_PLUGIN to neutron_lib.callbacks.resources
PVLAN_PLUGIN = 'pvlan_plugin'
DROP_ALL_PRIORITY = 1010
PROMISCUOUS_PRIORITY = 1011
COMMUNITY_PRIORITY = 1012
ISOLATED_PORT_GROUP_PREFIX = "pvlan_isolated"
COMMUNITY_PORT_GROUP_PREFIX = "pvlan_community"
PROMISCUOUS_PORT_GROUP_PREFIX = "pvlan_promiscuous"
DROP_PORT_GROUP_NAME = "pvlan_pg_drop"


def _initialize_pvlan_pg_drop(resource, event, trigger, payload=None):
    """Create pvlan_pg_drop Port Group.

    Same pattern as neutron_pg_drop but at higher priority to override
    security group allows for PVLAN ports.
    """
    pg_name = DROP_PORT_GROUP_NAME
    command = [
        "OVN_Northbound", {
            "op": "wait",
            "timeout": 0,
            "table": "Port_Group",
            "where": [["name", "==", pg_name]],
            "until": "==",
            "rows": []
        }, {
            "op": "insert",
            "table": "ACL",
            "row": {
                "action": "drop",
                "direction": "to-lport",
                "match": "outport == @%s && ip" % pg_name,
                "priority": DROP_ALL_PRIORITY
            },
            "uuid-name": "pvlandroptoport"
        }, {
            "op": "insert",
            "table": "ACL",
            "row": {
                "action": "drop",
                "direction": "from-lport",
                "match": "inport == @%s && ip" % pg_name,
                "priority": DROP_ALL_PRIORITY
            },
            "uuid-name": "pvlandropfromport"
        }, {
            "op": "insert",
            "table": "Port_Group",
            "row": {
                "name": pg_name,
                "acls": ["set", [
                    ["named-uuid", "pvlandroptoport"],
                    ["named-uuid", "pvlandropfromport"]
                ]]
            }
        }]
    ovn_utils.OvsdbClientTransactCommand.run(command)


def register(mech_driver):
    def _register_pvlan_driver(resource, event, trigger, payload=None):
        driver = PVLANDriver.create(mech_driver=mech_driver)
        if driver.is_loaded:
            trigger.register_driver(driver)

    registry.subscribe(_register_pvlan_driver,
                       PVLAN_PLUGIN, events.BEFORE_SPAWN)
    registry.subscribe(_initialize_pvlan_pg_drop,
                       resources.PROCESS, events.AFTER_INIT)


class PVLANDriver:
    """OVN driver for PVLAN."""

    def __init__(self, mech_driver):
        self._mech_driver = mech_driver

    @classmethod
    def create(cls, mech_driver):
        return cls(mech_driver)

    @property
    def is_loaded(self):
        try:
            return (ovn_const.OVN_ML2_MECH_DRIVER_NAME in
                    cfg.CONF.ml2.mechanism_drivers)
        except cfg.NoSuchOptError:
            return False

    @property
    def nb_ovn(self):
        return self._mech_driver.nb_ovn

    def create_network_resources(self, network_id, txn=None):
        """Create isolated and promiscuous port groups for a PVLAN network."""
        def _create_pgs(txn):
            self._create_isolated_port_group(network_id, txn)
            self._create_promiscuous_port_group(network_id, txn)

        if txn is None:
            with self.nb_ovn.transaction(check_error=True) as txn:
                _create_pgs(txn)
        else:
            _create_pgs(txn)

    def delete_network_resources(self, network_id, context=None):
        """Remove all PVLAN port groups for a network."""
        community_suffix = "_%s" % network_id.replace('-', '_')
        community_pgs = [
            pg.name for pg in
            self.nb_ovn.tables['Port_Group'].rows.values()
            if pg.name.startswith(COMMUNITY_PORT_GROUP_PREFIX) and
            pg.name.endswith(community_suffix)]
        with self.nb_ovn.transaction(check_error=True) as txn:
            for pg_name in community_pgs:
                txn.add(self.nb_ovn.pg_acl_del(pg_name, if_exists=True))
                txn.add(self.nb_ovn.pg_del(pg_name, if_exists=True))
            promiscuous_pg = self._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            for pg_name in community_pgs:
                txn.add(self.nb_ovn.pg_acl_del(
                    promiscuous_pg, direction="from-lport",
                    priority=PROMISCUOUS_PRIORITY,
                    match="inport == @%s" % pg_name, if_exists=True))
            for pvlan_type in (pvlan_const.ISOLATED_TYPE,
                               pvlan_const.PROMISCUOUS_TYPE):
                pg_name = self._get_pg_name(network_id, pvlan_type)
                txn.add(self.nb_ovn.pg_acl_del(pg_name, if_exists=True))
                txn.add(self.nb_ovn.pg_del(pg_name, if_exists=True))
            if context:
                for port in port_objects.Port.get_objects(
                        context, network_id=network_id):
                    txn.add(self.nb_ovn.pg_del_ports(
                        DROP_PORT_GROUP_NAME, port.id))

    def _create_isolated_port_group(self, network_id, txn):
        pg_name = self._get_pg_name(network_id, pvlan_const.ISOLATED_TYPE)
        promiscuous_pg = self._get_pg_name(
            network_id, pvlan_const.PROMISCUOUS_TYPE)
        txn.add(self.nb_ovn.pg_add(
            name=pg_name, acls=[],
            external_ids={"neutron:network_id": network_id}))
        # inport covers same-chassis and router ports (addresses="router"),
        # ip4/ip6.src covers cross-chassis where inport doesn't resolve.
        txn.add(self.nb_ovn.pg_acl_add(
            port_group=pg_name, priority=PROMISCUOUS_PRIORITY,
            action=ovn_const.ACL_ACTION_ALLOW_STATELESS,
            log=False, name=[], severity=[], meter=[],
            direction="to-lport",
            match=("outport == @%(dst)s && (inport == @%(src)s || "
                   "ip4.src == $%(src)s_ip4 || "
                   "ip6.src == $%(src)s_ip6)"
                   % {"dst": pg_name, "src": promiscuous_pg}),
            may_exist=True,
            **{"neutron:network_id": network_id}))

    def _create_promiscuous_port_group(self, network_id, txn):
        pg_name = self._get_pg_name(
            network_id, pvlan_const.PROMISCUOUS_TYPE)
        isolated_pg = self._get_pg_name(
            network_id, pvlan_const.ISOLATED_TYPE)

        txn.add(self.nb_ovn.pg_add(
            name=pg_name, acls=[],
            external_ids={"neutron:network_id": network_id}))
        for direction, match in [
            ("to-lport", "outport == @%s" % pg_name),
            ("from-lport", "inport == @%s" % pg_name),
            ("from-lport", "inport == @%s" % isolated_pg),
        ]:
            txn.add(self.nb_ovn.pg_acl_add(
                port_group=pg_name, priority=PROMISCUOUS_PRIORITY,
                action=ovn_const.ACL_ACTION_ALLOW_STATELESS,
                log=False, name=[], severity=[], meter=[],
                direction=direction, match=match, may_exist=True,
                **{"neutron:network_id": network_id}))

    def _get_pg_name(self, network_id, pvlan_type, community=None):
        net_id = network_id.replace('-', '_')
        if pvlan_type == pvlan_const.COMMUNITY_TYPE:
            return "%s_%s_%s" % (
                COMMUNITY_PORT_GROUP_PREFIX, community, net_id)
        if pvlan_type == pvlan_const.ISOLATED_TYPE:
            return "%s_%s" % (ISOLATED_PORT_GROUP_PREFIX, net_id)
        if pvlan_type == pvlan_const.PROMISCUOUS_TYPE:
            return "%s_%s" % (PROMISCUOUS_PORT_GROUP_PREFIX, net_id)

    def _add_port_to_pg(self, port_id, network_id, pvlan_type, txn,
                        community=None):
        if pvlan_type == pvlan_const.COMMUNITY_TYPE:
            if not community:
                raise pvlan_exc.PVLANCommunityNameRequired(port_id=port_id)
            pg_name = self._get_pg_name(network_id, pvlan_type, community)
            if not self.nb_ovn.get_port_group(pg_name):
                self._create_community(pg_name, network_id, txn)
        elif pvlan_type in (pvlan_const.ISOLATED_TYPE,
                            pvlan_const.PROMISCUOUS_TYPE):
            pg_name = self._get_pg_name(network_id, pvlan_type)
        else:
            raise pvlan_exc.PVLANUnsupportedType(
                pvlan_type=pvlan_type, port_id=port_id)
        txn.add(self.nb_ovn.pg_add_ports(pg_name, port_id))

    def _remove_port_from_pg(self, port_id, network_id, pvlan_type, txn,
                             community=None):
        pg_name = self._get_pg_name(network_id, pvlan_type, community)
        if not pg_name or not self.nb_ovn.get_port_group(pg_name):
            return
        txn.add(self.nb_ovn.pg_del_ports(pg_name, port_id, if_exists=True))
        if pvlan_type == pvlan_const.COMMUNITY_TYPE:
            self._delete_community_if_empty(pg_name, network_id, txn)

    def _delete_community_if_empty(self, pg_name, network_id, txn):
        pg = self.nb_ovn.get_port_group(pg_name)
        if pg and len(pg.ports) <= 1:
            promiscuous_pg = self._get_pg_name(
                network_id, pvlan_const.PROMISCUOUS_TYPE)
            txn.add(self.nb_ovn.pg_acl_del(pg_name, if_exists=True))
            txn.add(self.nb_ovn.pg_del(pg_name))
            txn.add(self.nb_ovn.pg_acl_del(
                promiscuous_pg, direction="from-lport",
                priority=PROMISCUOUS_PRIORITY,
                match="inport == @%s" % pg_name, if_exists=True))

    def _create_community(self, pg_name, network_id, txn):
        promiscuous_pg = self._get_pg_name(
            network_id, pvlan_const.PROMISCUOUS_TYPE)
        txn.add(self.nb_ovn.pg_add(
            name=pg_name, acls=[],
            external_ids={"neutron:network_id": network_id}))
        for src_pg in (pg_name, promiscuous_pg):
            txn.add(self.nb_ovn.pg_acl_add(
                port_group=pg_name, priority=COMMUNITY_PRIORITY,
                action=ovn_const.ACL_ACTION_ALLOW_STATELESS,
                log=False, name=[], severity=[], meter=[],
                direction="to-lport",
                match=("outport == @%(dst)s && (inport == @%(src)s || "
                       "ip4.src == $%(src)s_ip4 || "
                       "ip6.src == $%(src)s_ip6)"
                       % {"dst": pg_name, "src": src_pg}),
                may_exist=True,
                **{"neutron:network_id": network_id}))
        txn.add(self.nb_ovn.pg_acl_add(
            port_group=promiscuous_pg, priority=PROMISCUOUS_PRIORITY,
            action=ovn_const.ACL_ACTION_ALLOW_STATELESS,
            log=False, name=[], severity=[], meter=[],
            direction="from-lport",
            match="inport == @%s" % pg_name, may_exist=True,
            **{"neutron:network_id": network_id}))

    def create_port(self, context, txn, port):
        """Add newly created port to PVLAN port group within the same txn.

        Called from OVNClient.create_port() so the port group membership
        is set in the same transaction that creates the LSP.
        """
        if not port.get('pvlan_type'):
            return

        self._add_port_to_pg(port['id'], port['network_id'],
                             port['pvlan_type'], txn,
                             community=port.get('pvlan_community'))
        txn.add(self.nb_ovn.pg_add_ports(
            DROP_PORT_GROUP_NAME, port['id']))

    def delete_port(self, port_id, network_id, pvlan_type,
                    pvlan_community=None):
        """Remove a deleted port from its PVLAN port group and the drop PG."""
        with self.nb_ovn.transaction(check_error=True) as txn:
            self._remove_port_from_pg(port_id, network_id, pvlan_type, txn,
                                      community=pvlan_community)
            txn.add(self.nb_ovn.pg_del_ports(
                DROP_PORT_GROUP_NAME, port_id))

    def update_port(self, context, port,
                    prev_pvlan_type=None, prev_pvlan_community=None):
        """Add and/or remove LSP from its port group."""
        with self.nb_ovn.transaction(check_error=True) as txn:
            if port.pvlan_type:
                self._add_port_to_pg(port.id, port.network_id,
                                     port.pvlan_type, txn,
                                     community=port.pvlan_community)
                if not prev_pvlan_type:
                    txn.add(self.nb_ovn.pg_add_ports(
                        DROP_PORT_GROUP_NAME, port.id))

            if prev_pvlan_type and prev_pvlan_type != port.pvlan_type:
                self._remove_port_from_pg(port.id, port.network_id,
                                          prev_pvlan_type, txn,
                                          community=prev_pvlan_community)
                if not port.pvlan_type:
                    txn.add(self.nb_ovn.pg_del_ports(
                        DROP_PORT_GROUP_NAME, port.id))
            elif (prev_pvlan_type == pvlan_const.COMMUNITY_TYPE and
                    port.pvlan_community != prev_pvlan_community):
                self._remove_port_from_pg(port.id, port.network_id,
                                          prev_pvlan_type, txn,
                                          community=prev_pvlan_community)
