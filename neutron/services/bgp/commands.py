# Copyright 2025 Red Hat, Inc.
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

import netaddr
from neutron_lib import constants as n_const
from oslo_log import log
from ovsdbapp.backend.ovs_idl import command as ovs_cmd
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import constants as ovsdbapp_const
from ovsdbapp.schema.ovn_northbound import commands as nb_cmd

from neutron.agent.linux import ip_lib
from neutron.common.ovn import constants as ovn_const
from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import constants
from neutron.services.bgp import exceptions
from neutron.services.bgp import helpers

LOG = log.getLogger(__name__)


def _run_idl_command(cmd, txn):
    """A wrapper around a command to run it and return the row result.

    This avoids using the self.result attribute but returns a custom row_result
    instead. Important is that in case of a new row creation, the row_result
    does not contain the same UUID that is stored in the DB after the commit.
    """
    cmd.run_idl(txn)
    try:
        return cmd.row_result
    except AttributeError:
        # If the command does not implement the row_result attribute,
        # return the result
        return cmd.result


def _get_lrp_peer_ip(nb_idl, lrp):
    peer_lrp = nb_idl.lookup('Logical_Router_Port', lrp.peer[0])
    try:
        return str(netaddr.IPNetwork(peer_lrp.networks[0]).ip)
    except IndexError:
        return helpers.ipv6_link_local_from_mac(peer_lrp.mac)


def _lrps_to_chassis_routers(router):
    return [lrp for lrp in router.ports
            if hasattr(lrp, 'external_ids') and
            constants.BGP_LRP_TO_CHASSIS in lrp.external_ids]


def _get_main_router(nb_idl):
    return nb_idl.lookup('Logical_Router', bgp_config.get_main_router_name())


def _get_all_provider_switches(nb_idl):
    return [
        s for s in nb_idl.tables['Logical_Switch'].rows.values()
        if hasattr(s, 'external_ids') and s.external_ids.get(
            ovn_const.OVN_NETTYPE_EXT_ID_KEY) in n_const.TYPE_PHYSICAL]


def _get_switch_dhcp_options(nb_idl, switch):
    n_net_id = helpers.get_neutron_id_from_ovn_name(switch)
    for dhcp_opt in nb_idl.tables['DHCP_Options'].rows.values():
        if dhcp_opt.external_ids.get(
                ovn_const.OVN_NETWORK_ID_EXT_ID_KEY) == n_net_id:
            yield dhcp_opt


def _get_gw_ips_for_switch(nb_idl, switch):
    gw_ips = [
        gw_ip for dhcp_opt in _get_switch_dhcp_options(nb_idl, switch)
        if (gw_ip := helpers.get_gw_ip_from_dhcp_options(
            dhcp_opt)) is not None]
    LOG.debug("For logical switch %s, found gateway IPs: %s",
              switch.name, gw_ips)
    return gw_ips


def _make_main_router_policy_match(ic_switch_lrp_name, chassis_lrp_name):
    return (f'inport=="{ic_switch_lrp_name}" && '
            f'is_chassis_resident("cr-{chassis_lrp_name}")')


class _LsAddCommand(nb_cmd.LsAddCommand):
    def run_idl(self, txn):
        try:
            self.row_result = self.result = self.api.lookup(
                'Logical_Switch', self.switch)
        except idlutils.RowNotFound:
            super().run_idl(txn)
            self.row_result = self.api.lookup('Logical_Switch', self.switch)
            return

        self.set_columns(self.row_result, **self.columns)


class _LrAddCommand(nb_cmd.LrAddCommand):
    """An idempotent command to add a logical router.

    We need to subclass the LrAddCommand because it does not check if the
    columns in the existing row are the same as the columns we are trying to
    set.
    """

    def run_idl(self, txn):
        try:
            self.row_result = self.result = self.api.lookup(
                'Logical_Router', self.router)
        except idlutils.RowNotFound:
            super().run_idl(txn)
            self.row_result = self.api.lookup('Logical_Router', self.router)
            return

        self.set_columns(self.row_result, **self.columns)


class _LspAddCommand(nb_cmd.LspAddCommand):
    def run_idl(self, txn):
        try:
            self.row_result = self.result = self.api.lookup(
                'Logical_Switch_Port', self.port)
        except idlutils.RowNotFound:
            super().run_idl(txn)
            self.row_result = self.api.lookup('Logical_Switch_Port', self.port)
            return

        self.set_columns(self.row_result, **self.columns)


class _LrpAddCommand(nb_cmd.LrpAddCommand):
    """An idempotent command to add a logical router port.

    We need to subclass the LrpAddCommand because it does not check if the
    columns in the existing row are the same as the columns we are trying to
    set.
    """

    def __init__(
            self, api, router_name, lrp_name, networks=None, **kwargs):
        networks = networks or []
        mac = helpers.get_mac_address_from_lrp_name(lrp_name)
        super().__init__(api, router_name, lrp_name, mac, networks, **kwargs)

    def run_idl(self, txn):
        try:
            self.row_result = self.result = self.api.lookup(
                'Logical_Router_Port', self.port)
        except idlutils.RowNotFound:
            super().run_idl(txn)
            self.row_result = self.api.lookup('Logical_Router_Port', self.port)
            return

        # TODO(jlibosva): Make sure the mac is unique for this router
        self.row_result.mac = self.mac
        self.row_result.networks = self.networks
        self.row_result.peer = self.peer
        self.set_columns(self.row_result, **self.columns)


class _HAChassisGroupAddCommand(nb_cmd.HAChassisGroupAddCommand):
    """An idempotent command to add a HA chassis group.

    We need to subclass the HAChassisGroupAddCommand because it does not check
    if the columns in the existing row are the same as the columns we are
    trying to set.
    """

    def run_idl(self, txn):
        try:
            self.row_result = self.result = self.api.lookup(
                'HA_Chassis_Group', self.name)
        except idlutils.RowNotFound:
            super().run_idl(txn)
            self.row_result = self.api.lookup(
                'HA_Chassis_Group', self.name)
            return

        self.set_columns(self.row_result, **self.columns)


class HaChassisGroupDelCommand(nb_cmd.HAChassisGroupDelCommand):
    def __init__(self, api, chassis):
        ha_chassis_group_name = helpers.get_hcg_name(chassis.name)
        super().__init__(api, ha_chassis_group_name, if_exists=True)


class _LrPolicyAddCommand(nb_cmd.LrPolicyAddCommand):
    """An idempotent command to add a logical router policy.
    """

    def __init__(self, api, router, priority, match, action, output_port,
                 *args, **kwargs):

        if 'nexthops' not in kwargs:
            kwargs['nexthops'] = [ip_lib.get_ipv6_lladdr(output_port.mac)]

        super().__init__(api, router, priority, match, action,
                         may_exist=True, output_port=output_port,
                         *args, **kwargs)


class CreateSwitchWithLocalnetCommand(_LsAddCommand):
    def __init__(self, api, name, network_name):
        super().__init__(api, name, may_exist=True)
        self.network_name = network_name

    def run_idl(self, txn):
        super().run_idl(txn)

        CreateLspLocalnetCommand(
            self.api, self.switch, self.network_name,
        ).run_idl(txn)


class CreateLspLocalnetCommand(_LspAddCommand):
    def __init__(self, api, switch_name, network_name):
        localnet_lsp_name = helpers.get_lsp_localnet_name(switch_name)
        super().__init__(
            api, switch_name, localnet_lsp_name, may_exist=True)
        self.network_name = network_name

    def run_idl(self, txn):
        self.columns = {
            'type': ovn_const.LSP_TYPE_LOCALNET,
            'options': {'network_name': self.network_name},
            'addresses': [ovn_const.UNKNOWN_ADDR],
        }
        super().run_idl(txn)


class _NeutronSwitchBase(ovs_cmd.BaseCommand):
    def __init__(self, api, n_switch):
        super().__init__(api)
        self.n_switch = n_switch
        self.router_name = bgp_config.get_main_router_name()
        self.interconnect_switch_name = (
            helpers.get_provider_interconnect_switch_name(self.n_switch.name))


class ReconcileNeutronSwitchCommand(_NeutronSwitchBase):
    def __init__(self, api, n_switch):
        super().__init__(api, n_switch)
        self.network_name = self._get_network_name()

    def _get_network_name(self):
        for port in self.n_switch.ports:
            if port.type == ovn_const.LSP_TYPE_LOCALNET:
                return port.options['network_name']
        raise ValueError(
            f"No localnet port found for switch {self.n_switch.name}")

    def run_idl(self, txn):
        # The fake connection to distribute the routes to the BGP router
        ConnectRouterToSwitchCommand(
            self.api,
            self.router_name,
            self.n_switch.name,
        ).run_idl(txn)

        CreateSwitchWithLocalnetCommand(
            self.api,
            self.interconnect_switch_name,
            self.network_name,
        ).run_idl(txn)

        ConnectRouterToSwitchCommand(
            self.api,
            self.router_name,
            self.interconnect_switch_name,
            lrp_ips=_get_gw_ips_for_switch(self.api, self.n_switch),
        ).run_idl(txn)

        ReconcileMainRouterPoliciesForProviderCommand(
            self.api,
            self.interconnect_switch_name,
        ).run_idl(txn)


class DeleteNeutronSwitchCommand(_NeutronSwitchBase):
    def run_idl(self, txn):
        router_to_interconnect_lrp_name = helpers.get_lrp_name(
            self.router_name, self.interconnect_switch_name)
        router_to_n_switch_lrp_name = helpers.get_lrp_name(
            self.router_name, self.n_switch.name)

        main_router = _get_main_router(self.api)

        for chassis_lrp in _lrps_to_chassis_routers(main_router):
            nb_cmd.LrPolicyDelCommand(
                self.api,
                self.router_name,
                priority=constants.LR_BGP_TO_CHASSIS_POLICY_PRIORITY,
                match=_make_main_router_policy_match(
                    router_to_interconnect_lrp_name, chassis_lrp.name),
            ).run_idl(txn)

        nb_cmd.LsDelCommand(
            self.api,
            self.interconnect_switch_name,
        ).run_idl(txn)

        for lrp_name in [router_to_interconnect_lrp_name,
                         router_to_n_switch_lrp_name]:
            nb_cmd.LrpDelCommand(
                self.api,
                lrp_name,
            ).run_idl(txn)


class ReconcileMainRouterPoliciesForProviderCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, interconnect_switch_name):
        super().__init__(api)
        self.interconnect_switch_name = interconnect_switch_name

    def run_idl(self, txn):
        router = _get_main_router(self.api)
        lrp_interconnect_name = helpers.get_lrp_name(
            router.name, self.interconnect_switch_name)
        for lrp in _lrps_to_chassis_routers(router):
            ReconcileMainRouterPoliciesCommand(
                self.api,
                router,
                lrp_interconnect_name,
                lrp,
            ).run_idl(txn)


class ReconcileMainRouterPoliciesCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, router, interconnect_lrp_name, chassis_lrp):
        super().__init__(api)
        self.router = router
        self.interconnect_lrp_name = interconnect_lrp_name
        self.chassis_lrp = chassis_lrp

    def run_idl(self, txn):
        lrp_peer_ip = _get_lrp_peer_ip(self.api, self.chassis_lrp)

        # An egress policy to reroute traffic to the chassis router that is
        # local to the chassis where the traffic originated from
        _LrPolicyAddCommand(
            self.api,
            self.router.name,
            priority=constants.LR_BGP_TO_CHASSIS_POLICY_PRIORITY,
            match=_make_main_router_policy_match(
                self.interconnect_lrp_name, self.chassis_lrp.name),
            action='reroute',
            output_port=self.chassis_lrp,
            nexthops=[lrp_peer_ip],
        ).run_idl(txn)


class ReconcileRouterCommand(_LrAddCommand):
    def __init__(self, api, name):
        # We need to set policies and static_routes to empty list because IDL
        # won't have that set until the transaction is committed
        super().__init__(
            api, name, may_exist=True, policies=[], static_routes=[])

    def run_idl(self, txn):
        super().run_idl(txn)

        for key, value in self.options.items():
            self.row_result.setkey('options', key, value)

    @property
    def options(self):
        return {}


class ReconcileMainRouterCommand(ReconcileRouterCommand):
    def __init__(self, api):
        name = bgp_config.get_main_router_name()
        super().__init__(api, name)

    @property
    def options(self):
        return {
            constants.LR_OPTIONS_DYNAMIC_ROUTING: 'true',
            constants.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE:
                constants.BGP_ROUTER_REDISTRIBUTE,
            constants.LR_OPTIONS_DYNAMIC_ROUTING_VRF_ID:
                str(bgp_config.get_main_router_vrf_id()),
            constants.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE_LOCAL: 'true',
        }

    def run_idl(self, txn):
        super().run_idl(txn)

        # Create a fake LRP just to get the fake route in place
        fake_lrp = _run_idl_command(_LrpAddCommand(
            self.api,
            self.router,
            f'{self.router}-dead-lrp',
            may_exist=True,
        ), txn)

        # A fake route to get over the routing stage in routers logical flows
        # This is required for the egress policy to work
        nb_cmd.LrRouteAddCommand(
            self.api,
            self.router,
            '0.0.0.0/0',
            helpers.ipv6_link_local_from_mac(fake_lrp.mac),
            may_exist=True,
        ).run_idl(txn)


class ReconcileChassisRouterCommand(ReconcileRouterCommand):
    def __init__(self, api, chassis):
        self.chassis = chassis
        router_name = helpers.get_chassis_router_name(self.chassis.name)
        super().__init__(api, router_name)

    @property
    def options(self):
        return {
            'chassis': self.chassis.name,
            constants.LR_OPTIONS_DYNAMIC_ROUTING: 'true',
            constants.LR_OPTIONS_DYNAMIC_ROUTING_VRF_ID:
                str(bgp_config.get_chassis_router_vrf_id()),
        }


class DeleteChassisPeerCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, chassis, network_name):
        super().__init__(api)
        self.chassis = chassis
        self.network_name = network_name

    def run_idl(self, txn):
        chassis_router_name = helpers.get_chassis_router_name(
            self.chassis.name)
        switch_name = helpers.get_chassis_peer_switch_name(
            self.chassis.name, self.network_name)
        peer_switch_lrp_name = helpers.get_lrp_name(
            chassis_router_name, switch_name)

        try:
            nb_cmd.LrPolicyDelCommand(
                self.api,
                chassis_router_name,
                priority=constants.LR_BGP_TO_CHASSIS_POLICY_PRIORITY,
                match=f'inport=="{peer_switch_lrp_name}"',
                if_exists=True,
            ).run_idl(txn)
        except idlutils.RowNotFound:
            pass

        nb_cmd.LsDelCommand(
            self.api, switch_name, if_exists=True,
        ).run_idl(txn)

        nb_cmd.LrpDelCommand(
            self.api,
            peer_switch_lrp_name,
            if_exists=True,
        ).run_idl(txn)


class DeleteChassisCommand(ovs_cmd.BaseCommand):
    """Deletes all resources related to a chassis

    The command deletes all peer connections, main router policies, LRPs, and
    the chassis router. However, it does not delete the HA Chassis Group
    itself because it is referenced by the main router LRP and must be deleted
    in a subsequent transaction.
    """

    def __init__(self, api, chassis):
        super().__init__(api)
        self.chassis = chassis

    def run_idl(self, txn):
        main_router_name = bgp_config.get_main_router_name()
        chassis_router_name = helpers.get_chassis_router_name(
            self.chassis.name)

        self._delete_peers(txn)
        self._delete_main_router_policies(
            chassis_router_name, main_router_name)
        self._cleanup_ha_chassis_group(txn)
        self._delete_lrps(
            txn, chassis_router_name, main_router_name)
        nb_cmd.LrDelCommand(
            self.api, chassis_router_name, if_exists=True,
        ).run_idl(txn)

    def _delete_peers(self, txn):
        for network_name in helpers.get_chassis_bgp_bridges(
                self.chassis):
            DeleteChassisPeerCommand(
                self.api, self.chassis, network_name,
            ).run_idl(txn)

    def _delete_main_router_policies(
            self, chassis_router_name, main_router_name):
        lrp_main = helpers.get_lrp_name(
            main_router_name, chassis_router_name)
        chassis_resident = (
            f'is_chassis_resident("cr-{lrp_main}")')

        main_router = _get_main_router(self.api)
        for policy in list(main_router.policies):
            if chassis_resident in policy.match:
                main_router.delvalue('policies', policy)
                policy.delete()

    def _delete_lrps(self, txn, chassis_router_name,
                     main_router_name):
        lrp_main = helpers.get_lrp_name(
            main_router_name, chassis_router_name)
        lrp_ch = helpers.get_lrp_name(
            chassis_router_name, main_router_name)

        try:
            lrp_main_row = self.api.lookup(
                'Logical_Router_Port', lrp_main)
            lrp_main_row.ha_chassis_group = []
        except idlutils.RowNotFound:
            pass

        nb_cmd.LrpDelCommand(
            self.api, lrp_ch, if_exists=True,
        ).run_idl(txn)
        nb_cmd.LrpDelCommand(
            self.api, lrp_main, if_exists=True,
        ).run_idl(txn)

    def _cleanup_ha_chassis_group(self, txn):
        hcg_name = helpers.get_hcg_name(self.chassis.name)
        try:
            hcg = self.api.lookup(
                'HA_Chassis_Group', hcg_name)
        except idlutils.RowNotFound:
            return
        nb_cmd.HAChassisGroupDelChassisCommand(
            self.api, hcg.uuid, self.chassis.name,
            if_exists=True,
        ).run_idl(txn)

        # The HA Chassis Group itself remains because the reference
        # integrity in the schema prevents it from being deleted in the same
        # transaction


class ConnectRouterToSwitchCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, router_name, switch_name, lrp_ips=None):
        super().__init__(api)
        self.router_name = router_name
        self.switch_name = switch_name
        self.lrp_name = helpers.get_lrp_name(
            self.router_name, self.switch_name)
        self.lrp_ips = lrp_ips or []

    def run_idl(self, txn):
        _LrpAddCommand(
            self.api,
            self.router_name,
            self.lrp_name,
            networks=self.lrp_ips,
        ).run_idl(txn)

        lsp_name = helpers.get_lsp_name(self.switch_name, self.router_name)
        _LspAddCommand(
            self.api,
            self.switch_name,
            lsp_name,
            addresses=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER,
            type=ovn_const.LSP_TYPE_ROUTER,
            options={'router-port': self.lrp_name},
        ).run_idl(txn)


class ReconcileGatewayIPCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, dhcp_opt):
        super().__init__(api)
        prefixlen = netaddr.IPNetwork(dhcp_opt.cidr).prefixlen
        self.gw_ip = f"{dhcp_opt.options['router']}/{prefixlen}"
        router_name = bgp_config.get_main_router_name()
        try:
            n_net_id = dhcp_opt.external_ids[
                ovn_const.OVN_NETWORK_ID_EXT_ID_KEY]
        except KeyError:
            raise exceptions.ReconcileError(
                f"DHCP option {dhcp_opt} does not have a network ID")
        interconnect_switch_name = (
            helpers.get_provider_interconnect_switch_name(
                f"neutron-{n_net_id}"))
        self.lrp_name = helpers.get_lrp_name(
            router_name, interconnect_switch_name)

    def run_idl(self, txn):
        try:
            lrp = self.api.lookup('Logical_Router_Port', self.lrp_name)
        except idlutils.RowNotFound:
            LOG.error("LRP %s not found", self.lrp_name)
            return

        # Use addvalue (OVSDB mutate insert) instead of read-modify-write.
        # Reading lrp.networks between back-to-back transactions can return
        # stale data from the IDL cache, causing duplicates. addvalue is
        # idempotent for set columns and avoids this race.
        lrp.addvalue('networks', self.gw_ip)


class ConnectChassisRouterToSwitchCommand(ConnectRouterToSwitchCommand):
    def __init__(self, api, router_name, switch_name, network_name):
        super().__init__(api, router_name, switch_name)
        self.network_name = network_name

    def run_idl(self, txn):
        super().run_idl(txn)
        ovs_cmd.DbSetCommand(
            self.api,
            'Logical_Router_Port',
            self.lrp_name,
            external_ids={
                constants.LRP_NETWORK_NAME_EXT_ID_KEY: self.network_name,
            },
            options={
                constants.LRP_OPTIONS_PORT_NAME: self.network_name,
            },
        ).run_idl(txn)


class ConnectChassisRouterToMainRouterCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, chassis, hcg_uuid):
        super().__init__(api)
        self.chassis = chassis
        self.hcg_uuid = hcg_uuid
        self.router_name = helpers.get_chassis_router_name(self.chassis.name)

    def validate_prerequisites(self):
        for router_name in [
                bgp_config.get_main_router_name(), self.router_name]:
            try:
                self.api.lookup('Logical_Router', router_name)
            except idlutils.RowNotFound:
                raise exceptions.ReconcileError(
                    f"Router {router_name} not found")

    def run_idl(self, txn):
        self.validate_prerequisites()

        main_router_name = bgp_config.get_main_router_name()

        lrp_main = helpers.get_lrp_name(main_router_name, self.router_name)
        lrp_ch = helpers.get_lrp_name(self.router_name, main_router_name)

        _LrpAddCommand(
            self.api,
            self.router_name,
            lrp_ch,
            peer=lrp_main,
            options={
                constants.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF: 'true',
            },
        ).run_idl(txn)

        self.row_result = _run_idl_command(_LrpAddCommand(
            self.api,
            main_router_name,
            lrp_main,
            peer=lrp_ch,
            ha_chassis_group=self.hcg_uuid,
            options={
                constants.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF: 'true'},
            external_ids={
                constants.BGP_LRP_TO_CHASSIS: self.router_name,
            },
        ), txn)


class ReconcileMainRouterPoliciesForChassisCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, chassis_lrp):
        super().__init__(api)
        self.chassis_lrp = chassis_lrp

    def run_idl(self, txn):
        router = _get_main_router(self.api)
        for switch in _get_all_provider_switches(self.api):
            interconnect_switch_name = (
                helpers.get_provider_interconnect_switch_name(switch.name))
            lrp_interconnect_name = helpers.get_lrp_name(
                router.name, interconnect_switch_name)
            ReconcileMainRouterPoliciesCommand(
                self.api,
                router,
                lrp_interconnect_name,
                self.chassis_lrp,
            ).run_idl(txn)


class ReconcileChassisCommand(ovs_cmd.BaseCommand):
    """Reconcile all BGP components for a chassis

    The command reconciles the chassis router and all its configured peer
    connections based on the configured BGP bridges on the given chassis. It
    creates a logical switch with a localnet port connected to the BGP bridge,
    creates routes in and out on the router and connects the router to the main
    router with a peer connection.
    """

    def __init__(self, api, chassis):
        super().__init__(api)
        self.chassis = chassis

    def run_idl(self, txn):
        hcg_name = helpers.get_hcg_name(self.chassis.name)
        hcg = _run_idl_command(_HAChassisGroupAddCommand(
            self.api,
            hcg_name), txn)

        nb_cmd.HAChassisGroupAddChassisCommand(
            self.api,
            hcg.uuid,
            self.chassis.name, constants.HA_CHASSIS_GROUP_PRIORITY
        ).run_idl(txn)

        ReconcileChassisRouterCommand(
            self.api,
            self.chassis,
        ).run_idl(txn)

        chassis_lrp = _run_idl_command(
            ConnectChassisRouterToMainRouterCommand(
                self.api,
                self.chassis,
                hcg.uuid,
            ), txn)

        ReconcileMainRouterPoliciesForChassisCommand(
            self.api,
            chassis_lrp,
        ).run_idl(txn)

        for bgp_bridge in helpers.get_chassis_bgp_bridges(self.chassis):
            ReconcileChassisPeerCommand(
                self.api,
                self.chassis,
                network_name=bgp_bridge,
            ).run_idl(txn)


class ReconcileChassisPeerCommand(ovs_cmd.BaseCommand):
    """The command reconciles a BGP peer connection for a chassis

    The BGP peer connection is based on the BGP bridge chassis configuration.
    It creates a logical switch with a localnet port connected to the BGP
    bridge. All traffic is routed out to the localnet port but there is a
    policy based on the inport, so traffic coming from the main BGP router is
    rerouted with ECMP to the peer IP, that typically resides on the
    neighboring physical switch.
    """

    def __init__(
            self, api, chassis, network_name):
        super().__init__(api)
        self.chassis = chassis
        self.network_name = network_name

    @property
    def chassis_router_name(self):
        return helpers.get_chassis_router_name(self.chassis.name)

    @property
    def switch_name(self):
        return helpers.get_chassis_peer_switch_name(
            self.chassis.name, self.network_name)

    def run_idl(self, txn):
        CreateSwitchWithLocalnetCommand(
            self.api,
            self.switch_name,
            self.network_name,
        ).run_idl(txn)

        ConnectChassisRouterToSwitchCommand(
            self.api,
            self.chassis_router_name,
            self.switch_name,
            network_name=self.network_name,
        ).run_idl(txn)

        peer_switch_lrp_name = helpers.get_lrp_name(
            self.chassis_router_name, self.switch_name)
        match = f'inport=="{peer_switch_lrp_name}"'
        lrp_to_main_router_name = helpers.get_lrp_name(
            self.chassis_router_name, bgp_config.get_main_router_name())
        lrp = self.api.lookup('Logical_Router_Port', lrp_to_main_router_name)
        lrp_peer_ip = _get_lrp_peer_ip(self.api, lrp)
        _LrPolicyAddCommand(
            self.api,
            self.chassis_router_name,
            priority=constants.LR_BGP_TO_CHASSIS_POLICY_PRIORITY,
            match=match,
            action=ovsdbapp_const.POLICY_ACTION_REROUTE,
            nexthops=[lrp_peer_ip],
            output_port=lrp,
        ).run_idl(txn)


class FullSyncBGPTopologyCommand(ovs_cmd.BaseCommand):
    def __init__(self, nb_api, sb_api):
        super().__init__(nb_api)
        self.sb_api = sb_api

    def run_idl(self, txn):
        LOG.debug("BGP full sync topology started")
        self.reconcile_central(txn)
        self.reconcile_all_chassis(txn)
        self.reconcile_neutron_switches(txn)
        LOG.debug("BGP full sync topology completed")

    def reconcile_all_chassis(self, txn):
        for chassis in self.sb_api.tables['Chassis_Private'].rows.values():
            ReconcileChassisCommand(self.api, chassis).run_idl(txn)

    def reconcile_neutron_switches(self, txn):
        for switch in _get_all_provider_switches(self.api):
            ReconcileNeutronSwitchCommand(
                self.api,
                switch,
            ).run_idl(txn)

    def reconcile_central(self, txn):
        ReconcileMainRouterCommand(
            self.api,
        ).run_idl(txn)
