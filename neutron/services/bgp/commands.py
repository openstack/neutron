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
    instead. Imporant is that in case of a new row creation, the row_result
    does not contain the same UUID that is stored in the DB after the commit.
    """
    cmd.run_idl(txn)
    return cmd.row_result


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
        }


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
            peer=lrp_main
        ).run_idl(txn)

        _LrpAddCommand(
            self.api,
            main_router_name,
            lrp_main,
            peer=lrp_ch,
            ha_chassis_group=self.hcg_uuid,
            options={
                constants.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF: 'true'},
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

        # Connect chassis router to the main router
        ConnectChassisRouterToMainRouterCommand(
            self.api,
            self.chassis,
            hcg.uuid,
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
        match=f'inport==\"{peer_switch_lrp_name}\"'
        lrp_to_main_router_name = helpers.get_lrp_name(
            self.chassis_router_name, bgp_config.get_main_router_name())
        lrp = self.api.lookup('Logical_Router_Port', lrp_to_main_router_name)
        _LrPolicyAddCommand(
            self.api,
            self.chassis_router_name,
            priority=10,
            match=match,
            action=ovsdbapp_const.POLICY_ACTION_REROUTE,
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
        LOG.debug("BGP full sync topology completed")

    def reconcile_all_chassis(self, txn):
        for chassis in self.sb_api.tables['Chassis_Private'].rows.values():
            ReconcileChassisCommand(self.api, chassis).run_idl(txn)

    def reconcile_central(self, txn):
        ReconcileMainRouterCommand(
            self.api,
        ).run_idl(txn)
