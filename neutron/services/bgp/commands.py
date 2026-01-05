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
from ovsdbapp.schema.ovn_northbound import commands as nb_cmd

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
                bgp_config.get_bgp_router_tunnel_key(),
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
        }


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
