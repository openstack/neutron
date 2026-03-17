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

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import commands
from neutron.services.bgp import constants
from neutron.services.bgp import events
from neutron.services.bgp import helpers
from neutron.services.bgp import ovn


LOG = log.getLogger(__name__)


class BGPTopologyReconciler:
    def __init__(self):
        self.resource_map = {
            constants.Action.RECONCILE: {
                constants.BGPReconcilerResource.CHASSIS_BGP_BRIDGES:
                    self.reconcile_chassis_bgp_bridges,
                constants.BGPReconcilerResource.PROVIDER_SWITCH:
                    self.reconcile_provider_switch,
                constants.BGPReconcilerResource.GATEWAY_IP:
                    self.reconcile_gateway_ip,
                constants.BGPReconcilerResource.CHASSIS:
                    self.reconcile_chassis,
            },
            constants.Action.DELETE: {
                constants.BGPReconcilerResource.PROVIDER_SWITCH:
                    self.delete_provider_switch,
                constants.BGPReconcilerResource.CHASSIS:
                    self.delete_chassis,
            },
        }
        self.nb_api = ovn.OvnNbIdl(
            ovn_conf.get_ovn_nb_connection(),
            self.nb_events).start(
                timeout=ovn_conf.get_ovn_ovsdb_timeout())
        self.sb_api = ovn.OvnSbIdl(
            ovn_conf.get_ovn_sb_connection(),
            self.sb_events).start(
                timeout=ovn_conf.get_ovn_ovsdb_timeout())

    def stop(self):
        self.nb_api.stop()
        self.sb_api.stop()

    @property
    def nb_events(self):
        return [
            events.ProviderSwitchEvent(self),
            events.GatewayIPCreatedEvent(self),
            events.GatewayIPUpdatedEvent(self),
        ]

    @property
    def sb_events(self):
        return [
            events.BGPChassisBridgesUpdateEvent(self),
            events.BGPChassisEvent(self),
        ]

    def full_sync(self):
        if not self.nb_api.ovsdb_connection.idl.is_lock_contended:
            LOG.info("Full BGP topology synchronization started")
            # First make sure all chassis are indexed
            commands.FullSyncBGPTopologyCommand(
                self.nb_api, self.sb_api).execute(check_error=True)
            LOG.info(
                "Full BGP topology synchronization completed successfully")
        else:
            LOG.info("Full BGP topology synchronization already in progress")

    def reconcile(self, action, resource, trigger):
        try:
            self.resource_map[action][resource](trigger)
        except KeyError:
            LOG.error(
                "Resource %s or action %s not found in reconciler resource "
                "map", resource, action)

    def reconcile_chassis_bgp_bridges(self, chassis):
        for bgp_bridge in helpers.get_chassis_bgp_bridges(chassis):
            commands.ReconcileChassisPeerCommand(
                self.nb_api,
                chassis,
                network_name=bgp_bridge,
            ).execute(check_error=True)

    def reconcile_provider_switch(self, switch):
        commands.ReconcileNeutronSwitchCommand(
            self.nb_api,
            switch,
        ).execute(check_error=True)

    def reconcile_gateway_ip(self, dhcp_opt):
        commands.ReconcileGatewayIPCommand(
            self.nb_api,
            dhcp_opt,
        ).execute(check_error=True)

    def delete_provider_switch(self, switch):
        commands.DeleteNeutronSwitchCommand(
            self.nb_api,
            switch,
        ).execute(check_error=True)

    def reconcile_chassis(self, chassis):
        LOG.info("Reconciling chassis %s", chassis.name)
        commands.ReconcileChassisCommand(
            self.nb_api,
            chassis,
        ).execute(check_error=True)

    def delete_chassis(self, chassis):
        LOG.info("Deleting chassis %s", chassis.name)
        commands.DeleteChassisCommand(
            self.nb_api,
            chassis,
        ).execute(check_error=True)

        # The HA Chassis Group cannot be deleted in the same transaction as
        # the LRP that references it, we need to delete it in a subsequent
        # transaction.
        commands.HaChassisGroupDelCommand(
            self.nb_api,
            chassis,
        ).execute(check_error=True)
