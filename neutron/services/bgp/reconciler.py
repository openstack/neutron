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

import enum

from oslo_log import log

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import commands
from neutron.services.bgp import events
from neutron.services.bgp import helpers
from neutron.services.bgp import ovn


LOG = log.getLogger(__name__)


class BGPTopologyReconciler:
    class BGPReconcilerResource(enum.Enum):
        CHASSIS_BGP_BRIDGES = 'chassis-bgp-bridges'

        def __str__(self):
            return self.value

    def __init__(self):
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
    def resource_map(self):
        return {
            self.BGPReconcilerResource.CHASSIS_BGP_BRIDGES:
                self.reconcile_chassis_bgp_bridges,
        }

    @property
    def nb_events(self):
        return [
        ]

    @property
    def sb_events(self):
        return [
            events.BGPChassisBridgesUpdateEvent(self),
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

    def reconcile(self, resource, trigger):
        try:
            self.resource_map[resource](trigger)
        except KeyError:
            LOG.error("Resource %s not found in reconciler resource map",
                      resource)

    def reconcile_chassis_bgp_bridges(self, chassis):
        for bgp_bridge in helpers.get_chassis_bgp_bridges(chassis):
            commands.ReconcileChassisPeerCommand(
                self.nb_api,
                chassis,
                network_name=bgp_bridge,
            ).execute(check_error=True)
