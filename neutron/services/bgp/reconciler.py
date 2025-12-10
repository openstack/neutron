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

from neutron.services.bgp import commands

LOG = log.getLogger(__name__)


class BGPTopologyReconciler:
    def __init__(self, nb_ovn, sb_ovn):
        self.nb_ovn = nb_ovn
        self.sb_ovn = sb_ovn
        # We are doing full sync when the extension is started so we don't
        # need to process all events when IDLs connect.
        self.register_events()

    def register_events(self):
        self.nb_ovn.register_events(self.nb_events)
        self.sb_ovn.register_events(self.sb_events)

    @property
    def resource_map(self):
        return {
        }

    @property
    def nb_events(self):
        return [
        ]

    @property
    def sb_events(self):
        return [
        ]

    def full_sync(self):
        if not self.nb_ovn.ovsdb_connection.idl.is_lock_contended:
            LOG.info("Full BGP topology synchronization started")
            # First make sure all chassis are indexed
            commands.FullSyncBGPTopologyCommand(
                self.nb_ovn,
                self.sb_ovn,
            ).execute(check_error=True)
            LOG.info(
                "Full BGP topology synchronization completed successfully")
        else:
            LOG.info("Full BGP topology synchronization already in progress")

    def reconcile(self, resource, uuid):
        try:
            self.resource_map[resource](uuid)
        except KeyError:
            LOG.error("Resource %s not found in reconciler resource map",
                      resource)
