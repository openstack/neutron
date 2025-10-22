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

from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.services.bgp import constants


class BGPChassisEvent(row_event.RowEvent):
    TABLE = 'Chassis_Private'

    def __init__(self, reconciler):
        super().__init__(self.EVENTS, self.TABLE, None)
        self.reconciler = reconciler

    @property
    def event_name(self):
        return self.__class__.__name__


class BGPChassisBridgesUpdateEvent(BGPChassisEvent):
    """Event for chassis BGP bridges updates.

    This event is triggered only if bgp-bridges are changed.
    """
    EVENTS = (BGPChassisEvent.ROW_UPDATE,)

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False
        if not hasattr(old, 'external_ids'):
            return False
        current_bgp_bridges = row.external_ids.get(
            constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY)
        old_bgp_bridges = old.external_ids.get(
            constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY)

        return current_bgp_bridges != old_bgp_bridges

    def run(self, event, row, old):
        self.reconciler.reconcile(
            self.reconciler.BGPReconcilerResource.CHASSIS_BGP_BRIDGES,
            row)
