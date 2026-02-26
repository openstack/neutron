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

import typing

import netaddr
from neutron_lib import constants as n_const
from oslo_log import log
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants

LOG = log.getLogger(__name__)

_event_to_action = {
    row_event.RowEvent.ROW_CREATE: constants.Action.RECONCILE,
    row_event.RowEvent.ROW_UPDATE: constants.Action.RECONCILE,
    row_event.RowEvent.ROW_DELETE: constants.Action.DELETE,
}


class BGPReconcilerResourceEvent(row_event.RowEvent):
    RESOURCE: typing.ClassVar[
        constants.BGPReconcilerResource | None] = None

    def __init__(self, reconciler):
        super().__init__(self.EVENTS, self.TABLE, None)
        self.reconciler = reconciler

    @property
    def event_name(self):
        return self.__class__.__name__

    def run(self, event, row, old):
        self.reconciler.reconcile(_event_to_action[event], self.RESOURCE, row)


class BGPChassisBridgesUpdateEvent(BGPReconcilerResourceEvent):
    """Event for chassis BGP bridges updates.

    This event is triggered only if bgp-bridges are changed.
    """
    EVENTS = (BGPReconcilerResourceEvent.ROW_UPDATE,)
    RESOURCE = constants.BGPReconcilerResource.CHASSIS_BGP_BRIDGES
    TABLE = 'Chassis_Private'

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


class ProviderSwitchCreatedEvent(BGPReconcilerResourceEvent):
    EVENTS = (BGPReconcilerResourceEvent.ROW_CREATE,)
    RESOURCE = constants.BGPReconcilerResource.PROVIDER_SWITCH
    TABLE = 'Logical_Switch'

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False
        net_type = row.external_ids.get(ovn_const.OVN_NETTYPE_EXT_ID_KEY)
        return net_type in n_const.TYPE_PHYSICAL


class GatewayIPEvent(BGPReconcilerResourceEvent):
    RESOURCE = constants.BGPReconcilerResource.GATEWAY_IP
    TABLE = 'DHCP_Options'

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        if netaddr.IPNetwork(row.cidr).version == 6:
            return False

        net_id = row.external_ids.get(ovn_const.OVN_NETWORK_ID_EXT_ID_KEY)
        try:
            switch = self.reconciler.nb_api.lookup(
                'Logical_Switch', ovn_utils.ovn_name(net_id))
        except idlutils.RowNotFound:
            LOG.warning("Switch neutron-%s not found", net_id)
            return False

        net_type = switch.external_ids.get(ovn_const.OVN_NETTYPE_EXT_ID_KEY)
        return net_type in n_const.TYPE_PHYSICAL


class GatewayIPCreatedEvent(GatewayIPEvent):
    EVENTS = (BGPReconcilerResourceEvent.ROW_CREATE,)

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        return 'router' in row.options


class GatewayIPUpdatedEvent(GatewayIPEvent):
    EVENTS = (BGPReconcilerResourceEvent.ROW_UPDATE,)

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        if not hasattr(old, 'options'):
            return False

        return ('router' in row.options and
                row.options['router'] != old.options.get('router'))
