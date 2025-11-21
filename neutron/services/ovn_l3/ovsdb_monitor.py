# Copyright 2025 Red Hat, Inc.
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

from neutron_lib import context as neutron_context
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_utils import strutils
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils


class LogicalRouterPortEvent(row_event.RowEvent):
    """Logical_Router_Port create/delete event.

    If a Logical_Router_Port is deleted or added, first check if this LRP is a
    gateway port or not. Then update the corresponding network (or networks)
    HA_Chassis_Group, matching the Logical_Router Gateway_Chassis.
    See LP#2125553.
    """
    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.admin_context = neutron_context.get_admin_context()
        table = 'Logical_Router_Port'
        events = (self.ROW_CREATE, self.ROW_DELETE)
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if event == self.ROW_DELETE:
            # Check if the LR has another port in the same network. If that is
            # the case, do nothing.
            ls_name = row.external_ids[ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY]
            lr_name = row.external_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY]
            lr = self.driver._nb_ovn.lookup('Logical_Router', lr_name)
            for lrp in (lrp for lrp in lr.ports if lrp.name != row.name):
                if (ls_name == lrp.external_ids[
                        ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY]):
                    return False
            return True

        # event == self.ROW_CREATE
        return True

    def run(self, event, row, old=None):
        ext_gw = row.external_ids.get(ovn_const.OVN_ROUTER_IS_EXT_GW)
        router_id = utils.get_neutron_name(
            row.external_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY])
        net_id = utils.get_neutron_name(
            row.external_ids[ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY])
        if event == self.ROW_DELETE:
            if not strutils.bool_from_string(ext_gw):  # LRP internal port.
                self.l3_plugin._ovn_client.unlink_network_ha_chassis_group(
                    net_id)
            else:  # LRP gateway port.
                self.l3_plugin._ovn_client.update_router_ha_chassis_group(
                    self.admin_context, router_id)

        else:  # event == self.ROW_CREATE
            if not strutils.bool_from_string(ext_gw):  # LRP internal port.
                self.l3_plugin._ovn_client.link_network_ha_chassis_group(
                    self.admin_context, net_id, router_id)
            else:  # LRP gateway port.
                self.l3_plugin._ovn_client.update_router_ha_chassis_group(
                    self.admin_context, router_id)


class LogicalRouterPortGatewayChassisEvent(row_event.RowEvent):
    """Logical_Router_Port Gateway_Chassis change event.

    When the Gateway_Chassis list of a Logical_Router_Port changes, it is
    needed to update the linked HA_Chassis_Group registers.
    """
    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.admin_context = neutron_context.get_admin_context()
        table = 'Logical_Router_Port'
        events = (self.ROW_UPDATE, )
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if hasattr(old, 'gateway_chassis'):
            # NOTE: when a Gateway_Chassis register is deleted, is no longer
            # present in the old.gateway_chassis list.
            return True

        return False

    def run(self, event, row, old=None):
        lr_name = row.external_ids.get(ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)
        router_id = utils.get_neutron_name(lr_name)
        self.l3_plugin._ovn_client.update_router_ha_chassis_group(
            self.admin_context, router_id)
