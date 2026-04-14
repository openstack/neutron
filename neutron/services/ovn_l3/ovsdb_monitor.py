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
    HA_Chassis_Group, matching the Logical_Router_Port HA_Chassis_Group.
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
        try:
            ls_name = row.external_ids[ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY]
            lr_name = row.external_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY]
        except KeyError:
            # The Logical_Router_Port doesn't have the Neutron owned resources
            # external_ids ("neutron:network_name", "neutron:router_name").
            return False

        if event == self.ROW_DELETE:
            # Check if the LR has another port in the same network. If that is
            # the case, do nothing.
            lr = self.driver._nb_ovn.lookup('Logical_Router', lr_name,
                                            default=None)
            if not lr:
                # The LRP has been deleted along with the LR. That happens
                # only with the GW LRPs. No action needed.
                return False

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


class RouterHAChassisGroupEvent(row_event.RowEvent):
    """HA_Chassis_Group change event for router gateway ports.

    When the HA_Chassis list of a router's HA_Chassis_Group changes, it is
    needed to update the linked network HA_Chassis_Group registers.
    """

    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.admin_context = neutron_context.get_admin_context()
        table = 'HA_Chassis_Group'
        events = (self.ROW_UPDATE, )
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if not hasattr(old, 'ha_chassis'):
            return False

        # Only match router HA_Chassis_Groups (those with a router_id tag
        # but without a network_id tag, to exclude network HCGs).
        ext_ids = row.external_ids
        return (bool(ext_ids.get(ovn_const.OVN_ROUTER_ID_EXT_ID_KEY)) and
                ovn_const.OVN_NETWORK_ID_EXT_ID_KEY not in ext_ids)

    def run(self, event, row, old=None):
        router_id = row.external_ids[ovn_const.OVN_ROUTER_ID_EXT_ID_KEY]
        self.l3_plugin._ovn_client.update_router_ha_chassis_group(
            self.admin_context, router_id)
