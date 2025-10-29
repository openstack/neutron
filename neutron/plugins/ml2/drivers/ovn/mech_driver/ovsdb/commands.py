# Copyright 2019 Red Hat, Inc.
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

import abc
import copy
import uuid

from oslo_utils import timeutils
from ovs.db import idl as ovs_idl
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.backend.ovs_idl import rowview
from ovsdbapp.schema.ovn_northbound import commands as ovn_nb_commands
from ovsdbapp import utils as ovsdbapp_utils

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils
from neutron.services.portforwarding.constants import PORT_FORWARDING_PREFIX

from oslo_log import log


LOG = log.getLogger(__name__)

RESOURCE_TYPE_MAP = {
    ovn_const.TYPE_NETWORKS: 'Logical_Switch',
    ovn_const.TYPE_PORTS: 'Logical_Switch_Port',
    ovn_const.TYPE_ROUTERS: 'Logical_Router',
    ovn_const.TYPE_ROUTER_PORTS: 'Logical_Router_Port',
    ovn_const.TYPE_FLOATINGIPS: 'NAT',
    ovn_const.TYPE_SUBNETS: 'DHCP_Options',
    ovn_const.TYPE_ADDRESS_GROUPS: 'Address_Set',
}


def _addvalue_to_list(row, column, new_value):
    row.addvalue(column, new_value)


def _delvalue_from_list(row, column, old_value):
    row.delvalue(column, old_value)


def _updatevalues_in_list(row, column, new_values=None, old_values=None):
    new_values = new_values or []
    old_values = old_values or []

    for new_value in new_values:
        row.addvalue(column, new_value)
    for old_value in old_values:
        row.delvalue(column, old_value)


def get_lsp_dhcp_options_uuids(lsp, lsp_name):
    # Get dhcpv4_options and dhcpv6_options uuids from Logical_Switch_Port,
    # which are references of port dhcp options in DHCP_Options table.
    uuids = set()
    for dhcp_opts in getattr(lsp, 'dhcpv4_options', []):
        external_ids = getattr(dhcp_opts, 'external_ids', {})
        if external_ids.get('port_id') == lsp_name:
            uuids.add(dhcp_opts.uuid)
    for dhcp_opts in getattr(lsp, 'dhcpv6_options', []):
        external_ids = getattr(dhcp_opts, 'external_ids', {})
        if external_ids.get('port_id') == lsp_name:
            uuids.add(dhcp_opts.uuid)
    return uuids


def _add_gateway_chassis(api, txn, lrp_name, val):
    gateway_chassis = api._tables.get('Gateway_Chassis')
    if not gateway_chassis:
        chassis = {ovn_const.OVN_GATEWAY_CHASSIS_KEY: val[0]}
        return 'options', chassis
    prio = len(val)
    uuid_list = []
    for chassis in val:
        gwc_name = f'{lrp_name}_{chassis}'
        try:
            gwc = idlutils.row_by_value(
                api.idl, 'Gateway_Chassis', 'name', gwc_name)
        except idlutils.RowNotFound:
            gwc = txn.insert(gateway_chassis)
            gwc.name = gwc_name
        gwc.chassis_name = chassis
        gwc.priority = prio
        LOG.info(
            "Schedule LRP %(lrp)s on gateway %(gtw)s with priority %(prio)s",
            {"lrp": lrp_name, "gtw": chassis, "prio": prio})
        prio = prio - 1
        uuid_list.append(gwc.uuid)
    return 'gateway_chassis', uuid_list


def _sync_ha_chassis_group(txn, nb_api, name, chassis_priority,
                           may_exist=False, table_name='HA_Chassis_Group',
                           **columns):
    result = None
    hcg = nb_api.lookup(table_name, name, default=None)
    if hcg:
        if not may_exist:
            raise RuntimeError(_('HA_Chassis_Group %s exists') % name)
    else:
        hcg = txn.insert(nb_api._tables[table_name])
        hcg.name = name
        command.BaseCommand.set_columns(hcg, **columns)
        result = hcg.uuid

    # HA_Chassis registers handling.
    # Remove the non-existing chassis in ``self.chassis_priority``
    hc_to_remove = []
    for hc in getattr(hcg, 'ha_chassis', []):
        if hc.chassis_name not in chassis_priority:
            hc_to_remove.append(hc)

    for hc in hc_to_remove:
        hcg.delvalue('ha_chassis', hc)
        hc.delete()

    # Update the priority of the existing chassis.
    for hc in getattr(hcg, 'ha_chassis', []):
        hc_priority = chassis_priority.pop(hc.chassis_name)
        hc.priority = hc_priority

    # Add the non-existing HA_Chassis registers.
    for hc_name, priority in chassis_priority.items():
        hc = txn.insert(nb_api.tables['HA_Chassis'])
        hc.chassis_name = hc_name
        hc.priority = priority
        hcg.addvalue('ha_chassis', hc)

    if not result:
        result = rowview.RowView(hcg)

    return result


class CheckLivenessCommand(command.BaseCommand):
    def run_idl(self, txn):
        # txn.pre_commit responsible for updating nb_global.nb_cfg, but
        # python-ovs will not update nb_cfg if no other changes are made
        self.api.nb_global.setkey('external_ids',
                                  ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY,
                                  str(timeutils.utcnow(with_timezone=True)))
        self.result = self.api.nb_global.nb_cfg


class AddNetworkCommand(command.AddCommand):
    table_name = 'Logical_Switch'

    def __init__(self, api, network_id, may_exist=False, **columns):
        super().__init__(api)
        self.network_uuid = uuid.UUID(str(network_id))
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):
        table = self.api.tables[self.table_name]
        try:
            ls = table.rows[self.network_uuid]
            if self.may_exist:
                self.result = rowview.RowView(ls)
                return
            msg = _("Switch %s already exists") % self.network_uuid
            raise RuntimeError(msg)
        except KeyError:
            # Adding a new LS
            if utils.ovs_persist_uuid_supported(txn.idl):
                ls = txn.insert(table, new_uuid=self.network_uuid,
                                persist_uuid=True)
            else:
                ls = txn.insert(table)
        self.set_columns(ls, **self.columns)
        ls.name = utils.ovn_name(self.network_uuid)
        self.result = ls.uuid


class DelLogicalSwitchCommand(command.BaseCommand):
    def __init__(self, api, ls_name, if_exists):
        super().__init__(api)
        self.ls_name = ls_name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            ls = self.api.lookup('Logical_Switch', self.ls_name)
        except idlutils.RowNotFound as e:
            if self.if_exists:
                return
            msg = "Logical Switch %s does not exist" % self.ls_name
            raise RuntimeError(msg) from e

        # Delete the DNS record associated to this Neutron network.
        for dns_row in ls.dns_records:
            if dns_row.external_ids.get('ls_name') == self.ls_name:
                dns_row.delete()
                break

        # Delete the Logical_Switch register.
        ls.delete()

        # Delete the HA_Chassis_Group register associated, if exists.
        hcg = self.api.lookup('HA_Chassis_Group', self.ls_name, default=None)
        if hcg:
            hcg.delete()


class AddLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, lswitch, may_exist, network_id=None,
                 **columns):
        super().__init__(api)
        self.lport = lport
        self.lswitch = lswitch
        self.may_exist = may_exist
        self.network_uuid = uuid.UUID(str(network_id)) if network_id else None
        self.columns = columns

    def run_idl(self, txn):
        try:
            # We must look in the local cache first, because the LS may have
            # been created as part of the current transaction. or in the case
            # of adding an LSP to a LS that was created before persist_uuid
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            if self.network_uuid and utils.ovs_persist_uuid_supported(txn.idl):
                # Create a "fake" row with the right UUID so python-ovs creates
                # a transaction referencing the Row, even though we might not
                # have received the update for the row ourselves.
                lswitch = ovs_idl.Row(self.api.idl,
                                      self.api.tables['Logical_Switch'],
                                      uuid=self.network_uuid, data={})
            else:
                msg = _("Logical Switch %s does not exist") % self.lswitch
                raise RuntimeError(msg)
        if self.may_exist:
            port = idlutils.row_by_value(self.api.idl,
                                         'Logical_Switch_Port', 'name',
                                         self.lport, None)
            if port:
                self.result = port.uuid
                return

        port = txn.insert(self.api._tables['Logical_Switch_Port'])
        port.name = self.lport
        port.tag = self.columns.pop('tag', []) or []
        dhcpv4_options = self.columns.pop('dhcpv4_options', [])
        if isinstance(dhcpv4_options, list):
            port.dhcpv4_options = dhcpv4_options
        else:
            port.dhcpv4_options = [dhcpv4_options.result]
        dhcpv6_options = self.columns.pop('dhcpv6_options', [])
        if isinstance(dhcpv6_options, list):
            port.dhcpv6_options = dhcpv6_options
        else:
            port.dhcpv6_options = [dhcpv6_options.result]

        # NOTE(ralonsoh): HA chassis group is created by Neutron, there is no
        # need to create it in this command.
        ha_chassis_group = self.columns.pop('ha_chassis_group', None)
        if ha_chassis_group:
            hcg_uuid = ovsdbapp_utils.get_uuid(ha_chassis_group)
            port.ha_chassis_group = hcg_uuid

        for col, val in self.columns.items():
            setattr(port, col, val)
        # add the newly created port to existing lswitch
        _addvalue_to_list(lswitch, 'ports', port.uuid)
        self.result = port.uuid

    def post_commit(self, txn):
        self.result = txn.get_insert_uuid(self.result)


class SetLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, external_ids_update, if_exists, **columns):
        super().__init__(api)
        self.lport = lport
        self.external_ids_update = external_ids_update
        self.columns = columns
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            port = idlutils.row_by_value(self.api.idl, 'Logical_Switch_Port',
                                         'name', self.lport)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        # Delete DHCP_Options records no longer referred by this port.
        # The table rows should be consistent for the same transaction.
        # After we get DHCP_Options rows uuids from port dhcpv4_options
        # and dhcpv6_options references, the rows shouldn't disappear for
        # this transaction before we delete it.
        cur_port_dhcp_opts = get_lsp_dhcp_options_uuids(
            port, self.lport)
        new_port_dhcp_opts = set()
        dhcpv4_options = self.columns.pop('dhcpv4_options', None)
        if dhcpv4_options is None:
            new_port_dhcp_opts.update([option.uuid for option in
                                       getattr(port, 'dhcpv4_options', [])])
        elif isinstance(dhcpv4_options, list):
            new_port_dhcp_opts.update(dhcpv4_options)
            port.dhcpv4_options = dhcpv4_options
        else:
            new_port_dhcp_opts.add(dhcpv4_options.result)
            port.dhcpv4_options = [dhcpv4_options.result]
        dhcpv6_options = self.columns.pop('dhcpv6_options', None)
        if dhcpv6_options is None:
            new_port_dhcp_opts.update([option.uuid for option in
                                       getattr(port, 'dhcpv6_options', [])])
        elif isinstance(dhcpv6_options, list):
            new_port_dhcp_opts.update(dhcpv6_options)
            port.dhcpv6_options = dhcpv6_options
        else:
            new_port_dhcp_opts.add(dhcpv6_options.result)
            port.dhcpv6_options = [dhcpv6_options.result]
        for uuid_ in cur_port_dhcp_opts - new_port_dhcp_opts:
            self.api._tables['DHCP_Options'].rows[uuid_].delete()

        external_ids_update = self.external_ids_update or {}
        external_ids = getattr(port, 'external_ids', {})
        for k, v in external_ids_update.items():
            external_ids[k] = v
        port.external_ids = external_ids

        # NOTE(ralonsoh): HA chassis group is created by Neutron, there is no
        # need to create it in this command. The register is also deleted when
        # the network to which the HA chassis group is associated is deleted.
        ha_chassis_group = self.columns.pop('ha_chassis_group', None)
        if ha_chassis_group:
            hcg_uuid = ovsdbapp_utils.get_uuid(ha_chassis_group)
            try:
                port_hcg_uuid = port.ha_chassis_group[0].uuid
            except IndexError:
                port_hcg_uuid = None
            if port_hcg_uuid != hcg_uuid:
                port.ha_chassis_group = hcg_uuid
        elif ha_chassis_group == []:
            port.ha_chassis_group = []

        for col, val in self.columns.items():
            setattr(port, col, val)


class UpdateLSwitchPortQosOptionsCommand(command.BaseCommand):
    def __init__(self, api, lport, if_exists, **qos):
        super().__init__(api)
        self.lport = lport
        self.if_exists = if_exists
        self.qos = qos

    def run_idl(self, txn):
        # NOTE(ralonsoh): this command can be called from inside a transaction
        # where the LSP is being created. If this is not the case, the value
        # provided in the Neutron port ID (== LSP.name).
        if isinstance(self.lport, command.BaseCommand):
            port_id = self.lport.result
        else:
            port_id = self.lport

        try:
            port = self.api.lookup('Logical_Switch_Port', port_id)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            raise RuntimeError(_('Logical Switch Port %s does not exist') %
                               port_id)

        # TODO(ralonsoh): add a check to only modify the QoS related keys:
        # qos_max_rate, qos_burst and qos_min_rate.
        for key, value in self.qos.items():
            if value is None:
                port.delkey('options', key)
            else:
                port.setkey('options', key, value)


class DelLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, lswitch, if_exists):
        super().__init__(api)
        self.lport = lport
        self.lswitch = lswitch
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lport = idlutils.row_by_value(self.api.idl, 'Logical_Switch_Port',
                                          'name', self.lport)
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        # Delete DHCP_Options records no longer referred by this port.
        cur_port_dhcp_opts = get_lsp_dhcp_options_uuids(
            lport, self.lport)
        for uuid_ in cur_port_dhcp_opts:
            self.api._tables['DHCP_Options'].rows[uuid_].delete()

        # Delete the HA_Chassis_Group associated to an external port.
        if (lport.type == ovn_const.LSP_TYPE_EXTERNAL and
                lport.ha_chassis_group):
            hcg = lport.ha_chassis_group[0]
            lport.delvalue('ha_chassis_group', hcg)
            if hcg.name == utils.ovn_extport_chassis_group_name(lport.name):
                hcg.delete()

        _delvalue_from_list(lswitch, 'ports', lport)
        self.api._tables['Logical_Switch_Port'].rows[lport.uuid].delete()


class UpdateLRouterCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists, **columns):
        super().__init__(api)
        self.name = name
        self.columns = columns
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name, None)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.name
            raise RuntimeError(msg)

        if lrouter:
            for col, val in self.columns.items():
                setattr(lrouter, col, val)
            return


class ScheduleUnhostedGatewaysCommand(command.BaseCommand):
    def __init__(self, nb_api, g_name, sb_api, plugin, port_physnets,
                 all_gw_chassis, chassis_with_physnets, chassis_with_azs):
        super().__init__(api=nb_api)
        self.g_name = g_name
        self.sb_api = sb_api
        self.scheduler = plugin.scheduler
        self.ovn_client = plugin._ovn_client
        self.port_physnets = port_physnets
        self.all_gw_chassis = all_gw_chassis
        self.chassis_with_physnets = chassis_with_physnets
        self.chassis_with_azs = chassis_with_azs

    def run_idl(self, txn):
        lrouter_port = self.api.lookup("Logical_Router_Port", self.g_name)
        physnet = self.port_physnets.get(
            self.g_name[len(ovn_const.LRP_PREFIX):])
        # Remove any invalid gateway chassis from the list, otherwise
        # we can have a situation where all existing_chassis are invalid
        existing_chassis = self.api.get_gateway_chassis_binding(self.g_name)
        primary = existing_chassis[0] if existing_chassis else None
        az_hints = self.api.get_gateway_chassis_az_hints(self.g_name)
        filtered_existing_chassis = (
            self.scheduler.filter_existing_chassis(
                gw_chassis=self.all_gw_chassis, physnet=physnet,
                chassis_physnets=self.chassis_with_physnets,
                existing_chassis=existing_chassis, az_hints=az_hints,
                chassis_with_azs=self.chassis_with_azs))
        if existing_chassis != filtered_existing_chassis:
            first_diff = None
            for i in range(len(filtered_existing_chassis)):
                if existing_chassis[i] != filtered_existing_chassis[i]:
                    first_diff = i
                    break
            if first_diff is not None:
                LOG.debug(
                    "A chassis for this gateway has been filtered. "
                    "Rebalancing priorities %s and lower", first_diff)
                filtered_existing_chassis = filtered_existing_chassis[
                    :max(first_diff, 1)]

        candidates = self.ovn_client.get_candidates_for_scheduling(
            physnet, cms=self.all_gw_chassis,
            chassis_physnets=self.chassis_with_physnets,
            availability_zone_hints=az_hints)
        chassis = self.scheduler.select(
            self.api, self.sb_api, self.g_name, candidates=candidates,
            existing_chassis=filtered_existing_chassis)
        if primary and primary != chassis[0]:
            if primary not in chassis:
                LOG.debug("Primary gateway chassis %(old)s "
                          "has been removed from the system. Moving "
                          "gateway %(gw)s to other chassis %(new)s.",
                          {'gw': self.g_name,
                           'old': primary,
                           'new': chassis[0]})
            else:
                LOG.debug("Gateway %s is hosted at %s.", self.g_name, primary)
                # NOTE(mjozefcz): It means scheduler moved primary chassis
                # to other gw based on scheduling method. But we don't
                # want network flap - so moving actual primary to be on
                # the top.
                index = chassis.index(primary)
                chassis[0], chassis[index] = chassis[index], chassis[0]
        setattr(
            lrouter_port,
            *_add_gateway_chassis(self.api, txn, self.g_name, chassis))


class ScheduleNewGatewayCommand(command.BaseCommand):
    def __init__(self, nb_api, g_name, sb_api, lrouter_name, plugin, physnet,
                 az_hints):
        super().__init__(nb_api)
        self.g_name = g_name
        self.sb_api = sb_api
        self.lrouter_name = lrouter_name
        self.ovn_client = plugin._ovn_client
        self.scheduler = plugin.scheduler
        self.physnet = physnet
        self.az_hints = az_hints

    def run_idl(self, txn):
        lrouter = self.api.lookup("Logical_Router", self.lrouter_name)
        lrouter_port = self.api.lookup("Logical_Router_Port", self.g_name)

        candidates = self.ovn_client.get_candidates_for_scheduling(
            self.physnet, availability_zone_hints=self.az_hints)
        chassis = self.scheduler.select(
            self.api, self.sb_api, self.g_name, candidates=candidates,
            target_lrouter=lrouter)
        if chassis:
            setattr(lrouter_port,
                    *_add_gateway_chassis(self.api, txn, self.g_name, chassis))


class LrDelCommand(ovn_nb_commands.LrDelCommand):

    def run_idl(self, txn):
        super().run_idl(txn)
        try:
            hcg = self.api.lookup('HA_Chassis_Group', self.router)
            hcg.delete()
        except idlutils.RowNotFound:
            pass


class AddLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, lrouter, may_exist, **columns):
        super().__init__(api)
        self.name = name
        self.lrouter = lrouter
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):

        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)
        try:
            idlutils.row_by_value(self.api.idl, 'Logical_Router_Port',
                                  'name', self.name)
            if self.may_exist:
                return
            # The LRP entry with certain name has already exist, raise an
            # exception to notice caller. It's caller's responsibility to
            # call UpdateLRouterPortCommand to get LRP entry processed
            # correctly.
            msg = _("Logical Router Port with name \"%s\" "
                    "already exists.") % self.name
            raise RuntimeError(msg)
        except idlutils.RowNotFound:
            lrouter_port = txn.insert(self.api._tables['Logical_Router_Port'])
            lrouter_port.name = self.name
            for col, val in self.columns.items():
                if col == 'gateway_chassis':
                    col, val = _add_gateway_chassis(self.api, txn, self.name,
                                                    val)
                self.set_column(lrouter_port, col, val)
            _addvalue_to_list(lrouter, 'ports', lrouter_port)
            self.result = lrouter_port.uuid


class UpdateLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists, **columns):
        super().__init__(api)
        self.name = name
        self.columns = columns
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter_port = idlutils.row_by_value(self.api.idl,
                                                 'Logical_Router_Port',
                                                 'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router Port %s does not exist") % self.name
            raise RuntimeError(msg)

        for col, val in self.columns.items():
            if col == 'gateway_chassis':
                col, val = _add_gateway_chassis(self.api, txn, self.name,
                                                val)
            self.set_column(lrouter_port, col, val)


class DelLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, lrouter, if_exists):
        super().__init__(api)
        self.name = name
        self.lrouter = lrouter
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter_port = idlutils.row_by_value(self.api.idl,
                                                 'Logical_Router_Port',
                                                 'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router Port %s does not exist") % self.name
            raise RuntimeError(msg)
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        _delvalue_from_list(lrouter, 'ports', lrouter_port)
        lrouter_port.delete()


class SetLRouterPortInLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lswitch_port, lrouter_port, is_gw_port,
                 if_exists, lsp_address):
        super().__init__(api)
        self.lswitch_port = lswitch_port
        self.lrouter_port = lrouter_port
        self.is_gw_port = is_gw_port
        self.if_exists = if_exists
        self.lsp_address = lsp_address

    def run_idl(self, txn):
        try:
            port = idlutils.row_by_value(self.api.idl, 'Logical_Switch_Port',
                                         'name', self.lswitch_port)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch Port %s does not "
                    "exist") % self.lswitch_port
            raise RuntimeError(msg)

        options = {'router-port': self.lrouter_port}
        if self.is_gw_port:
            options[ovn_const.OVN_GATEWAY_NAT_ADDRESSES_KEY] = 'router'
            options[ovn_const.OVN_ROUTER_PORT_EXCLUDE_LB_VIPS_GARP] = 'true'
        setattr(port, 'options', options)
        setattr(port, 'type', 'router')
        setattr(port, 'addresses', self.lsp_address)


class SetLRouterMacAgeLimitCommand(command.BaseCommand):
    def __init__(self, api, router, threshold):
        super().__init__(api)
        self.router = router
        self.threshold = str(threshold)  # Just in case an integer sneaks in

    def run_idl(self, txn):
        # Creating a Command object that iterates over the list of Routers
        # from inside a transaction avoids the issue of doing two
        # transactions: one for list_rows() and the other for setting the
        # values on routers, which would allow routers to be added and removed
        # between the two transactions.
        if self.router is None:
            routers = self.api.tables["Logical_Router"].rows.values()
        else:
            routers = [self.api.lookup("Logical_Router", self.router)]

        for router in routers:
            # It's not technically necessary to check the value before setting
            # it as python-ovs is smart enough to avoid sending operations to
            # the server that would result in no change. The overhead of
            # setkey() though is > than the overhead of checking the value here
            try:
                if (router.options.get(ovn_const.LR_OPTIONS_MAC_AGE_LIMIT) ==
                        self.threshold):
                    continue
            except AttributeError:
                # The Logical_Router is newly created in this txn and has no
                # "options" set yet, which the following setkey will rectify
                pass
            router.setkey("options", ovn_const.LR_OPTIONS_MAC_AGE_LIMIT,
                          self.threshold)


class AddACLCommand(command.BaseCommand):
    def __init__(self, api, lswitch, lport, **columns):
        super().__init__(api)
        self.lswitch = lswitch
        self.lport = lport
        self.columns = columns

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)

        row = txn.insert(self.api._tables['ACL'])
        for col, val in self.columns.items():
            setattr(row, col, val)
        _addvalue_to_list(lswitch, 'acls', row.uuid)


class DelACLCommand(command.BaseCommand):
    def __init__(self, api, lswitch, lport, if_exists):
        super().__init__(api)
        self.lswitch = lswitch
        self.lport = lport
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)

        acls_to_del = []
        acls = getattr(lswitch, 'acls', [])
        for acl in acls:
            ext_ids = getattr(acl, 'external_ids', {})
            if ext_ids.get('neutron:lport') == self.lport:
                acls_to_del.append(acl)
        for acl in acls_to_del:
            acl.delete()
        _updatevalues_in_list(lswitch, 'acls', old_values=acls_to_del)


class AddStaticRouteCommand(command.BaseCommand):
    def __init__(self, api, lrouter, maintain_bfd=False, **columns):
        super().__init__(api)
        self.lrouter = lrouter
        self.maintain_bfd = maintain_bfd
        self.columns = columns

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        bfd_uuid = None
        if (self.maintain_bfd and
                'nexthop' in self.columns and
                'output_port' in self.columns):
            cmd = ovn_nb_commands.BFDAddCommand(self.api,
                                                self.columns['output_port'],
                                                self.columns['nexthop'],
                                                may_exist=True)
            cmd.run_idl(txn)
            try:
                bfd_uuid = cmd.result.uuid
            except AttributeError:
                # When the BFD record is created in the same transaction the
                # post commit code that would resolve the real UUID and look up
                # the bfd record has not run yet, and consequently the object
                # returned by BFDAddCommand() is an UUID object.
                bfd_uuid = cmd.result

        row = txn.insert(self.api._tables['Logical_Router_Static_Route'])
        for col, val in self.columns.items():
            setattr(row, col, val)
        if bfd_uuid:
            setattr(row, 'bfd', bfd_uuid)
        _addvalue_to_list(lrouter, 'static_routes', row.uuid)


class DelStaticRoutesCommand(command.BaseCommand):
    def __init__(self, api, lrouter, routes, if_exists):
        super().__init__(api)
        self.lrouter = lrouter
        self.routes = routes
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        routes_to_be_deleted = []
        for route in getattr(lrouter, 'static_routes', []):
            route_tuple = (getattr(route, 'ip_prefix', ''),
                           getattr(route, 'nexthop', ''))
            if route_tuple in self.routes:
                routes_to_be_deleted.append(route)

        for route in routes_to_be_deleted:
            _delvalue_from_list(lrouter, 'static_routes', route)
            route.delete()


class SetStaticRouteCommand(command.BaseCommand):
    def __init__(self, api, sroute, **columns):
        super().__init__(api)
        self.sroute = sroute
        self.columns = columns

    def run_idl(self, txn):
        try:
            for col, val in self.columns.items():
                setattr(self.sroute, col, val)

        except idlutils.RowNotFound:
            msg = (_('Logical Router Static Route %s does not exist')
                   % self.sroute)
            raise RuntimeError(msg)


class UpdateObjectExtIdsCommand(command.BaseCommand, metaclass=abc.ABCMeta):
    table: str
    field = 'name'

    def __init__(self, api, record, external_ids, if_exists):
        super().__init__(api)
        self.record = record
        self.external_ids = external_ids
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            # api.lookup() would be better as it doesn't rely on hardcoded col
            obj = idlutils.row_by_value(self.api.idl, self.table, self.field,
                                        self.record)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            raise RuntimeError(
                _("%(table)s %(record)s does not exist. "
                  "Cannot update external IDs") %
                  {'table': self.table, 'record': self.record})

        for ext_id_key, ext_id_value in self.external_ids.items():
            obj.setkey('external_ids', ext_id_key, ext_id_value)


class UpdateChassisExtIdsCommand(UpdateObjectExtIdsCommand):
    table = 'Chassis'


class UpdatePortBindingExtIdsCommand(UpdateObjectExtIdsCommand):
    table = 'Port_Binding'
    field = 'logical_port'


class UpdateLbExternalIds(UpdateObjectExtIdsCommand):
    table = 'Load_Balancer'


class AddDHCPOptionsCommand(command.BaseCommand):
    def __init__(self, api, subnet_id, port_id=None, may_exist=True,
                 **columns):
        super().__init__(api)
        self.columns = columns
        self.may_exist = may_exist
        self.subnet_id = subnet_id
        self.port_id = port_id
        self.new_insert = False

    def _get_dhcp_options_row(self):
        for row in self.api._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            port_id = external_ids.get('port_id')
            if self.subnet_id == external_ids.get('subnet_id'):
                if self.port_id == port_id:
                    return row

    def run_idl(self, txn):
        row = None
        if self.may_exist:
            row = self._get_dhcp_options_row()

        if not row:
            row = txn.insert(self.api._tables['DHCP_Options'])
            self.new_insert = True
        for col, val in self.columns.items():
            setattr(row, col, val)
        self.result = row.uuid

    def post_commit(self, txn):
        # Update the result with inserted uuid for new inserted row, or the
        # uuid get in run_idl should be real uuid already.
        if self.new_insert:
            self.result = txn.get_insert_uuid(self.result)


class DelDHCPOptionsCommand(command.BaseCommand):
    def __init__(self, api, row_uuid, if_exists=True):
        super().__init__(api)
        self.if_exists = if_exists
        self.row_uuid = row_uuid

    def run_idl(self, txn):
        if self.row_uuid not in self.api._tables['DHCP_Options'].rows:
            if self.if_exists:
                return
            msg = _("DHCP Options row %s does not exist") % self.row_uuid
            raise RuntimeError(msg)

        self.api._tables['DHCP_Options'].rows[self.row_uuid].delete()


class AddNATRuleInLRouterCommand(command.BaseCommand):
    # TODO(chandrav): Add unit tests, bug #1638715.
    def __init__(self, api, lrouter, **columns):
        super().__init__(api)
        self.lrouter = lrouter
        self.columns = columns

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        row = txn.insert(self.api._tables['NAT'])
        for col, val in self.columns.items():
            setattr(row, col, val)
        lrouter.addvalue('nat', row.uuid)


class DeleteNATRuleInLRouterCommand(command.BaseCommand):
    # TODO(chandrav): Add unit tests, bug #1638715.
    def __init__(self, api, lrouter, type, logical_ip, external_ip,
                 if_exists):
        super().__init__(api)
        self.lrouter = lrouter
        self.type = type
        self.logical_ip = logical_ip
        self.external_ip = external_ip
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        for nat in lrouter.nat:
            if (self.type == nat.type and
                    self.external_ip == nat.external_ip and
                    self.logical_ip == nat.logical_ip):
                lrouter.delvalue('nat', nat)
                nat.delete()
                break


class SetNATRuleInLRouterCommand(command.BaseCommand):
    def __init__(self, api, lrouter, nat_rule_uuid, **columns):
        super().__init__(api)
        self.lrouter = lrouter
        self.nat_rule_uuid = nat_rule_uuid
        self.columns = columns

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        for nat_rule in lrouter.nat:
            if nat_rule.uuid == self.nat_rule_uuid:
                for col, val in self.columns.items():
                    setattr(nat_rule, col, val)
                break


class CheckRevisionNumberCommand(command.BaseCommand):

    def __init__(self, api, name, resource, resource_type, if_exists):
        super().__init__(api)
        self.name = name
        self.resource = resource
        self.resource_type = resource_type
        self.if_exists = if_exists

    def _get_floatingip_or_pf(self):
        # TYPE_FLOATINGIPS: Determine table to use based on name.
        # Floating ip port forwarding resources are kept in load
        # balancer table and have a well known name.
        if self.name.startswith(PORT_FORWARDING_PREFIX):
            return self.api.lookup('Load_Balancer', self.name)

        # TODO(lucasagomes): We can't use self.api.lookup() because that
        # method does not introspect map type columns. We could either:
        # 1. Enhance it to look into maps or, 2. Add a new ``name`` column
        # to the NAT table so that we can use lookup() just like we do
        # for other resources
        for nat in self.api._tables['NAT'].rows.values():
            if nat.type != 'dnat_and_snat':
                continue
            ext_ids = getattr(nat, 'external_ids', {})
            if ext_ids.get(ovn_const.OVN_FIP_EXT_ID_KEY) == self.name:
                return nat

        raise idlutils.RowNotFound(
            table='NAT', col='external_ids', match=self.name)

    def _get_subnet(self):
        for dhcp in self.api._tables['DHCP_Options'].rows.values():
            ext_ids = getattr(dhcp, 'external_ids', {})
            # Ignore ports DHCP Options
            if ext_ids.get('port_id'):
                continue
            if ext_ids.get('subnet_id') == self.name:
                return dhcp

        raise idlutils.RowNotFound(
            table='DHCP_Options', col='external_ids', match=self.name)

    def run_idl(self, txn):
        try:
            ovn_table = RESOURCE_TYPE_MAP[self.resource_type]
            ovn_resource = None
            if self.resource_type == ovn_const.TYPE_FLOATINGIPS:
                ovn_resource = self._get_floatingip_or_pf()
            elif self.resource_type == ovn_const.TYPE_SUBNETS:
                ovn_resource = self._get_subnet()
            else:
                ovn_resource = self.api.lookup(ovn_table, self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = (_('Failed to check the revision number for %s: Resource '
                     'does not exist') % self.name)
            raise RuntimeError(msg)

        external_ids = getattr(ovn_resource, 'external_ids', {})
        ovn_revision = int(external_ids.get(
            ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
        neutron_revision = utils.get_revision_number(self.resource,
                                                     self.resource_type)
        if ovn_revision > neutron_revision:
            raise ovn_exc.RevisionConflict(
                resource_id=self.name, resource_type=self.resource_type)

        ovn_resource.verify('external_ids')
        ovn_resource.setkey('external_ids', ovn_const.OVN_REV_NUM_EXT_ID_KEY,
                            str(neutron_revision))

    def post_commit(self, txn):
        self.result = ovn_const.TXN_COMMITTED


class DeleteLRouterExtGwCommand(command.BaseCommand):

    def __init__(self, api, lrouter, if_exists, maintain_bfd=True):
        super().__init__(api)
        self.lrouter = lrouter
        self.if_exists = if_exists
        self.maintain_bfd = maintain_bfd

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        if self.maintain_bfd:
            lrp_names = set()
            for lrp in getattr(lrouter, 'ports', []):
                lrp_names.add(lrp.name)
        for route in lrouter.static_routes:
            external_ids = getattr(route, 'external_ids', {})
            if ovn_const.OVN_ROUTER_IS_EXT_GW in external_ids:
                bfd = getattr(route, 'bfd', [])
                if bfd and self.maintain_bfd:
                    for bfd_rec in bfd:
                        bfd_logical_port = getattr(bfd_rec, 'logical_port', '')
                        if bfd_logical_port in lrp_names:
                            route.delvalue('bfd', bfd_rec)
                            bfd_rec.delete()
                lrouter.delvalue('static_routes', route)
                route.delete()

        for nat in lrouter.nat:
            if nat.type != 'snat':
                continue
            lrouter.delvalue('nat', nat)
            nat.delete()

        # Remove the router pinning to a chassis (if any).
        lrouter.delkey('options', 'chassis')

        # Remove the HA_Chassis_Group of the router (if any).
        hcg = self.api.lookup('HA_Chassis_Group',
                              lrouter.name, default=None)
        if hcg:
            hcg.delete()

        for gw_port in self.api.get_lrouter_gw_ports(lrouter.name):
            lrouter.delvalue('ports', gw_port)


class SetLSwitchPortToVirtualTypeCommand(command.BaseCommand):
    def __init__(self, api, lport, vip, parent, if_exists):
        super().__init__(api)
        self.lport = lport
        self.vip = vip
        self.parent = parent
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lsp = idlutils.row_by_value(self.api.idl, 'Logical_Switch_Port',
                                        'name', self.lport)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        options = lsp.options
        options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY] = self.vip
        virtual_parents = options.get(
            ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY, set())
        if virtual_parents:
            virtual_parents = set(virtual_parents.split(','))

        virtual_parents.add(self.parent)
        options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY] = ','.join(
            virtual_parents)
        setattr(lsp, 'options', options)
        setattr(lsp, 'type', ovn_const.LSP_TYPE_VIRTUAL)


class UnsetLSwitchPortToVirtualTypeCommand(command.BaseCommand):
    def __init__(self, api, lport, parent, if_exists):
        super().__init__(api)
        self.lport = lport
        self.parent = parent
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lsp = idlutils.row_by_value(self.api.idl, 'Logical_Switch_Port',
                                        'name', self.lport)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        options = lsp.options
        virtual_parents = options.get(
            ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY, set())
        if virtual_parents:
            virtual_parents = set(virtual_parents.split(','))

        try:
            virtual_parents.remove(self.parent)
        except KeyError:
            pass

        # If virtual-parents is now empty, change the type and remove the
        # virtual-parents and virtual-ip options
        if not virtual_parents:
            options.pop(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY, None)
            options.pop(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY, None)
            setattr(lsp, 'type', '')
        else:
            options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY] = ','.join(
                virtual_parents)

        setattr(lsp, 'options', options)


class HAChassisGroupWithHCAddCommand(command.AddCommand):
    table_name = 'HA_Chassis_Group'

    def __init__(self, api, name, chassis_priority, may_exist=False,
                 **columns):
        super().__init__(api)
        self.name = name
        self.chassis_priority = copy.deepcopy(chassis_priority)
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):
        # HA_Chassis_Group register creation.
        self.result = _sync_ha_chassis_group(
            txn, self.api, self.name, self.chassis_priority,
            may_exist=self.may_exist, table_name=self.table_name,
            **self.columns)
