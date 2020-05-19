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

from oslo_utils import timeutils
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import idlutils

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils

RESOURCE_TYPE_MAP = {
    ovn_const.TYPE_NETWORKS: 'Logical_Switch',
    ovn_const.TYPE_PORTS: 'Logical_Switch_Port',
    ovn_const.TYPE_ROUTERS: 'Logical_Router',
    ovn_const.TYPE_ROUTER_PORTS: 'Logical_Router_Port',
    ovn_const.TYPE_FLOATINGIPS: 'NAT',
    ovn_const.TYPE_SUBNETS: 'DHCP_Options',
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
    if gateway_chassis:
        prio = len(val)
        uuid_list = []
        for chassis in val:
            gwc_name = '%s_%s' % (lrp_name, chassis)
            try:
                gwc = idlutils.row_by_value(api.idl,
                                            'Gateway_Chassis',
                                            'name', gwc_name)
            except idlutils.RowNotFound:
                gwc = txn.insert(gateway_chassis)
                gwc.name = gwc_name
            gwc.chassis_name = chassis
            gwc.priority = prio
            prio = prio - 1
            uuid_list.append(gwc.uuid)
        return 'gateway_chassis', uuid_list
    else:
        chassis = {ovn_const.OVN_GATEWAY_CHASSIS_KEY: val[0]}
        return 'options', chassis


class CheckLivenessCommand(command.BaseCommand):
    def __init__(self, api):
        super(CheckLivenessCommand, self).__init__(api)

    def run_idl(self, txn):
        # txn.pre_commit responsible for updating nb_global.nb_cfg, but
        # python-ovs will not update nb_cfg if no other changes are made
        self.api.nb_global.setkey('external_ids',
                                  ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY,
                                  str(timeutils.utcnow(with_timezone=True)))
        self.result = self.api.nb_global.nb_cfg


class AddLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, lswitch, may_exist, **columns):
        super(AddLSwitchPortCommand, self).__init__(api)
        self.lport = lport
        self.lswitch = lswitch
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)
        if self.may_exist:
            port = idlutils.row_by_value(self.api.idl,
                                         'Logical_Switch_Port', 'name',
                                         self.lport, None)
            if port:
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
        for col, val in self.columns.items():
            setattr(port, col, val)
        # add the newly created port to existing lswitch
        _addvalue_to_list(lswitch, 'ports', port.uuid)
        self.result = port.uuid

    def post_commit(self, txn):
        self.result = txn.get_insert_uuid(self.result)


class SetLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, if_exists, **columns):
        super(SetLSwitchPortCommand, self).__init__(api)
        self.lport = lport
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
        for uuid in cur_port_dhcp_opts - new_port_dhcp_opts:
            self.api._tables['DHCP_Options'].rows[uuid].delete()

        for col, val in self.columns.items():
            setattr(port, col, val)


class DelLSwitchPortCommand(command.BaseCommand):
    def __init__(self, api, lport, lswitch, if_exists):
        super(DelLSwitchPortCommand, self).__init__(api)
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
        for uuid in cur_port_dhcp_opts:
            self.api._tables['DHCP_Options'].rows[uuid].delete()

        _delvalue_from_list(lswitch, 'ports', lport)
        self.api._tables['Logical_Switch_Port'].rows[lport.uuid].delete()


class AddLRouterCommand(command.BaseCommand):
    def __init__(self, api, name, may_exist, **columns):
        super(AddLRouterCommand, self).__init__(api)
        self.name = name
        self.columns = columns
        self.may_exist = may_exist

    def run_idl(self, txn):
        if self.may_exist:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name, None)
            if lrouter:
                return

        row = txn.insert(self.api._tables['Logical_Router'])
        row.name = self.name
        for col, val in self.columns.items():
            setattr(row, col, val)


class UpdateLRouterCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists, **columns):
        super(UpdateLRouterCommand, self).__init__(api)
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


class DelLRouterCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists):
        super(DelLRouterCommand, self).__init__(api)
        self.name = name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.name
            raise RuntimeError(msg)

        self.api._tables['Logical_Router'].rows[lrouter.uuid].delete()


class AddLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, lrouter, may_exist, **columns):
        super(AddLRouterPortCommand, self).__init__(api)
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
                setattr(lrouter_port, col, val)
            _addvalue_to_list(lrouter, 'ports', lrouter_port)


class UpdateLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists, **columns):
        super(UpdateLRouterPortCommand, self).__init__(api)
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

        # TODO(lucasagomes): Remove this check once we drop the support
        # for OVS versions <= 2.8
        ipv6_ra_configs_supported = self.api.is_col_present(
            'Logical_Router_Port', 'ipv6_ra_configs')
        for col, val in self.columns.items():
            if col == 'ipv6_ra_configs' and not ipv6_ra_configs_supported:
                continue

            if col == 'gateway_chassis':
                col, val = _add_gateway_chassis(self.api, txn, self.name,
                                                val)
            setattr(lrouter_port, col, val)


class DelLRouterPortCommand(command.BaseCommand):
    def __init__(self, api, name, lrouter, if_exists):
        super(DelLRouterPortCommand, self).__init__(api)
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
        super(SetLRouterPortInLSwitchPortCommand, self).__init__(api)
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
        setattr(port, 'options', options)
        setattr(port, 'type', 'router')
        setattr(port, 'addresses', self.lsp_address)


class AddACLCommand(command.BaseCommand):
    def __init__(self, api, lswitch, lport, **columns):
        super(AddACLCommand, self).__init__(api)
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
        super(DelACLCommand, self).__init__(api)
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


class UpdateACLsCommand(command.BaseCommand):
    def __init__(self, api, lswitch_names, port_list, acl_new_values_dict,
                 need_compare=True, is_add_acl=True):
        """This command updates the acl list for the logical switches

        @param lswitch_names: List of Logical Switch Names
        @type lswitch_names: []
        @param port_list: Iterator of List of Ports
        @type port_list: []
        @param acl_new_values_dict: Dictionary of acls indexed by port id
        @type acl_new_values_dict: {}
        @need_compare: If acl_new_values_dict needs be compared with existing
                       acls.
        @type: Boolean.
        @is_add_acl: If updating is caused by acl adding action.
        @type: Boolean.

        """
        super(UpdateACLsCommand, self).__init__(api)
        self.lswitch_names = lswitch_names
        self.port_list = port_list
        self.acl_new_values_dict = acl_new_values_dict
        self.need_compare = need_compare
        self.is_add_acl = is_add_acl

    def _acl_list_sub(self, acl_list1, acl_list2):
        """Compute the elements in acl_list1 but not in acl_list2.

        If acl_list1 and acl_list2 were sets, the result of this routine
        could be thought of as acl_list1 - acl_list2. Note that acl_list1
        and acl_list2 cannot actually be sets as they contain dictionary
        items i.e. set([{'a':1}) doesn't work.
        """
        acl_diff = []
        for acl in acl_list1:
            if acl not in acl_list2:
                acl_diff.append(acl)
        return acl_diff

    def _compute_acl_differences(self, port_list, acl_old_values_dict,
                                 acl_new_values_dict, acl_obj_dict):
        """Compute the difference between the new and old sets of acls

        @param port_list: Iterator of a List of ports
        @type port_list: []
        @param acl_old_values_dict: Dictionary of old acl values indexed
                                    by port id
        @param acl_new_values_dict: Dictionary of new acl values indexed
                                    by port id
        @param acl_obj_dict: Dictionary of acl objects indexed by the acl
                             value in string format.
        @var acl_del_objs_dict: Dictionary of acl objects to be deleted
                                indexed by the lswitch.
        @var acl_add_values_dict: Dictionary of acl values to be added
                                  indexed by the lswitch.
        @return: (acl_del_objs_dict, acl_add_values_dict)
        @rtype: ({}, {})
        """

        acl_del_objs_dict = {}
        acl_add_values_dict = {}
        for port in port_list:
            lswitch_name = port['network_id']
            acls_old = acl_old_values_dict.get(port['id'], [])
            acls_new = acl_new_values_dict.get(port['id'], [])
            acls_del = self._acl_list_sub(acls_old, acls_new)
            acls_add = self._acl_list_sub(acls_new, acls_old)
            acl_del_objs = acl_del_objs_dict.setdefault(lswitch_name, [])
            for acl in acls_del:
                acl_del_objs.append(acl_obj_dict[str(acl)])
            acl_add_values = acl_add_values_dict.setdefault(lswitch_name, [])
            for acl in acls_add:
                # Remove lport and lswitch columns
                del acl['lswitch']
                del acl['lport']
                acl_add_values.append(acl)
        return acl_del_objs_dict, acl_add_values_dict

    def _get_update_data_without_compare(self):
        lswitch_ovsdb_dict = {}
        for switch_name in self.lswitch_names:
            switch_name = utils.ovn_name(switch_name)
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', switch_name)
            lswitch_ovsdb_dict[switch_name] = lswitch
        if self.is_add_acl:
            acl_add_values_dict = {}
            for port in self.port_list:
                switch_name = utils.ovn_name(port['network_id'])
                if switch_name not in acl_add_values_dict:
                    acl_add_values_dict[switch_name] = []
                if port['id'] in self.acl_new_values_dict:
                    acl_add_values_dict[switch_name].append(
                        self.acl_new_values_dict[port['id']])
            acl_del_objs_dict = {}
        else:
            acl_add_values_dict = {}
            acl_del_objs_dict = {}
            del_acl_extids = []
            for acl_dict in self.acl_new_values_dict.values():
                del_acl_extids.append({acl_dict['match']:
                                       acl_dict['external_ids']})
            for switch_name, lswitch in lswitch_ovsdb_dict.items():
                if switch_name not in acl_del_objs_dict:
                    acl_del_objs_dict[switch_name] = []
                acls = getattr(lswitch, 'acls', [])
                for acl in acls:
                    match = getattr(acl, 'match')
                    acl_extids = {match: getattr(acl, 'external_ids')}
                    if acl_extids in del_acl_extids:
                        acl_del_objs_dict[switch_name].append(acl)
        return lswitch_ovsdb_dict, acl_del_objs_dict, acl_add_values_dict

    def run_idl(self, txn):

        if self.need_compare:
            # Get all relevant ACLs in 1 shot
            acl_values_dict, acl_obj_dict, lswitch_ovsdb_dict = (
                self.api.get_acls_for_lswitches(self.lswitch_names))

            # Compute the difference between the new and old set of ACLs
            acl_del_objs_dict, acl_add_values_dict = (
                self._compute_acl_differences(
                    self.port_list, acl_values_dict,
                    self.acl_new_values_dict, acl_obj_dict))
        else:
            lswitch_ovsdb_dict, acl_del_objs_dict, acl_add_values_dict = (
                self._get_update_data_without_compare())

        for lswitch_name, lswitch in lswitch_ovsdb_dict.items():
            acl_del_objs = acl_del_objs_dict.get(lswitch_name, [])
            acl_add_values = acl_add_values_dict.get(lswitch_name, [])

            # Continue if no ACLs to add or delete.
            if not acl_del_objs and not acl_add_values:
                continue

            # Delete old ACLs.
            if acl_del_objs:
                for acl_del_obj in acl_del_objs:
                    try:
                        acl_del_obj.delete()
                    except AssertionError:
                        # If we try to delete a row twice, just continue
                        pass

            # Add new ACLs.
            acl_add_objs = None
            if acl_add_values:
                acl_add_objs = []
                for acl_value in acl_add_values:
                    row = txn.insert(self.api._tables['ACL'])
                    for col, val in acl_value.items():
                        setattr(row, col, val)
                    acl_add_objs.append(row.uuid)

            # Update logical switch ACLs.
            _updatevalues_in_list(lswitch, 'acls',
                                  new_values=acl_add_objs,
                                  old_values=acl_del_objs)


class AddStaticRouteCommand(command.BaseCommand):
    def __init__(self, api, lrouter, **columns):
        super(AddStaticRouteCommand, self).__init__(api)
        self.lrouter = lrouter
        self.columns = columns

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        row = txn.insert(self.api._tables['Logical_Router_Static_Route'])
        for col, val in self.columns.items():
            setattr(row, col, val)
        _addvalue_to_list(lrouter, 'static_routes', row.uuid)


class DelStaticRouteCommand(command.BaseCommand):
    def __init__(self, api, lrouter, ip_prefix, nexthop, if_exists):
        super(DelStaticRouteCommand, self).__init__(api)
        self.lrouter = lrouter
        self.ip_prefix = ip_prefix
        self.nexthop = nexthop
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

        static_routes = getattr(lrouter, 'static_routes', [])
        for route in static_routes:
            ip_prefix = getattr(route, 'ip_prefix', '')
            nexthop = getattr(route, 'nexthop', '')
            if self.ip_prefix == ip_prefix and self.nexthop == nexthop:
                _delvalue_from_list(lrouter, 'static_routes', route)
                route.delete()
                break


class DelAddrSetCommand(command.BaseCommand):
    def __init__(self, api, name, if_exists):
        super(DelAddrSetCommand, self).__init__(api)
        self.name = name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            addrset = idlutils.row_by_value(self.api.idl, 'Address_Set',
                                            'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Address set %s does not exist. "
                    "Can't delete.") % self.name
            raise RuntimeError(msg)

        self.api._tables['Address_Set'].rows[addrset.uuid].delete()


class UpdateObjectExtIdsCommand(command.BaseCommand):
    table = None
    field = 'name'

    def __init__(self, api, record, external_ids, if_exists):
        super(UpdateObjectExtIdsCommand, self).__init__(api)
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
            msg = _("%(tbl)s %(rec)s does not exist. "
                    "Can't update external IDs") % {
                'tbl': self.table, 'rec': self.record}
            raise RuntimeError(msg)

        for ext_id_key, ext_id_value in self.external_ids.items():
            obj.setkey('external_ids', ext_id_key, ext_id_value)


class UpdateChassisExtIdsCommand(UpdateObjectExtIdsCommand):
    table = 'Chassis'


class UpdatePortBindingExtIdsCommand(UpdateObjectExtIdsCommand):
    table = 'Port_Binding'
    field = 'logical_port'


class AddDHCPOptionsCommand(command.BaseCommand):
    def __init__(self, api, subnet_id, port_id=None, may_exist=True,
                 **columns):
        super(AddDHCPOptionsCommand, self).__init__(api)
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
        super(DelDHCPOptionsCommand, self).__init__(api)
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
        super(AddNATRuleInLRouterCommand, self).__init__(api)
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
        super(DeleteNATRuleInLRouterCommand, self).__init__(api)
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
        super(SetNATRuleInLRouterCommand, self).__init__(api)
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
        super(CheckRevisionNumberCommand, self).__init__(api)
        self.name = name
        self.resource = resource
        self.resource_type = resource_type
        self.if_exists = if_exists

    def _get_floatingip(self):
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
            # TODO(lucasagomes): After OVS 2.8.2 is released all tables should
            # have the external_ids column. We can remove this conditional
            # here by then.
            if not self.api.is_col_present(ovn_table, 'external_ids'):
                return

            ovn_resource = None
            if self.resource_type == ovn_const.TYPE_FLOATINGIPS:
                ovn_resource = self._get_floatingip()
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

    def __init__(self, api, lrouter, if_exists):
        super(DeleteLRouterExtGwCommand, self).__init__(api)
        self.lrouter = lrouter
        self.if_exists = if_exists

    def run_idl(self, txn):
        # TODO(lucasagomes): Remove this check after OVS 2.8.2 is tagged
        # (prior to that, the external_ids column didn't exist in this
        # table).
        if not self.api.is_col_present('Logical_Router_Static_Route',
                                       'external_ids'):
            return

        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.lrouter
            raise RuntimeError(msg)

        for route in lrouter.static_routes:
            external_ids = getattr(route, 'external_ids', {})
            if ovn_const.OVN_ROUTER_IS_EXT_GW in external_ids:
                lrouter.delvalue('static_routes', route)
                route.delete()
                break

        for nat in lrouter.nat:
            if nat.type != 'snat':
                continue
            lrouter.delvalue('nat', nat)
            nat.delete()

        lrouter_ext_ids = getattr(lrouter, 'external_ids', {})
        gw_port_id = lrouter_ext_ids.get(ovn_const.OVN_GW_PORT_EXT_ID_KEY)
        if not gw_port_id:
            return

        try:
            lrouter_port = idlutils.row_by_value(
                self.api.idl, 'Logical_Router_Port', 'name',
                utils.ovn_lrouter_port_name(gw_port_id))
        except idlutils.RowNotFound:
            return

        lrouter.delvalue('ports', lrouter_port)


class SetLSwitchPortToVirtualTypeCommand(command.BaseCommand):
    def __init__(self, api, lport, vip, parent, if_exists):
        super(SetLSwitchPortToVirtualTypeCommand, self).__init__(api)
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
            msg = "Logical Switch Port %s does not exist" % self.lport
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
        super(UnsetLSwitchPortToVirtualTypeCommand, self).__init__(api)
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
            msg = "Logical Switch Port %s does not exist" % self.lport
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
