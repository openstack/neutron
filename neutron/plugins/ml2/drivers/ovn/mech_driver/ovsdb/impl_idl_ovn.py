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

import contextlib
import functools
import socket
import uuid

from neutron_lib import exceptions as n_exc
from neutron_lib.utils import helpers
from oslo_log import log
from oslo_utils import uuidutils
from ovs import socket_util
from ovs import stream
from ovsdbapp.backend import ovs_idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.backend.ovs_idl import transaction as idl_trans
from ovsdbapp.backend.ovs_idl import vlog
from ovsdbapp.schema.ovn_northbound import impl_idl as nb_impl_idl
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl
import tenacity

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as cfg
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import commands as cmd
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker


LOG = log.getLogger(__name__)


# Override wait_for_change to not use a timeout so we always try to reconnect
def wait_for_change(idl_, timeout, seqno=None):
    if seqno is None:
        seqno = idl_.change_seqno
        while idl_.change_seqno == seqno and not idl_.run():
            poller = idlutils.poller.Poller()
            idl_.wait(poller)
            poller.block()


idlutils.wait_for_change = wait_for_change


class OvnNbTransaction(idl_trans.Transaction):

    def __init__(self, *args, **kwargs):
        # NOTE(lucasagomes): The bump_nb_cfg parameter is only used by
        # the agents health status check
        self.bump_nb_cfg = kwargs.pop('bump_nb_cfg', False)
        super(OvnNbTransaction, self).__init__(*args, **kwargs)

    def pre_commit(self, txn):
        if not self.bump_nb_cfg:
            return
        self.api.nb_global.increment('nb_cfg')


def add_keepalives(fn):
    @functools.wraps(fn)
    def _open(*args, **kwargs):
        error, sock = fn(*args, **kwargs)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except socket.error as e:
            sock.close()
            return socket_util.get_exception_errno(e), None
        return error, sock
    return _open


class NoProbesMixin(object):
    @staticmethod
    def needs_probes():
        # If we are using keepalives, we can force probe_interval=0
        return False


class TCPStream(stream.TCPStream, NoProbesMixin):
    @classmethod
    @add_keepalives
    def _open(cls, suffix, dscp):
        return super()._open(suffix, dscp)


class SSLStream(stream.SSLStream, NoProbesMixin):
    @classmethod
    @add_keepalives
    def _open(cls, suffix, dscp):
        return super()._open(suffix, dscp)


# Overwriting globals in a library is clearly a good idea
stream.Stream.register_method("tcp", TCPStream)
stream.Stream.register_method("ssl", SSLStream)


# This version of Backend doesn't use a class variable for ovsdb_connection
# and therefor allows networking-ovn to manage connection scope on its own
class Backend(ovs_idl.Backend):
    lookup_table = {}
    ovsdb_connection = None

    def __init__(self, connection):
        self.ovsdb_connection = connection
        super(Backend, self).__init__(connection)

    def start_connection(self, connection):
        try:
            self.ovsdb_connection.start()
        except Exception as e:
            connection_exception = OvsdbConnectionUnavailable(
                db_schema=self.schema, error=e)
            LOG.exception(connection_exception)
            raise connection_exception

    @property
    def idl(self):
        return self.ovsdb_connection.idl

    @property
    def tables(self):
        return self.idl.tables

    _tables = tables

    def is_table_present(self, table_name):
        return table_name in self._tables

    def is_col_present(self, table_name, col_name):
        return self.is_table_present(table_name) and (
            col_name in self._tables[table_name].columns)

    def create_transaction(self, check_error=False, log_errors=True):
        return idl_trans.Transaction(
            self, self.ovsdb_connection, self.ovsdb_connection.timeout,
            check_error, log_errors)

    # Check for a column match in the table. If not found do a retry with
    # a stop delay of 10 secs. This function would be useful if the caller
    # wants to verify for the presence of a particular row in the table
    # with the column match before doing any transaction.
    # Eg. We can check if Logical_Switch row is present before adding a
    # logical switch port to it.
    @tenacity.retry(retry=tenacity.retry_if_exception_type(RuntimeError),
                    wait=tenacity.wait_exponential(),
                    stop=tenacity.stop_after_delay(10),
                    reraise=True)
    def check_for_row_by_value_and_retry(self, table, column, match):
        try:
            idlutils.row_by_value(self.idl, table, column, match)
        except idlutils.RowNotFound:
            msg = (_("%(match)s does not exist in %(column)s of %(table)s")
                   % {'match': match, 'column': column, 'table': table})
            raise RuntimeError(msg)


class OvsdbConnectionUnavailable(n_exc.ServiceUnavailable):
    message = _("OVS database connection to %(db_schema)s failed with error: "
                "'%(error)s'. Verify that the OVS and OVN services are "
                "available and that the 'ovn_nb_connection' and "
                "'ovn_sb_connection' configuration options are correct.")


# Retry forever to get the OVN NB and SB IDLs. Wait 2^x * 1 seconds between
# each retry, up to 'max_interval' seconds, then interval will be fixed
# to 'max_interval' seconds afterwards. The default 'max_interval' is 180.
def get_ovn_idls(driver, trigger):
    @tenacity.retry(
        wait=tenacity.wait_exponential(
            max=cfg.get_ovn_ovsdb_retry_max_interval()),
        reraise=True)
    def get_ovn_idl_retry(api_cls):
        trigger_class = utils.get_method_class(trigger)
        LOG.info('Getting %(cls)s for %(trigger)s with retry',
                 {'cls': api_cls.__name__, 'trigger': trigger_class.__name__})
        return api_cls.from_worker(trigger_class, driver)

    vlog.use_python_logger(max_level=cfg.get_ovn_ovsdb_log_level())
    return tuple(get_ovn_idl_retry(c) for c in (OvsdbNbOvnIdl, OvsdbSbOvnIdl))


class OvsdbNbOvnIdl(nb_impl_idl.OvnNbApiIdlImpl, Backend):
    def __init__(self, connection):
        super(OvsdbNbOvnIdl, self).__init__(connection)

    @classmethod
    def from_worker(cls, worker_class, driver=None):
        args = (cfg.get_ovn_nb_connection(), 'OVN_Northbound')
        if worker_class == worker.MaintenanceWorker:
            idl_ = ovsdb_monitor.BaseOvnIdl.from_server(*args)
        else:
            idl_ = ovsdb_monitor.OvnNbIdl.from_server(*args, driver=driver)
        conn = connection.Connection(idl_, timeout=cfg.get_ovn_ovsdb_timeout())
        return cls(conn)

    @property
    def nb_global(self):
        return next(iter(self.tables['NB_Global'].rows.values()))

    def create_transaction(self, check_error=False, log_errors=True,
                           bump_nb_cfg=False):
        return OvnNbTransaction(
            self, self.ovsdb_connection, self.ovsdb_connection.timeout,
            check_error, log_errors, bump_nb_cfg=bump_nb_cfg)

    @contextlib.contextmanager
    def transaction(self, *args, **kwargs):
        """A wrapper on the ovsdbapp transaction to work with revisions.

        This method is just a wrapper around the ovsdbapp transaction
        to handle revision conflicts correctly.
        """
        try:
            with super(OvsdbNbOvnIdl, self).transaction(*args, **kwargs) as t:
                yield t
        except ovn_exc.RevisionConflict as e:
            LOG.info('Transaction aborted. Reason: %s', e)

    def create_lswitch_port(self, lport_name, lswitch_name, may_exist=True,
                            **columns):
        return cmd.AddLSwitchPortCommand(self, lport_name, lswitch_name,
                                         may_exist, **columns)

    def set_lswitch_port(self, lport_name, if_exists=True, **columns):
        return cmd.SetLSwitchPortCommand(self, lport_name,
                                         if_exists, **columns)

    def delete_lswitch_port(self, lport_name=None, lswitch_name=None,
                            ext_id=None, if_exists=True):
        if lport_name is not None:
            return cmd.DelLSwitchPortCommand(self, lport_name,
                                             lswitch_name, if_exists)
        else:
            raise RuntimeError(_("Currently only supports "
                                 "delete by lport-name"))

    def get_all_logical_switches_with_ports(self):
        result = []
        for lswitch in self._tables['Logical_Switch'].rows.values():
            if ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY not in (
                    lswitch.external_ids):
                continue
            ports = []
            provnet_ports = []
            for lport in getattr(lswitch, 'ports', []):
                if ovn_const.OVN_PORT_NAME_EXT_ID_KEY in lport.external_ids:
                    ports.append(lport.name)
                # Handle provider network port
                elif lport.name.startswith(
                        ovn_const.OVN_PROVNET_PORT_NAME_PREFIX):
                    provnet_ports.append(lport.name)
            result.append({'name': lswitch.name,
                           'ports': ports,
                           'provnet_ports': provnet_ports})
        return result

    def get_all_logical_routers_with_rports(self):
        """Get logical Router ports associated with all logical Routers

        @return: list of dict, each dict has key-value:
                 - 'name': string router_id in neutron.
                 - 'static_routes': list of static routes dict.
                 - 'ports': dict of port_id in neutron (key) and networks on
                            port (value).
                 - 'snats': list of snats dict
                 - 'dnat_and_snats': list of dnat_and_snats dict
        """
        result = []
        for lrouter in self._tables['Logical_Router'].rows.values():
            if ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY not in (
                    lrouter.external_ids):
                continue
            lrports = {lrport.name.replace('lrp-', ''): lrport.networks
                       for lrport in getattr(lrouter, 'ports', [])}
            sroutes = [{'destination': sroute.ip_prefix,
                        'nexthop': sroute.nexthop}
                       for sroute in getattr(lrouter, 'static_routes', [])]

            dnat_and_snats = []
            snat = []
            for nat in getattr(lrouter, 'nat', []):
                columns = {'logical_ip': nat.logical_ip,
                           'external_ip': nat.external_ip,
                           'type': nat.type}
                if nat.type == 'dnat_and_snat':
                    if nat.external_mac:
                        columns['external_mac'] = nat.external_mac[0]
                    if nat.logical_port:
                        columns['logical_port'] = nat.logical_port[0]
                    dnat_and_snats.append(columns)
                elif nat.type == 'snat':
                    snat.append(columns)

            result.append({'name': lrouter.name.replace('neutron-', ''),
                           'static_routes': sroutes,
                           'ports': lrports,
                           'snats': snat,
                           'dnat_and_snats': dnat_and_snats})
        return result

    def get_acl_by_id(self, acl_id):
        try:
            return self.lookup('ACL', uuid.UUID(acl_id))
        except idlutils.RowNotFound:
            return

    def get_acls_for_lswitches(self, lswitch_names):
        """Get the existing set of acls that belong to the logical switches

        @param lswitch_names: List of logical switch names
        @type lswitch_names: []
        @var acl_values_dict: A dictionary indexed by port_id containing the
                              list of acl values in string format that belong
                              to that port
        @var acl_obj_dict: A dictionary indexed by acl value containing the
                           corresponding acl idl object.
        @var lswitch_ovsdb_dict: A dictionary mapping from logical switch
                                 name to lswitch idl object
        @return: (acl_values_dict, acl_obj_dict, lswitch_ovsdb_dict)
        """
        acl_values_dict = {}
        acl_obj_dict = {}
        lswitch_ovsdb_dict = {}
        for lswitch_name in lswitch_names:
            try:
                lswitch = idlutils.row_by_value(self.idl,
                                                'Logical_Switch',
                                                'name',
                                                utils.ovn_name(lswitch_name))
            except idlutils.RowNotFound:
                # It is possible for the logical switch to be deleted
                # while we are searching for it by name in idl.
                continue
            lswitch_ovsdb_dict[lswitch_name] = lswitch
            acls = getattr(lswitch, 'acls', [])

            # Iterate over each acl in a lswitch and store the acl in
            # a key:value representation for e.g. acl_string. This
            # key:value representation can invoke the code -
            # self._ovn.add_acl(**acl_string)
            for acl in acls:
                ext_ids = getattr(acl, 'external_ids', {})
                port_id = ext_ids.get('neutron:lport')
                acl_list = acl_values_dict.setdefault(port_id, [])
                acl_string = {'lport': port_id,
                              'lswitch': utils.ovn_name(lswitch_name)}
                for acl_key in getattr(acl, "_data", {}):
                    try:
                        acl_string[acl_key] = getattr(acl, acl_key)
                    except AttributeError:
                        pass
                acl_obj_dict[str(acl_string)] = acl
                acl_list.append(acl_string)
        return acl_values_dict, acl_obj_dict, lswitch_ovsdb_dict

    def create_lrouter(self, name, may_exist=True, **columns):
        return cmd.AddLRouterCommand(self, name,
                                     may_exist, **columns)

    def update_lrouter(self, name, if_exists=True, **columns):
        return cmd.UpdateLRouterCommand(self, name,
                                        if_exists, **columns)

    def delete_lrouter(self, name, if_exists=True):
        return cmd.DelLRouterCommand(self, name, if_exists)

    def add_lrouter_port(self, name, lrouter, may_exist=False, **columns):
        return cmd.AddLRouterPortCommand(self, name, lrouter,
                                         may_exist, **columns)

    def update_lrouter_port(self, name, if_exists=True, **columns):
        return cmd.UpdateLRouterPortCommand(self, name, if_exists, **columns)

    def delete_lrouter_port(self, name, lrouter, if_exists=True):
        return cmd.DelLRouterPortCommand(self, name, lrouter,
                                         if_exists)

    def set_lrouter_port_in_lswitch_port(
            self, lswitch_port, lrouter_port, is_gw_port=False, if_exists=True,
            lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER):
        return cmd.SetLRouterPortInLSwitchPortCommand(self, lswitch_port,
                                                      lrouter_port, is_gw_port,
                                                      if_exists,
                                                      lsp_address)

    def add_acl(self, lswitch, lport, **columns):
        return cmd.AddACLCommand(self, lswitch, lport, **columns)

    def delete_acl(self, lswitch, lport, if_exists=True):
        return cmd.DelACLCommand(self, lswitch, lport, if_exists)

    def update_acls(self, lswitch_names, port_list, acl_new_values_dict,
                    need_compare=True, is_add_acl=True):
        return cmd.UpdateACLsCommand(self, lswitch_names,
                                     port_list, acl_new_values_dict,
                                     need_compare=need_compare,
                                     is_add_acl=is_add_acl)

    def add_static_route(self, lrouter, **columns):
        return cmd.AddStaticRouteCommand(self, lrouter, **columns)

    def delete_static_route(self, lrouter, ip_prefix, nexthop, if_exists=True):
        return cmd.DelStaticRouteCommand(self, lrouter, ip_prefix, nexthop,
                                         if_exists)

    def delete_address_set(self, name, if_exists=True, **columns):
        return cmd.DelAddrSetCommand(self, name, if_exists)

    def _get_logical_router_port_gateway_chassis(self, lrp):
        """Get the list of chassis hosting this gateway port.

        @param   lrp: logical router port
        @type    lrp: Logical_Router_Port row
        @return: List of tuples (chassis_name, priority) sorted by priority
        """
        # Try retrieving gateway_chassis with new schema. If new schema is not
        # supported or user is using old schema, then use old schema for
        # getting gateway_chassis
        chassis = []
        if self._tables.get('Gateway_Chassis'):
            for gwc in lrp.gateway_chassis:
                chassis.append((gwc.chassis_name, gwc.priority))
        else:
            rc = lrp.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
            if rc:
                chassis.append((rc, 0))
        # make sure that chassis are sorted by priority
        return sorted(chassis, reverse=True, key=lambda x: x[1])

    def get_all_chassis_gateway_bindings(self,
                                         chassis_candidate_list=None):
        chassis_bindings = {}
        for chassis_name in chassis_candidate_list or []:
            chassis_bindings.setdefault(chassis_name, [])
        for lrp in self._tables['Logical_Router_Port'].rows.values():
            if not lrp.name.startswith('lrp-'):
                continue
            chassis = self._get_logical_router_port_gateway_chassis(lrp)
            for chassis_name, prio in chassis:
                if (not chassis_candidate_list or
                        chassis_name in chassis_candidate_list):
                    routers_hosted = chassis_bindings.setdefault(chassis_name,
                                                                 [])
                    routers_hosted.append((lrp.name, prio))
        return chassis_bindings

    def get_gateway_chassis_binding(self, gateway_name):
        try:
            lrp = idlutils.row_by_value(
                self.idl, 'Logical_Router_Port', 'name', gateway_name)
            chassis_list = self._get_logical_router_port_gateway_chassis(lrp)
            return [chassis for chassis, prio in chassis_list]
        except idlutils.RowNotFound:
            return []

    def get_chassis_gateways(self, chassis_name):
        gw_chassis = self.db_find_rows(
            'Gateway_Chassis', ('chassis_name', '=', chassis_name))
        return gw_chassis.execute(check_error=True)

    def get_unhosted_gateways(self, port_physnet_dict, chassis_with_physnets,
                              all_gw_chassis):
        unhosted_gateways = set()
        for port, physnet in port_physnet_dict.items():
            lrp_name = '%s%s' % (ovn_const.LRP_PREFIX, port)
            original_state = self.get_gateway_chassis_binding(lrp_name)

            # Filter out chassis that lost physnet, the cms option,
            # or has been deleted.
            actual_gw_chassis = [
                chassis for chassis in original_state
                if not utils.is_gateway_chassis_invalid(
                    chassis, all_gw_chassis, physnet, chassis_with_physnets)]

            # Check if gw ports are fully scheduled.
            if len(actual_gw_chassis) >= ovn_const.MAX_GW_CHASSIS:
                continue

            # If there are no gateways with 'enable-chassis-as-gw' cms option
            # then try to schedule on all gateways with physnets connected,
            # and filter required physnet.
            available_chassis = {
                c for c in all_gw_chassis or chassis_with_physnets.keys()
                if not utils.is_gateway_chassis_invalid(
                    c, all_gw_chassis, physnet, chassis_with_physnets)}

            if available_chassis == set(original_state):
                # The same situation as was before. Nothing
                # to be rescheduled.
                continue
            if not available_chassis:
                # There is no chassis that could host
                # this gateway.
                continue
            unhosted_gateways.add(lrp_name)
        return unhosted_gateways

    def add_dhcp_options(self, subnet_id, port_id=None, may_exist=True,
                         **columns):
        return cmd.AddDHCPOptionsCommand(self, subnet_id, port_id=port_id,
                                         may_exist=may_exist, **columns)

    def delete_dhcp_options(self, row_uuid, if_exists=True):
        return cmd.DelDHCPOptionsCommand(self, row_uuid, if_exists=if_exists)

    def _format_dhcp_row(self, row):
        ext_ids = dict(getattr(row, 'external_ids', {}))
        return {'cidr': row.cidr, 'options': dict(row.options),
                'external_ids': ext_ids, 'uuid': row.uuid}

    def get_subnet_dhcp_options(self, subnet_id, with_ports=False):
        subnet = None
        ports = []
        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            if subnet_id == external_ids.get('subnet_id'):
                port_id = external_ids.get('port_id')
                if with_ports and port_id:
                    ports.append(self._format_dhcp_row(row))
                elif not port_id:
                    subnet = self._format_dhcp_row(row)
                    if not with_ports:
                        break
        return {'subnet': subnet, 'ports': ports}

    def get_subnets_dhcp_options(self, subnet_ids):
        ret_opts = []
        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            if (external_ids.get('subnet_id') in subnet_ids and not
                    external_ids.get('port_id')):
                ret_opts.append(self._format_dhcp_row(row))
                if len(ret_opts) == len(subnet_ids):
                    break
        return ret_opts

    def get_all_dhcp_options(self):
        dhcp_options = {'subnets': {}, 'ports_v4': {}, 'ports_v6': {}}

        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            if not external_ids.get('subnet_id'):
                # This row is not created by OVN ML2 driver. Ignore it.
                continue

            if not external_ids.get('port_id'):
                dhcp_options['subnets'][external_ids['subnet_id']] = (
                    self._format_dhcp_row(row))
            else:
                port_dict = 'ports_v6' if ':' in row.cidr else 'ports_v4'
                dhcp_options[port_dict][external_ids['port_id']] = (
                    self._format_dhcp_row(row))

        return dhcp_options

    def get_address_sets(self):
        address_sets = {}
        for row in self._tables['Address_Set'].rows.values():
            # TODO(lucasagomes): Remove OVN_SG_NAME_EXT_ID_KEY in the
            # Rocky release
            if not (ovn_const.OVN_SG_EXT_ID_KEY in row.external_ids or
               ovn_const.OVN_SG_NAME_EXT_ID_KEY in row.external_ids):
                continue
            name = getattr(row, 'name')
            data = {}
            for row_key in getattr(row, "_data", {}):
                data[row_key] = getattr(row, row_key)
            address_sets[name] = data
        return address_sets

    def get_router_port_options(self, lsp_name):
        try:
            lsp = idlutils.row_by_value(self.idl, 'Logical_Switch_Port',
                                        'name', lsp_name)
            options = getattr(lsp, 'options')
            for key in list(options.keys()):
                if key not in ovn_const.OVN_ROUTER_PORT_OPTION_KEYS:
                    del(options[key])
            return options
        except idlutils.RowNotFound:
            return {}

    def add_nat_rule_in_lrouter(self, lrouter, **columns):
        return cmd.AddNATRuleInLRouterCommand(self, lrouter, **columns)

    def delete_nat_rule_in_lrouter(self, lrouter, type, logical_ip,
                                   external_ip, if_exists=True):
        return cmd.DeleteNATRuleInLRouterCommand(self, lrouter, type,
                                                 logical_ip, external_ip,
                                                 if_exists)

    def get_lrouter_nat_rules(self, lrouter_name):
        try:
            lrouter = idlutils.row_by_value(self.idl, 'Logical_Router',
                                            'name', lrouter_name)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % lrouter_name
            raise RuntimeError(msg)

        nat_rules = []
        for nat_rule in getattr(lrouter, 'nat', []):
            ext_ids = {}
            # TODO(dalvarez): remove this check once the minimum OVS required
            # version contains the column (when OVS 2.8.2 is released).
            if self.is_col_present('NAT', 'external_ids'):
                ext_ids = dict(getattr(nat_rule, 'external_ids', {}))

            nat_rules.append({'external_ip': nat_rule.external_ip,
                              'logical_ip': nat_rule.logical_ip,
                              'type': nat_rule.type,
                              'uuid': nat_rule.uuid,
                              'external_ids': ext_ids})
        return nat_rules

    def set_nat_rule_in_lrouter(self, lrouter, nat_rule_uuid, **columns):
        return cmd.SetNATRuleInLRouterCommand(self, lrouter, nat_rule_uuid,
                                              **columns)

    def get_lswitch_port(self, lsp_name):
        try:
            return self.lookup('Logical_Switch_Port', lsp_name)
        except idlutils.RowNotFound:
            return None

    def get_parent_port(self, lsp_name):
        lsp = self.get_lswitch_port(lsp_name)
        if not lsp:
            return ''
        return lsp.parent_name

    def get_lswitch(self, lswitch_name):
        # FIXME(lucasagomes): We should refactor those get_*()
        # methods. Some of 'em require the name, others IDs etc... It can
        # be confusing.
        if uuidutils.is_uuid_like(lswitch_name):
            lswitch_name = utils.ovn_name(lswitch_name)

        try:
            return self.lookup('Logical_Switch', lswitch_name)
        except idlutils.RowNotFound:
            return None

    def get_ls_and_dns_record(self, lswitch_name):
        ls = self.get_lswitch(lswitch_name)
        if not ls:
            return (None, None)

        if not hasattr(ls, 'dns_records'):
            return (ls, None)

        for dns_row in ls.dns_records:
            if dns_row.external_ids.get('ls_name') == lswitch_name:
                return (ls, dns_row)

        return (ls, None)

    def get_floatingip(self, fip_id):
        # TODO(dalvarez): remove this check once the minimum OVS required
        # version contains the column (when OVS 2.8.2 is released).
        if not self.is_col_present('NAT', 'external_ids'):
            return

        fip = self.db_find('NAT', ('external_ids', '=',
                                   {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}))
        result = fip.execute(check_error=True)
        return result[0] if result else None

    def get_floatingip_by_ips(self, router_id, logical_ip, external_ip):
        if not all([router_id, logical_ip, external_ip]):
            return

        for nat in self.get_lrouter_nat_rules(utils.ovn_name(router_id)):
            if (nat['type'] == 'dnat_and_snat' and
               nat['logical_ip'] == logical_ip and
               nat['external_ip'] == external_ip):
                return nat

    def check_revision_number(self, name, resource, resource_type,
                              if_exists=True):
        return cmd.CheckRevisionNumberCommand(
            self, name, resource, resource_type, if_exists)

    def get_lrouter(self, lrouter_name):
        if uuidutils.is_uuid_like(lrouter_name):
            lrouter_name = utils.ovn_name(lrouter_name)

        # TODO(lucasagomes): Use lr_get() once we start refactoring this
        # API to use methods from ovsdbapp.
        lr = self.db_find_rows('Logical_Router', ('name', '=', lrouter_name))
        result = lr.execute(check_error=True)
        return result[0] if result else None

    def get_lrouter_port(self, lrp_name):
        # TODO(mangelajo): Implement lrp_get() ovsdbapp and use from here
        if uuidutils.is_uuid_like(lrp_name):
            lrp_name = utils.ovn_lrouter_port_name(lrp_name)
        lrp = self.db_find_rows('Logical_Router_Port', ('name', '=', lrp_name))
        result = lrp.execute(check_error=True)
        return result[0] if result else None

    def delete_lrouter_ext_gw(self, lrouter_name, if_exists=True):
        return cmd.DeleteLRouterExtGwCommand(self, lrouter_name, if_exists)

    def get_port_group(self, pg_name):
        if uuidutils.is_uuid_like(pg_name):
            pg_name = utils.ovn_port_group_name(pg_name)
        try:
            for pg in self._tables['Port_Group'].rows.values():
                if pg.name == pg_name:
                    return pg
        except KeyError:
            # TODO(dalvarez): This except block is added for backwards compat
            # with old OVN schemas (<=2.9) where Port Groups are not present.
            # This (and other conditional code around this feature) shall be
            # removed at some point.
            return

    def get_port_groups(self):
        port_groups = {}
        try:
            for row in self._tables['Port_Group'].rows.values():
                name = getattr(row, 'name')
                if not (ovn_const.OVN_SG_EXT_ID_KEY in row.external_ids or
                   name == ovn_const.OVN_DROP_PORT_GROUP_NAME):
                    continue
                data = {}
                for row_key in getattr(row, "_data", {}):
                    data[row_key] = getattr(row, row_key)
                port_groups[name] = data
        except KeyError:
            # TODO(dalvarez): This except block is added for backwards compat
            # with old OVN schemas (<=2.9) where Port Groups are not present.
            # This (and other conditional code around this feature) shall be
            # removed at some point.
            pass
        return port_groups

    def check_liveness(self):
        return cmd.CheckLivenessCommand(self)

    def set_lswitch_port_to_virtual_type(self, lport_name, vip,
                                         virtual_parent, if_exists=True):
        return cmd.SetLSwitchPortToVirtualTypeCommand(
            self, lport_name, vip, virtual_parent, if_exists)

    def unset_lswitch_port_to_virtual_type(self, lport_name,
                                           virtual_parent, if_exists=True):
        return cmd.UnsetLSwitchPortToVirtualTypeCommand(
            self, lport_name, virtual_parent, if_exists)


class OvsdbSbOvnIdl(sb_impl_idl.OvnSbApiIdlImpl, Backend):
    def __init__(self, connection):
        super(OvsdbSbOvnIdl, self).__init__(connection)

    @classmethod
    def from_worker(cls, worker_class, driver=None):
        args = (cfg.get_ovn_sb_connection(), 'OVN_Southbound')
        if worker_class == worker.MaintenanceWorker:
            idl_ = ovsdb_monitor.BaseOvnSbIdl.from_server(*args)
        else:
            idl_ = ovsdb_monitor.OvnSbIdl.from_server(*args, driver=driver)
        conn = connection.Connection(idl_, timeout=cfg.get_ovn_ovsdb_timeout())
        return cls(conn)

    def _get_chassis_physnets(self, chassis):
        bridge_mappings = chassis.external_ids.get('ovn-bridge-mappings', '')
        mapping_dict = helpers.parse_mappings(bridge_mappings.split(','),
                                              unique_values=False)
        return list(mapping_dict.keys())

    def chassis_exists(self, hostname):
        cmd = self.db_find('Chassis', ('hostname', '=', hostname))
        return bool(cmd.execute(check_error=True))

    def get_chassis_hostname_and_physnets(self):
        chassis_info_dict = {}
        for ch in self.chassis_list().execute(check_error=True):
            chassis_info_dict[ch.hostname] = self._get_chassis_physnets(ch)
        return chassis_info_dict

    def get_gateway_chassis_from_cms_options(self):
        gw_chassis = []
        for ch in self.chassis_list().execute(check_error=True):
            cms_options = ch.external_ids.get('ovn-cms-options', '')
            if 'enable-chassis-as-gw' in cms_options.split(','):
                gw_chassis.append(ch.name)
        return gw_chassis

    def get_chassis_and_physnets(self):
        chassis_info_dict = {}
        for ch in self.chassis_list().execute(check_error=True):
            chassis_info_dict[ch.name] = self._get_chassis_physnets(ch)
        return chassis_info_dict

    def get_all_chassis(self, chassis_type=None):
        # TODO(azbiswas): Use chassis_type as input once the compute type
        # preference patch (as part of external ids) merges.
        return [c.name for c in self.chassis_list().execute(check_error=True)]

    def get_chassis_data_for_ml2_bind_port(self, hostname):
        try:
            cmd = self.db_find_rows('Chassis', ('hostname', '=', hostname))
            chassis = next(c for c in cmd.execute(check_error=True))
        except StopIteration:
            msg = _('Chassis with hostname %s does not exist') % hostname
            raise RuntimeError(msg)
        return (chassis.external_ids.get('datapath-type', ''),
                chassis.external_ids.get('iface-types', ''),
                self._get_chassis_physnets(chassis))

    def get_metadata_port_network(self, network):
        # TODO(twilson) This function should really just take a Row/RowView
        try:
            dp = self.lookup('Datapath_Binding', uuid.UUID(network))
        except idlutils.RowNotFound:
            return None
        cmd = self.db_find_rows('Port_Binding', ('datapath', '=', dp),
                                ('type', '=', 'localport'))
        return next(iter(cmd.execute(check_error=True)), None)

    def get_chassis_metadata_networks(self, chassis_name):
        """Return a list with the metadata networks the chassis is hosting."""
        chassis = self.lookup('Chassis', chassis_name)
        proxy_networks = chassis.external_ids.get(
            'neutron-metadata-proxy-networks', None)
        return proxy_networks.split(',') if proxy_networks else []

    def set_chassis_metadata_networks(self, chassis, networks):
        nets = ','.join(networks) if networks else ''
        # TODO(twilson) This could just use DbSetCommand
        return cmd.UpdateChassisExtIdsCommand(
            self, chassis, {'neutron-metadata-proxy-networks': nets},
            if_exists=True)

    def set_chassis_neutron_description(self, chassis, description,
                                        agent_type):
        desc_key = (ovn_const.OVN_AGENT_METADATA_DESC_KEY
                    if agent_type == ovn_const.OVN_METADATA_AGENT else
                    ovn_const.OVN_AGENT_DESC_KEY)
        return cmd.UpdateChassisExtIdsCommand(
            self, chassis, {desc_key: description}, if_exists=False)

    def get_network_port_bindings_by_ip(self, network, ip_address):
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        # TODO(twilson) It would be useful to have a db_find that takes a
        # comparison function

        def check_net_and_ip(port):
            # If the port is not bound to any chassis it is not relevant
            if not port.chassis:
                return False

            # TODO(dalvarez): Remove the comparison to port.datapath.uuid in Y
            # cycle when we are sure that all namespaces will be created with
            # the Neutron network UUID and not anymore with the OVN datapath
            # UUID.
            is_in_network = lambda port: (
                str(port.datapath.uuid) == network or
                utils.get_network_name_from_datapath(port.datapath) == network)

            return port.mac and is_in_network(port) and (
                    ip_address in port.mac[0].split(' '))

        return [r for r in rows if check_net_and_ip(r)]

    def set_port_cidrs(self, name, cidrs):
        # TODO(twilson) add if_exists to db commands
        return self.db_set('Port_Binding', name, 'external_ids',
                           {'neutron-port-cidrs': cidrs})

    def get_ports_on_chassis(self, chassis):
        # TODO(twilson) Some day it would be nice to stop passing names around
        # and just start using chassis objects so db_find_rows could be used
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        return [r for r in rows if r.chassis and r.chassis[0].name == chassis]

    def get_logical_port_chassis_and_datapath(self, name):
        for port in self._tables['Port_Binding'].rows.values():
            if port.logical_port == name:
                datapath = str(port.datapath.uuid)
                chassis = port.chassis[0].name if port.chassis else None
                return chassis, datapath
