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

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.utils import helpers
from oslo_log import log
from oslo_utils import strutils
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
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as cfg
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import commands as cmd
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker
from neutron.services.portforwarding import constants as pf_const


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
        super().__init__(*args, **kwargs)

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
        except OSError as e:
            sock.close()
            return socket_util.get_exception_errno(e), None
        return error, sock
    return _open


class NoProbesMixin:
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
        super().__init__(connection)

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

    @n_utils.classproperty
    def connection_string(cls):
        raise NotImplementedError()

    @n_utils.classproperty
    def schema_helper(cls):
        # SchemaHelper.get_idl_schema() sets schema_json to None which is
        # called in Idl.__init__(), so if we've done that return new helper
        try:
            if cls._schema_helper.schema_json:
                return cls._schema_helper
        except AttributeError:
            pass

        ovsdb_monitor._check_and_set_ssl_files(cls.schema)
        cls._schema_helper = idlutils.get_schema_helper(cls.connection_string,
                                                        cls.schema)
        return cls._schema_helper

    @classmethod
    def get_schema_version(cls):
        return cls.schema_helper.schema_json['version']

    @classmethod
    def schema_has_table(cls, table_name):
        return table_name in cls.schema_helper.schema_json['tables']

    def is_table_present(self, table_name):
        return table_name in self._tables

    def is_col_present(self, table_name, col_name):
        return self.is_table_present(table_name) and (
            col_name in self._tables[table_name].columns)

    def is_col_supports_value(self, table_name, col_name, value):
        if not self.is_col_present(table_name, col_name):
            return False
        enum = self._tables[table_name].columns[col_name].type.key.enum
        if not enum:
            return False
        return value in {k.value for k in enum.values}

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
    @n_utils.classproperty
    def connection_string(cls):
        return cfg.get_ovn_nb_connection()

    @classmethod
    def from_worker(cls, worker_class, driver=None):
        args = (cls.connection_string, cls.schema_helper)
        if worker_class == worker.MaintenanceWorker:
            idl_ = ovsdb_monitor.BaseOvnIdl.from_server(*args)
        else:
            idl_ = ovsdb_monitor.OvnNbIdl.from_server(*args, driver=driver)
        conn = connection.Connection(idl_, timeout=cfg.get_ovn_ovsdb_timeout())
        return cls(conn)

    @property
    def nb_global(self):
        return next(iter(self.db_list_rows('NB_Global').execute(
            check_error=True)))

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
        revision_mismatch_raise = kwargs.pop('revision_mismatch_raise', False)
        try:
            with super().transaction(*args, **kwargs) as t:
                yield t
        except ovn_exc.RevisionConflict as e:
            LOG.info('Transaction aborted. Reason: %s', e)
            if revision_mismatch_raise:
                raise e

    def ls_add(self, switch=None, may_exist=False, network_id=None, **columns):
        if network_id is None:
            return super().ls_add(switch, may_exist, **columns)
        return cmd.AddNetworkCommand(self, network_id, may_exist=may_exist,
                                     **columns)

    def ls_del(self, switch, if_exists=False):
        return cmd.DelLogicalSwitchCommand(self, switch, if_exists)

    def create_lswitch_port(self, lport_name, lswitch_name, may_exist=True,
                            network_id=None, **columns):
        return cmd.AddLSwitchPortCommand(self, lport_name, lswitch_name,
                                         may_exist, network_id=network_id,
                                         **columns)

    def set_lswitch_port(self, lport_name, external_ids_update=None,
                         if_exists=True, **columns):
        return cmd.SetLSwitchPortCommand(self, lport_name, external_ids_update,
                                         if_exists, **columns)

    def update_lswitch_qos_options(self, port, if_exists=True, **qos):
        return cmd.UpdateLSwitchPortQosOptionsCommand(self, port, if_exists,
                                                      **qos)

    def delete_lswitch_port(self, lport_name=None, lswitch_name=None,
                            ext_id=None, if_exists=True):
        if lport_name is not None:
            return cmd.DelLSwitchPortCommand(self, lport_name,
                                             lswitch_name, if_exists)
        raise RuntimeError(_("Currently only supports delete by lport-name"))

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
            lrports = {
                lrport.name.replace('lrp-', ''): lrport.networks
                for lrport in getattr(lrouter, 'ports', [])
                if ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY in lrport.external_ids
            }
            sroutes = [
                {'destination': route.ip_prefix, 'nexthop': route.nexthop}
                for route in getattr(lrouter, 'static_routes', [])
                if any(eid.startswith(constants.DEVICE_OWNER_NEUTRON_PREFIX)
                       for eid in route.external_ids)
            ]

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
                    columns['external_ids'] = nat.external_ids
                    columns['uuid'] = nat.uuid
                    if utils.is_nat_gateway_port_supported(self):
                        columns['gateway_port'] = nat.gateway_port
                    dnat_and_snats.append(columns)
                elif nat.type == 'snat':
                    snat.append(columns)

            result.append({'name': utils.get_neutron_name(lrouter.name),
                           'static_routes': sroutes,
                           'ports': lrports,
                           'snats': snat,
                           'dnat_and_snats': dnat_and_snats})
        return result

    def get_all_logical_routers_static_routes(self):
        """Get static routes associated with all logical Routers

        @return: list of dict, each dict has key-value:
                 - 'name': string router_id in neutron.
                 - 'static_routes': list of static routes rows.
        """
        result = []
        for lrouter in self._tables['Logical_Router'].rows.values():
            if (ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY not in
                    lrouter.external_ids):
                continue
            result.append({'name': utils.get_neutron_name(lrouter.name),
                           'static_routes': getattr(lrouter, 'static_routes',
                                                    [])})

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
            # self.add_acl(**acl_string)
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

    def update_lrouter(self, name, if_exists=True, **columns):
        return cmd.UpdateLRouterCommand(self, name,
                                        if_exists, **columns)

    # This method overrides the parent class ``nb_impl_idl.OvnNbApiIdlImpl``
    # implementation.
    def lr_del(self, router, if_exists=False):
        return cmd.LrDelCommand(self, router, if_exists=if_exists)

    def add_lrouter_port(self, name, lrouter, may_exist=False, **columns):
        return cmd.AddLRouterPortCommand(self, name, lrouter,
                                         may_exist, **columns)

    def schedule_unhosted_gateways(self, g_name, sb_api, plugin, port_physnets,
                                   all_gw_chassis, chassis_with_physnets,
                                   chassis_with_azs):
        return cmd.ScheduleUnhostedGatewaysCommand(
            self, g_name, sb_api, plugin, port_physnets, all_gw_chassis,
            chassis_with_physnets, chassis_with_azs)

    def schedule_new_gateway(self, g_name, sb_api, lrouter_name, plugin,
                             physnet, az_hints):
        return cmd.ScheduleNewGatewayCommand(
            self, g_name, sb_api, lrouter_name, plugin, physnet, az_hints)

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

    def add_static_route(self, lrouter, maintain_bfd=False, **columns):
        return cmd.AddStaticRouteCommand(self, lrouter, maintain_bfd,
                                         **columns)

    def delete_static_routes(self, lrouter, routes, if_exists=True):
        return cmd.DelStaticRoutesCommand(self, lrouter, routes, if_exists)

    def set_static_route(self, sroute, **columns):
        return cmd.SetStaticRouteCommand(self, sroute, **columns)

    def _get_logical_router_port_gateway_chassis(self, lrp, priorities=None):
        """Get the list of chassis hosting this gateway port.

        @param   lrp: logical router port
        @type    lrp: Logical_Router_Port row
        @param   priorities: a list of gateway chassis priorities to search for
        @type    priorities: list of int
        @return: List of tuples (chassis_name, priority) sorted by priority. If
                 ``priorities`` is set then only chassis matching of of these
                 priorities are returned.
        """
        # Try retrieving gateway_chassis with new schema. If new schema is not
        # supported or user is using old schema, then use old schema for
        # getting gateway_chassis
        chassis = []
        if self._tables.get('Gateway_Chassis'):
            for gwc in getattr(lrp, 'gateway_chassis', set()):
                if priorities is not None and gwc.priority not in priorities:
                    continue
                chassis.append((gwc.chassis_name, gwc.priority))
        else:
            rc = lrp.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
            if rc:
                chassis.append((rc, 0))
        # make sure that chassis are sorted by priority
        return sorted(chassis, reverse=True, key=lambda x: x[1])

    @staticmethod
    def _get_logical_router_port_ha_chassis_group(lrp, priorities=None):
        """Get the list of chassis hosting this gateway port.

        @param   lrp: logical router port
        @type    lrp: Logical_Router_Port row
        @param   priorities: a list of gateway chassis priorities to search for
        @type    priorities: list of int
        @return: List of tuples (chassis_name, priority) sorted by priority. If
                 ``priorities`` is set then only chassis matching of these
                 priorities are returned.
        """
        chassis = []
        hcg = getattr(lrp, 'ha_chassis_group', None)
        if not hcg:
            return chassis

        for hc in hcg[0].ha_chassis:
            if priorities is not None and hc.priority not in priorities:
                continue
            chassis.append((hc.chassis_name, hc.priority))
        # Make sure that chassis are sorted by priority (highest prio first)
        return sorted(chassis, reverse=True, key=lambda x: x[1])

    def get_all_chassis_gateway_bindings(self,
                                         chassis_candidate_list=None,
                                         priorities=None):
        chassis_bindings = {}
        for chassis_name in chassis_candidate_list or []:
            chassis_bindings.setdefault(chassis_name, [])
        for lrp in self._tables['Logical_Router_Port'].rows.values():
            if not lrp.name.startswith('lrp-'):
                continue
            chassis = self._get_logical_router_port_gateway_chassis(
                lrp, priorities=priorities)
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

    def get_gateway_chassis_az_hints(self, gateway_name):
        lrp = self.lookup('Logical_Router_Port', gateway_name,
                          default=None)
        if not lrp:
            return []
        router_name = lrp.external_ids.get(
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY, "")
        lrouter = self.lookup('Logical_Router', router_name, default=None)
        if not lrouter:
            return []
        az_string = lrouter.external_ids.get(
            ovn_const.OVN_AZ_HINTS_EXT_ID_KEY, "")
        if not az_string:
            return []
        return az_string.split(",")

    def get_chassis_gateways(self, chassis_name):
        gw_chassis = self.db_find_rows(
            'Gateway_Chassis', ('chassis_name', '=', chassis_name))
        return gw_chassis.execute(check_error=True)

    def get_unhosted_gateways(self, port_physnet_dict, chassis_with_physnets,
                              all_gw_chassis, chassis_with_azs):
        """Return the GW LRPs with no chassis assigned

        If the LRP belongs to a tunnelled network (physnet=None), it won't be
        hosted to any chassis.
        """
        unhosted_gateways = set()
        for port, physnet in port_physnet_dict.items():
            if not physnet:
                continue

            lrp_name = f'{ovn_const.LRP_PREFIX}{port}'
            original_state = self.get_gateway_chassis_binding(lrp_name)
            az_hints = self.get_gateway_chassis_az_hints(lrp_name)
            # Filter out chassis that lost physnet, the cms option,
            # or has been deleted.
            actual_gw_chassis = [
                chassis for chassis in original_state
                if not utils.is_gateway_chassis_invalid(
                    chassis, all_gw_chassis, physnet, chassis_with_physnets,
                    az_hints, chassis_with_azs)]

            # Check if gw ports are fully scheduled.
            if len(actual_gw_chassis) >= ovn_const.MAX_GW_CHASSIS:
                continue

            # If there are no gateways with 'enable-chassis-as-gw' cms option
            # then try to schedule on all gateways with physnets connected,
            # and filter required physnet.
            available_chassis = {
                c for c in all_gw_chassis or chassis_with_physnets.keys()
                if not utils.is_gateway_chassis_invalid(
                    c, all_gw_chassis, physnet, chassis_with_physnets,
                    az_hints, chassis_with_azs)}

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
        subnet = {}
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

    def get_router_port_options(self, lsp_name):
        try:
            lsp = idlutils.row_by_value(self.idl, 'Logical_Switch_Port',
                                        'name', lsp_name)
            options = getattr(lsp, 'options')
            for key in list(options.keys()):
                if key not in ovn_const.OVN_ROUTER_PORT_OPTION_KEYS:
                    del options[key]
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

    def get_router_floatingip_lbs(self, lrouter_name):
        rc = self.db_find_rows('Load_Balancer', (
            'external_ids', '=',
            {ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
             pf_const.PORT_FORWARDING_PLUGIN,
             ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: lrouter_name}))
        return [ovn_obj for ovn_obj in rc.execute(check_error=True)
                if ovn_const.OVN_FIP_EXT_ID_KEY in ovn_obj.external_ids]

    def get_floatingip_in_nat_or_lb(self, fip_id):
        fip = self.get_floatingip(fip_id)
        if fip:
            return fip
        result = self.db_find('Load_Balancer', (
            'external_ids', '=',
            {ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
             pf_const.PORT_FORWARDING_PLUGIN,
             ovn_const.OVN_FIP_EXT_ID_KEY: fip_id})).execute(check_error=True)
        return result[0] if result else None

    def get_floatingip(self, fip_id):
        fip = self.db_find('NAT', ('external_ids', '=',
                                   {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}))
        result = fip.execute(check_error=True)
        return result[0] if result else None

    def get_floatingips(self):
        cmd = self.db_find('NAT',
            ('external_ids', '!=', {ovn_const.OVN_FIP_EXT_ID_KEY: ''}),
            ('type', '=', 'dnat_and_snat')
        )
        return cmd.execute(check_error=True)

    def check_revision_number(self, name, resource, resource_type,
                              if_exists=True):
        return cmd.CheckRevisionNumberCommand(
            self, name, resource, resource_type, if_exists)

    def get_lrouter(self, lrouter_name):
        if uuidutils.is_uuid_like(lrouter_name):
            lrouter_name = utils.ovn_name(lrouter_name)
        try:
            return self.lr_get(lrouter_name).execute(log_errors=False,
                                                     check_error=True)
        except idlutils.RowNotFound:
            return None

    def get_lrouter_port(self, lrp_name):
        # TODO(mangelajo): Implement lrp_get() ovsdbapp and use from here
        if uuidutils.is_uuid_like(lrp_name):
            lrp_name = utils.ovn_lrouter_port_name(lrp_name)
        lrp = self.db_find_rows('Logical_Router_Port', ('name', '=', lrp_name))
        result = lrp.execute(check_error=True)
        return result[0] if result else None

    def get_lrouter_gw_ports(self, lrouter_name):
        r_name = ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY
        is_gw = ovn_const.OVN_ROUTER_IS_EXT_GW
        lr = self.get_lrouter(lrouter_name)
        gw_ports = []
        for lrp in getattr(lr, 'ports', []):
            lrp_ext_ids = getattr(lrp, 'external_ids', {})
            if (r_name not in lrp_ext_ids or
                    lrp_ext_ids[r_name] != lr.name or
                    not strutils.bool_from_string(lrp_ext_ids.get(is_gw))):
                continue

            gw_ports.append(lrp)
        return gw_ports

    def get_lrouter_by_lrouter_port(self, lrp_name):
        """Get LR by name of LRP.

        :param lrp_name: Name of LRP.
        :type lrp_name:  str
        :returns:        LR associated with LRP as represented by lrp_name.
        :rtype:          Optional[ovs_idl.rowview.RowView]
        """
        lrp = self.get_lrouter_port(lrp_name)
        if not lrp:
            return None

        # NOTE(fnordahl) This could be replaced by something like:
        #
        #     lr = self.db_find_rows(
        #         'Logical_Router',
        #         ('ports', '{>}', lrp.uuid))
        #
        # However, ovsdbapp does not currently support the '{>}' operator.
        for lr in self._tables['Logical_Router'].rows.values():
            lr_ports = getattr(lr, 'ports', set())
            if lrp in lr_ports:
                return lr
        return None

    def delete_lrouter_ext_gw(self, lrouter_name, if_exists=True,
                              maintain_bfd=True):
        return cmd.DeleteLRouterExtGwCommand(self, lrouter_name, if_exists,
                                             maintain_bfd)

    def get_port_group(self, pg_name):
        if uuidutils.is_uuid_like(pg_name):
            pg_name = utils.ovn_port_group_name(pg_name)
        return self.lookup('Port_Group', pg_name, default=None)

    def get_address_set(self, as_name):
        if uuidutils.is_uuid_like(as_name):
            as_name_v4 = utils.ovn_ag_addrset_name(as_name, 'ip4')
            as_name_v6 = utils.ovn_ag_addrset_name(as_name, 'ip6')
            return (self.lookup('Address_Set', as_name_v4, default=None),
                    self.lookup('Address_Set', as_name_v6, default=None))
        return self.lookup('Address_Set', as_name, default=None), None

    def get_sg_port_groups(self):
        """Returns OVN port groups used as Neutron Security Groups.

        This method will return all port group entries in OVN that map to
        a Security Group. Even though neutron_pg_drop is used to assist on
        SGs, it will also not be returned.
        """
        port_groups = {}
        for row in self._tables['Port_Group'].rows.values():
            name = getattr(row, 'name')
            if (ovn_const.OVN_SG_EXT_ID_KEY not in row.external_ids or
                    name == ovn_const.OVN_DROP_PORT_GROUP_NAME):
                continue
            data = {}
            for row_key in getattr(row, "_data", {}):
                data[row_key] = getattr(row, row_key)
            port_groups[name] = data
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

    def update_lb_external_ids(self, lb_name, values, if_exists=True):
        return cmd.UpdateLbExternalIds(self, lb_name, values, if_exists)

    def set_nb_global_options(self, **options):
        LOG.debug("Setting NB_Global options: %s", options)
        return self.db_set("NB_Global", ".", options=options)

    def set_router_mac_age_limit(self, router=None):
        # Set the MAC_Binding age limit on OVN Logical Routers
        return cmd.SetLRouterMacAgeLimitCommand(
            self, router, cfg.get_ovn_mac_binding_age_threshold())

    def ha_chassis_group_with_hc_add(self, name, chassis_priority,
                                     may_exist=False, **columns):
        return cmd.HAChassisGroupWithHCAddCommand(
            self, name, chassis_priority, may_exist=may_exist,
            **columns)


class OvsdbSbOvnIdl(sb_impl_idl.OvnSbApiIdlImpl, Backend):
    @n_utils.classproperty
    def connection_string(cls):
        return cfg.get_ovn_sb_connection()

    @classmethod
    def from_worker(cls, worker_class, driver=None):
        args = (cls.connection_string, cls.schema_helper)
        if worker_class == worker.MaintenanceWorker:
            idl_ = ovsdb_monitor.BaseOvnSbIdl.from_server(*args)
        else:
            idl_ = ovsdb_monitor.OvnSbIdl.from_server(*args, driver=driver)
        conn = connection.Connection(idl_, timeout=cfg.get_ovn_ovsdb_timeout())
        return cls(conn)

    def _get_chassis_physnets(self, chassis):
        other_config = utils.get_ovn_chassis_other_config(chassis)
        bridge_mappings = other_config.get('ovn-bridge-mappings', '')
        mapping_dict = helpers.parse_mappings(bridge_mappings.split(','))
        return list(mapping_dict.keys())

    def chassis_exists(self, hostname):
        cmd = self.db_find('Chassis', ('hostname', '=', hostname))
        return bool(cmd.execute(check_error=True))

    def get_chassis_hostname_and_physnets(self):
        chassis_info_dict = {}
        for ch in self.chassis_list().execute(check_error=True):
            chassis_info_dict[ch.hostname] = self._get_chassis_physnets(ch)
        return chassis_info_dict

    def get_gateway_chassis_from_cms_options(self, name_only=True):
        return [ch.name if name_only else ch
                for ch in self.chassis_list().execute(check_error=True)
                if utils.is_gateway_chassis(ch)]

    def get_extport_chassis_from_cms_options(self):
        return [ch for ch in self.chassis_list().execute(check_error=True)
                if utils.is_extport_host_chassis(ch)]

    def get_chassis_and_physnets(self):
        chassis_info_dict = {}
        for ch in self.chassis_list().execute(check_error=True):
            chassis_info_dict[ch.name] = self._get_chassis_physnets(ch)
        return chassis_info_dict

    def get_chassis_and_azs(self):
        chassis_azs = {}
        for ch in self.chassis_list().execute(check_error=True):
            chassis_azs[ch.name] = utils.get_chassis_availability_zones(ch)
        return chassis_azs

    def get_all_chassis(self, chassis_type=None):
        # TODO(azbiswas): Use chassis_type as input once the compute type
        # preference patch (as part of external ids) merges.
        return [c.name for c in self.chassis_list().execute(check_error=True)]

    def get_chassis_by_card_serial_from_cms_options(self,
                                                    card_serial_number):
        for ch in self.chassis_list().execute(check_error=True):
            if ('{}={}'
                    .format(ovn_const.CMS_OPT_CARD_SERIAL_NUMBER,
                            card_serial_number)
                    in utils.get_ovn_chassis_other_config(ch).get(
                        ovn_const.OVN_CMS_OPTIONS, '').split(',')):
                return ch
        raise RuntimeError(
            _('Chassis with %(options)s %(serial)s %(num)s does not exist') %
            {'options': ovn_const.OVN_CMS_OPTIONS,
             'serial': ovn_const.CMS_OPT_CARD_SERIAL_NUMBER,
             'num': card_serial_number})

    def get_metadata_port(self, datapath_uuid):
        # TODO(twilson) This function should really just take a Row/RowView
        try:
            dp = self.lookup('Datapath_Binding', uuid.UUID(datapath_uuid))
        except idlutils.RowNotFound:
            return None
        cmd = self.db_find_rows('Port_Binding', ('datapath', '=', dp),
                                ('type', '=', ovn_const.LSP_TYPE_LOCALPORT),
                                ('external_ids', '=', {
                                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                                        constants.DEVICE_OWNER_DISTRIBUTED}))
        return next(iter(cmd.execute(check_error=True)), None)

    def set_chassis_neutron_description(self, chassis, description,
                                        agent_type):
        desc_key = (ovn_const.OVN_AGENT_METADATA_DESC_KEY
                    if agent_type == ovn_const.OVN_METADATA_AGENT else
                    ovn_const.OVN_AGENT_DESC_KEY)
        return cmd.UpdateChassisExtIdsCommand(
            self, chassis, {desc_key: description}, if_exists=False)

    def get_network_port_bindings_by_ip(self, network, ip_address, mac=None):
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        # TODO(twilson) It would be useful to have a db_find that takes a
        # comparison function

        def check_net_and_ip(port):
            # If the port is not bound to any chassis it is not relevant
            if not port.chassis:
                return False
            if not port.mac:
                return False
            # The MAC and IP address(es) are both present in port.mac as
            # ["MAC IP {IP2...IPN}"]. If either one is present that is a
            # match, since for link-local clients we can only match the MAC.
            mac_ip = port.mac[0].split(' ')
            address_match = False
            if mac and mac in mac_ip:
                address_match = True
            elif ip_address in mac_ip:
                address_match = True
            if not address_match:
                return False

            is_in_network = utils.get_network_name_from_datapath(
                port.datapath) == network
            return is_in_network

        return [r for r in rows if check_net_and_ip(r)]

    def set_port_cidrs(self, name, cidrs):
        # TODO(twilson) add if_exists to db commands
        return self.db_set('Port_Binding', name, 'external_ids',
                           {'neutron-port-cidrs': cidrs})

    def get_ports_on_chassis(self, chassis, include_additional_chassis=False):
        # TODO(twilson) Some day it would be nice to stop passing names around
        # and just start using chassis objects so db_find_rows could be used
        rows = self.db_list_rows('Port_Binding').execute(check_error=True)
        if (include_additional_chassis and
                utils.is_additional_chassis_supported(self)):
            return [r for r in rows
                    if r.chassis and r.chassis[0].name == chassis or
                    chassis in [ch.name for ch in r.additional_chassis]]
        return [r for r in rows
                if r.chassis and r.chassis[0].name == chassis]

    def get_chassis_host_for_port(self, port_id):
        chassis = set()
        cmd = self.db_find_rows('Port_Binding', ('logical_port', '=', port_id))
        for row in cmd.execute(check_error=True):
            try:
                chassis.add(row.chassis[0].name)
            except IndexError:
                # Do not short-circuit here. Proceed to additional
                # chassis handling
                pass

            if utils.is_additional_chassis_supported(self):
                for ch in row.additional_chassis:
                    chassis.add(ch.name)
        return chassis
