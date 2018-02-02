# Copyright (c) 2015 Red Hat, Inc.
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

import time

from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from ovs.db import idl
from six.moves import queue as Queue

from neutron._i18n import _, _LE
from neutron.agent.ovsdb import api
from neutron.agent.ovsdb.native import commands as cmd
from neutron.agent.ovsdb.native import connection
from neutron.agent.ovsdb.native import idlutils
from neutron.agent.ovsdb.native import vlog


cfg.CONF.import_opt('ovs_vsctl_timeout', 'neutron.agent.common.ovs_lib')

LOG = logging.getLogger(__name__)


class VswitchdInterfaceAddException(exceptions.NeutronException):
    message = _("Failed to add interfaces: %(ifaces)s")


class Transaction(api.Transaction):
    def __init__(self, api, ovsdb_connection, timeout,
                 check_error=False, log_errors=True):
        self.api = api
        self.check_error = check_error
        self.log_errors = log_errors
        self.commands = []
        self.results = Queue.Queue(1)
        self.ovsdb_connection = ovsdb_connection
        self.timeout = timeout
        self.expected_ifaces = set()

    def __str__(self):
        return ", ".join(str(cmd) for cmd in self.commands)

    def add(self, command):
        """Add a command to the transaction

        returns The command passed as a convenience
        """

        self.commands.append(command)
        return command

    def commit(self):
        self.ovsdb_connection.queue_txn(self)
        try:
            result = self.results.get(timeout=self.timeout)
        except Queue.Empty:
            raise api.TimeoutException(
                _("Commands %(commands)s exceeded timeout %(timeout)d "
                  "seconds") % {'commands': self.commands,
                                'timeout': self.timeout})
        if isinstance(result, idlutils.ExceptionResult):
            if self.log_errors:
                LOG.error(result.tb)
            if self.check_error:
                raise result.ex
        return result

    def pre_commit(self, txn):
        pass

    def post_commit(self, txn):
        for command in self.commands:
            command.post_commit(txn)

    def do_commit(self):
        self.start_time = time.time()
        attempts = 0
        while True:
            if attempts > 0 and self.timeout_exceeded():
                raise RuntimeError(_("OVS transaction timed out"))
            attempts += 1
            # TODO(twilson) Make sure we don't loop longer than vsctl_timeout
            txn = idl.Transaction(self.api.idl)
            self.pre_commit(txn)
            for i, command in enumerate(self.commands):
                LOG.debug("Running txn command(idx=%(idx)s): %(cmd)s",
                          {'idx': i, 'cmd': command})
                try:
                    command.run_idl(txn)
                except Exception:
                    with excutils.save_and_reraise_exception() as ctx:
                        txn.abort()
                        if not self.check_error:
                            ctx.reraise = False
            status = txn.commit_block()
            if status == txn.TRY_AGAIN:
                LOG.debug("OVSDB transaction returned TRY_AGAIN, retrying")
                continue
            elif status == txn.ERROR:
                msg = _("OVSDB Error: %s") % txn.get_error()
                if self.log_errors:
                    LOG.error(msg)
                if self.check_error:
                    # For now, raise similar error to vsctl/utils.execute()
                    raise RuntimeError(msg)
                return
            elif status == txn.ABORTED:
                LOG.debug("Transaction aborted")
                return
            elif status == txn.UNCHANGED:
                LOG.debug("Transaction caused no change")
            elif status == txn.SUCCESS:
                self.post_commit(txn)

            return [cmd.result for cmd in self.commands]

    def elapsed_time(self):
        return time.time() - self.start_time

    def time_remaining(self):
        return self.timeout - self.elapsed_time()

    def timeout_exceeded(self):
        return self.elapsed_time() > self.timeout


class NeutronOVSDBTransaction(Transaction):
    def pre_commit(self, txn):
        self.api._ovs.increment('next_cfg')
        txn.expected_ifaces = set()

    def post_commit(self, txn):
        super(NeutronOVSDBTransaction, self).post_commit(txn)
        # ovs-vsctl only logs these failures and does not return nonzero
        try:
            self.do_post_commit(txn)
        except Exception:
            LOG.exception(_LE("Post-commit checks failed"))

    def do_post_commit(self, txn):
        next_cfg = txn.get_increment_new_value()
        while not self.timeout_exceeded():
            self.api.idl.run()
            if self.vswitchd_has_completed(next_cfg):
                failed = self.post_commit_failed_interfaces(txn)
                if failed:
                    raise VswitchdInterfaceAddException(
                        ifaces=", ".join(failed))
                break
            self.ovsdb_connection.poller.timer_wait(
                self.time_remaining() * 1000)
            self.api.idl.wait(self.ovsdb_connection.poller)
            self.ovsdb_connection.poller.block()
        else:
            raise api.TimeoutException(
                _("Commands %(commands)s exceeded timeout %(timeout)d "
                  "seconds post-commit") % {'commands': self.commands,
                                            'timeout': self.timeout})

    def post_commit_failed_interfaces(self, txn):
        failed = []
        for iface_uuid in txn.expected_ifaces:
            uuid = txn.get_insert_uuid(iface_uuid)
            if uuid:
                ifaces = self.api.idl.tables['Interface']
                iface = ifaces.rows.get(uuid)
                if iface and (not iface.ofport or iface.ofport == -1):
                    failed.append(iface.name)
        return failed

    def vswitchd_has_completed(self, next_cfg):
        return self.api._ovs.cur_cfg >= next_cfg


class OvsdbIdl(api.API):

    ovsdb_connection = connection.Connection(cfg.CONF.OVS.ovsdb_connection,
                                             cfg.CONF.ovs_vsctl_timeout,
                                             'Open_vSwitch')

    def __init__(self, context):
        super(OvsdbIdl, self).__init__(context)
        OvsdbIdl.ovsdb_connection.start()
        self.idl = OvsdbIdl.ovsdb_connection.idl

    @property
    def _tables(self):
        return self.idl.tables

    @property
    def _ovs(self):
        return list(self._tables['Open_vSwitch'].rows.values())[0]

    def transaction(self, check_error=False, log_errors=True, **kwargs):
        return NeutronOVSDBTransaction(self, OvsdbIdl.ovsdb_connection,
                                       self.context.vsctl_timeout,
                                       check_error, log_errors)

    def add_manager(self, connection_uri):
        return cmd.AddManagerCommand(self, connection_uri)

    def get_manager(self):
        return cmd.GetManagerCommand(self)

    def remove_manager(self, connection_uri):
        return cmd.RemoveManagerCommand(self, connection_uri)

    def add_br(self, name, may_exist=True, datapath_type=None):
        return cmd.AddBridgeCommand(self, name, may_exist, datapath_type)

    def del_br(self, name, if_exists=True):
        return cmd.DelBridgeCommand(self, name, if_exists)

    def br_exists(self, name):
        return cmd.BridgeExistsCommand(self, name)

    def port_to_br(self, name):
        return cmd.PortToBridgeCommand(self, name)

    def iface_to_br(self, name):
        return cmd.InterfaceToBridgeCommand(self, name)

    def list_br(self):
        return cmd.ListBridgesCommand(self)

    def br_get_external_id(self, name, field):
        return cmd.BrGetExternalIdCommand(self, name, field)

    def br_set_external_id(self, name, field, value):
        return cmd.BrSetExternalIdCommand(self, name, field, value)

    def db_create(self, table, **col_values):
        return cmd.DbCreateCommand(self, table, **col_values)

    def db_destroy(self, table, record):
        return cmd.DbDestroyCommand(self, table, record)

    def db_set(self, table, record, *col_values):
        return cmd.DbSetCommand(self, table, record, *col_values)

    def db_add(self, table, record, column, *values):
        return cmd.DbAddCommand(self, table, record, column, *values)

    def db_clear(self, table, record, column):
        return cmd.DbClearCommand(self, table, record, column)

    def db_get(self, table, record, column):
        return cmd.DbGetCommand(self, table, record, column)

    def db_list(self, table, records=None, columns=None, if_exists=False):
        return cmd.DbListCommand(self, table, records, columns, if_exists)

    def db_find(self, table, *conditions, **kwargs):
        return cmd.DbFindCommand(self, table, *conditions, **kwargs)

    def set_controller(self, bridge, controllers):
        return cmd.SetControllerCommand(self, bridge, controllers)

    def del_controller(self, bridge):
        return cmd.DelControllerCommand(self, bridge)

    def get_controller(self, bridge):
        return cmd.GetControllerCommand(self, bridge)

    def set_fail_mode(self, bridge, mode):
        return cmd.SetFailModeCommand(self, bridge, mode)

    def add_port(self, bridge, port, may_exist=True):
        return cmd.AddPortCommand(self, bridge, port, may_exist)

    def del_port(self, port, bridge=None, if_exists=True):
        return cmd.DelPortCommand(self, port, bridge, if_exists)

    def list_ports(self, bridge):
        return cmd.ListPortsCommand(self, bridge)

    def list_ifaces(self, bridge):
        return cmd.ListIfacesCommand(self, bridge)


class NeutronOvsdbIdl(OvsdbIdl):
    def __init__(self, context):
        vlog.use_oslo_logger()
        super(NeutronOvsdbIdl, self).__init__(context)

    def ovs_cleanup(self, bridges, all_ports=False):
        return OvsCleanup(self, bridges, all_ports)


class OvsCleanup(cmd.BaseCommand):
    def __init__(self, api, bridge, all_ports=False):
        super(OvsCleanup, self).__init__(api)
        self.bridge = bridge
        self.all_ports = all_ports

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        for port in br.ports:
            if not any(self.is_deletable_port(iface)
                       for iface in port.interfaces):
                continue
            br.delvalue('ports', port)
            for iface in port.interfaces:
                iface.delete()
            port.delete()

    def is_deletable_port(self, port):
        # Deletable defined as "looks like vif port and not set to skip delete"
        if self.all_ports:
            return True
        if not all(field in port.external_ids
                   for field in ('iface-id', 'attached-mac')):
            return False
        return True
