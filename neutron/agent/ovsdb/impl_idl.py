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

from six.moves import queue as Queue
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from ovs.db import idl

from neutron.agent.ovsdb import api
from neutron.agent.ovsdb.native import commands as cmd
from neutron.agent.ovsdb.native import connection
from neutron.agent.ovsdb.native import helpers
from neutron.agent.ovsdb.native import idlutils
from neutron.i18n import _LE


OPTS = [
    cfg.StrOpt('ovsdb_connection',
               default='tcp:127.0.0.1:6640',
               help=_('The connection string for the native OVSDB backend')),
]
cfg.CONF.register_opts(OPTS, 'OVS')
# TODO(twilson) DEFAULT.ovs_vsctl_timeout should be OVS.vsctl_timeout
cfg.CONF.import_opt('ovs_vsctl_timeout', 'neutron.agent.common.ovs_lib')

LOG = logging.getLogger(__name__)


class Transaction(api.Transaction):
    def __init__(self, api, ovsdb_connection, timeout,
                 check_error=False, log_errors=False):
        self.api = api
        self.check_error = check_error
        self.log_errors = log_errors
        self.commands = []
        self.results = Queue.Queue(1)
        self.ovsdb_connection = ovsdb_connection
        self.timeout = timeout

    def add(self, command):
        """Add a command to the transaction

        returns The command passed as a convenience
        """

        self.commands.append(command)
        return command

    def commit(self):
        self.ovsdb_connection.queue_txn(self)
        result = self.results.get()
        if self.check_error:
            if isinstance(result, idlutils.ExceptionResult):
                if self.log_errors:
                    LOG.error(result.tb)
                raise result.ex
        return result

    def do_commit(self):
        start_time = time.time()
        attempts = 0
        while True:
            elapsed_time = time.time() - start_time
            if attempts > 0 and elapsed_time > self.timeout:
                raise RuntimeError("OVS transaction timed out")
            attempts += 1
            # TODO(twilson) Make sure we don't loop longer than vsctl_timeout
            txn = idl.Transaction(self.api.idl)
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
            seqno = self.api.idl.change_seqno
            status = txn.commit_block()
            if status == txn.TRY_AGAIN:
                LOG.debug("OVSDB transaction returned TRY_AGAIN, retrying")
                idlutils.wait_for_change(
                    self.api.idl, self.timeout - elapsed_time,
                    seqno)
                continue
            elif status == txn.ERROR:
                msg = _LE("OVSDB Error: %s") % txn.get_error()
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

            return [cmd.result for cmd in self.commands]


class OvsdbIdl(api.API):

    ovsdb_connection = connection.Connection(cfg.CONF.OVS.ovsdb_connection,
                                             cfg.CONF.ovs_vsctl_timeout,
                                             'Open_vSwitch')

    def __init__(self, context):
        super(OvsdbIdl, self).__init__(context)
        # it's a chicken and egg problem: by default, the manager that
        # corresponds to the connection URI is in most cases not enabled in
        # local ovsdb, so we still need ovs-vsctl to set it to allow
        # connections
        helpers.enable_connection_uri(self.ovsdb_connection.connection)
        OvsdbIdl.ovsdb_connection.start()
        self.idl = OvsdbIdl.ovsdb_connection.idl

    @property
    def _tables(self):
        return self.idl.tables

    @property
    def _ovs(self):
        return list(self._tables['Open_vSwitch'].rows.values())[0]

    def transaction(self, check_error=False, log_errors=True, **kwargs):
        return Transaction(self, OvsdbIdl.ovsdb_connection,
                           self.context.vsctl_timeout,
                           check_error, log_errors)

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
