# Copyright (c) 2015 Openstack Foundation
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

import collections

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.agent.ovsdb import api
from neutron.agent.ovsdb.native import idlutils
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)


class BaseCommand(api.Command):
    def __init__(self, api):
        self.api = api
        self.result = None

    def execute(self, check_error=False, log_errors=True):
        try:
            with self.api.transaction(check_error, log_errors) as txn:
                txn.add(self)
            return self.result
        except Exception:
            with excutils.save_and_reraise_exception() as ctx:
                if log_errors:
                    LOG.exception(_LE("Error executing command"))
                if not check_error:
                    ctx.reraise = False

    def __str__(self):
        command_info = self.__dict__
        return "%s(%s)" % (
            self.__class__.__name__,
            ", ".join("%s=%s" % (k, v) for k, v in command_info.items()
                      if k not in ['api', 'result']))


class AddBridgeCommand(BaseCommand):
    def __init__(self, api, name, may_exist):
        super(AddBridgeCommand, self).__init__(api)
        self.name = name
        self.may_exist = may_exist

    def run_idl(self, txn):
        if self.may_exist:
            br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name',
                                       self.name, None)
            if br:
                return
        row = txn.insert(self.api._tables['Bridge'])
        row.name = self.name
        self.api._ovs.verify('bridges')
        self.api._ovs.bridges = self.api._ovs.bridges + [row]

        # Add the internal bridge port
        cmd = AddPortCommand(self.api, self.name, self.name, self.may_exist)
        cmd.run_idl(txn)

        cmd = DbSetCommand(self.api, 'Interface', self.name,
                           ('type', 'internal'))
        cmd.run_idl(txn)


class DelBridgeCommand(BaseCommand):
    def __init__(self, api, name, if_exists):
        super(DelBridgeCommand, self).__init__(api)
        self.name = name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name',
                                       self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            else:
                msg = _LE("Bridge %s does not exist") % self.name
                LOG.error(msg)
                raise RuntimeError(msg)
        self.api._ovs.verify('bridges')
        for port in br.ports:
            cmd = DelPortCommand(self.api, port.name, self.name,
                                 if_exists=True)
            cmd.run_idl(txn)
        bridges = self.api._ovs.bridges
        bridges.remove(br)
        self.api._ovs.bridges = bridges
        self.api._tables['Bridge'].rows[br.uuid].delete()


class BridgeExistsCommand(BaseCommand):
    def __init__(self, api, name):
        super(BridgeExistsCommand, self).__init__(api)
        self.name = name

    def run_idl(self, txn):
        self.result = bool(idlutils.row_by_value(self.api.idl, 'Bridge',
                                                 'name', self.name, None))


class ListBridgesCommand(BaseCommand):
    def __init__(self, api):
        super(ListBridgesCommand, self).__init__(api)

    def run_idl(self, txn):
        # NOTE (twilson) [x.name for x in rows.values()] if no index
        self.result = [x.name for x in
                       self.api._tables['Bridge'].rows.values()]


class BrGetExternalIdCommand(BaseCommand):
    def __init__(self, api, name, field):
        super(BrGetExternalIdCommand, self).__init__(api)
        self.name = name
        self.field = field

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.name)
        self.result = br.external_ids[self.field]


class BrSetExternalIdCommand(BaseCommand):
    def __init__(self, api, name, field, value):
        super(BrSetExternalIdCommand, self).__init__(api)
        self.name = name
        self.field = field
        self.value = value

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.name)
        external_ids = getattr(br, 'external_ids', {})
        external_ids[self.field] = self.value
        br.external_ids = external_ids


class DbSetCommand(BaseCommand):
    def __init__(self, api, table, record, *col_values):
        super(DbSetCommand, self).__init__(api)
        self.table = table
        self.record = record
        self.col_values = col_values

    def run_idl(self, txn):
        record = idlutils.row_by_record(self.api.idl, self.table, self.record)
        for col, val in self.col_values:
            # TODO(twilson) Ugh, the OVS library doesn't like OrderedDict
            # We're only using it to make a unit test work, so we should fix
            # this soon.
            if isinstance(val, collections.OrderedDict):
                val = dict(val)
            setattr(record, col, val)


class DbClearCommand(BaseCommand):
    def __init__(self, api, table, record, column):
        super(DbClearCommand, self).__init__(api)
        self.table = table
        self.record = record
        self.column = column

    def run_idl(self, txn):
        record = idlutils.row_by_record(self.api.idl, self.table, self.record)
        # Create an empty value of the column type
        value = type(getattr(record, self.column))()
        setattr(record, self.column, value)


class DbGetCommand(BaseCommand):
    def __init__(self, api, table, record, column):
        super(DbGetCommand, self).__init__(api)
        self.table = table
        self.record = record
        self.column = column

    def run_idl(self, txn):
        record = idlutils.row_by_record(self.api.idl, self.table, self.record)
        # TODO(twilson) This feels wrong, but ovs-vsctl returns single results
        # on set types without the list. The IDL is returning them as lists,
        # even if the set has the maximum number of items set to 1. Might be
        # able to inspect the Schema and just do this conversion for that case.
        result = idlutils.get_column_value(record, self.column)
        if isinstance(result, list) and len(result) == 1:
            self.result = result[0]
        else:
            self.result = result


class SetControllerCommand(BaseCommand):
    def __init__(self, api, bridge, targets):
        super(SetControllerCommand, self).__init__(api)
        self.bridge = bridge
        self.targets = targets

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        controllers = []
        for target in self.targets:
            controller = txn.insert(self.api._tables['Controller'])
            controller.target = target
            controllers.append(controller)
        br.verify('controller')
        br.controller = controllers


class DelControllerCommand(BaseCommand):
    def __init__(self, api, bridge):
        super(DelControllerCommand, self).__init__(api)
        self.bridge = bridge

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        br.controller = []


class GetControllerCommand(BaseCommand):
    def __init__(self, api, bridge):
        super(GetControllerCommand, self).__init__(api)
        self.bridge = bridge

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        br.verify('controller')
        self.result = [c.target for c in br.controller]


class SetFailModeCommand(BaseCommand):
    def __init__(self, api, bridge, mode):
        super(SetFailModeCommand, self).__init__(api)
        self.bridge = bridge
        self.mode = mode

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        br.verify('fail_mode')
        br.fail_mode = self.mode


class AddPortCommand(BaseCommand):
    def __init__(self, api, bridge, port, may_exist):
        super(AddPortCommand, self).__init__(api)
        self.bridge = bridge
        self.port = port
        self.may_exist = may_exist

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        if self.may_exist:
            port = idlutils.row_by_value(self.api.idl, 'Port', 'name',
                                         self.port, None)
            if port:
                return
        port = txn.insert(self.api._tables['Port'])
        port.name = self.port
        br.verify('ports')
        ports = getattr(br, 'ports', [])
        ports.append(port)
        br.ports = ports

        iface = txn.insert(self.api._tables['Interface'])
        iface.name = self.port
        port.verify('interfaces')
        ifaces = getattr(port, 'interfaces', [])
        ifaces.append(iface)
        port.interfaces = ifaces


class DelPortCommand(BaseCommand):
    def __init__(self, api, port, bridge, if_exists):
        super(DelPortCommand, self).__init__(api)
        self.port = port
        self.bridge = bridge
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            port = idlutils.row_by_value(self.api.idl, 'Port', 'name',
                                         self.port)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _LE("Port %s does not exist") % self.port
            raise RuntimeError(msg)
        if self.bridge:
            br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name',
                                       self.bridge)
        else:
            br = next(b for b in self.api._tables['Bridge'].rows.values()
                      if port in b.ports)

        if port.uuid not in br.ports and not self.if_exists:
            # TODO(twilson) Make real errors across both implementations
            msg = _LE("Port %(port)s does not exist on %(bridge)s!") % {
                'port': self.name, 'bridge': self.bridge
            }
            LOG.error(msg)
            raise RuntimeError(msg)

        br.verify('ports')
        ports = br.ports
        ports.remove(port)
        br.ports = ports

        # Also remove port/interface directly for indexing?
        port.verify('interfaces')
        for iface in port.interfaces:
            self.api._tables['Interface'].rows[iface.uuid].delete()
        self.api._tables['Port'].rows[port.uuid].delete()


class ListPortsCommand(BaseCommand):
    def __init__(self, api, bridge):
        super(ListPortsCommand, self).__init__(api)
        self.bridge = bridge

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        self.result = [p.name for p in br.ports if p.name != self.bridge]


class ListIfacesCommand(BaseCommand):
    def __init__(self, api, bridge):
        super(ListIfacesCommand, self).__init__(api)
        self.bridge = bridge

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        self.result = [i.name for p in br.ports if p.name != self.bridge
                       for i in p.interfaces]


class PortToBridgeCommand(BaseCommand):
    def __init__(self, api, name):
        super(PortToBridgeCommand, self).__init__(api)
        self.name = name

    def run_idl(self, txn):
        # TODO(twilson) This is expensive!
        # This traversal of all ports could be eliminated by caching the bridge
        # name on the Port's external_id field
        # In fact, if we did that, the only place that uses to_br functions
        # could just add the external_id field to the conditions passed to find
        port = idlutils.row_by_value(self.api.idl, 'Port', 'name', self.name)
        bridges = self.api._tables['Bridge'].rows.values()
        self.result = next(br.name for br in bridges if port in br.ports)


class InterfaceToBridgeCommand(BaseCommand):
    def __init__(self, api, name):
        super(InterfaceToBridgeCommand, self).__init__(api)
        self.name = name

    def run_idl(self, txn):
        interface = idlutils.row_by_value(self.api.idl, 'Interface', 'name',
                                          self.name)
        ports = self.api._tables['Port'].rows.values()
        pname = next(
                port for port in ports if interface in port.interfaces)

        bridges = self.api._tables['Bridge'].rows.values()
        self.result = next(br.name for br in bridges if pname in br.ports)


class DbListCommand(BaseCommand):
    def __init__(self, api, table, records, columns, if_exists):
        super(DbListCommand, self).__init__(api)
        self.table = table
        self.columns = columns
        self.if_exists = if_exists
        self.records = records

    def run_idl(self, txn):
        table_schema = self.api._tables[self.table]
        columns = self.columns or table_schema.columns.keys() + ['_uuid']
        if self.records:
            row_uuids = []
            for record in self.records:
                try:
                    row_uuids.append(idlutils.row_by_record(
                                     self.api.idl, self.table, record).uuid)
                except idlutils.RowNotFound:
                    if self.if_exists:
                        continue
                    # NOTE(kevinbenton): this is converted to a RuntimeError
                    # for compat with the vsctl version. It might make more
                    # sense to change this to a RowNotFoundError in the future.
                    raise RuntimeError(_LE(
                          "Row doesn't exist in the DB. Request info: "
                          "Table=%(table)s. Columns=%(columns)s. "
                          "Records=%(records)s.") % {
                              "table": self.table,
                              "columns": self.columns,
                              "records": self.records,
                          })
        else:
            row_uuids = table_schema.rows.keys()
        self.result = [
            {
                c: idlutils.get_column_value(table_schema.rows[uuid], c)
                for c in columns
            }
            for uuid in row_uuids
        ]


class DbFindCommand(BaseCommand):
    def __init__(self, api, table, *conditions, **kwargs):
        super(DbFindCommand, self).__init__(api)
        self.table = self.api._tables[table]
        self.conditions = conditions
        self.columns = (kwargs.get('columns') or
                        self.table.columns.keys() + ['_uuid'])

    def run_idl(self, txn):
        self.result = [
            {
                c: idlutils.get_column_value(r, c)
                for c in self.columns
            }
            for r in self.table.rows.values()
            if idlutils.row_match(r, self.conditions)
        ]
