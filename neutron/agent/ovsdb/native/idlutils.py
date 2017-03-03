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

import collections
import os
import time
import uuid

from neutron_lib import exceptions
from oslo_utils import excutils
from ovs.db import idl
from ovs import jsonrpc
from ovs import poller
from ovs import stream
import six
import tenacity

from neutron._i18n import _
from neutron.agent.ovsdb import api
from neutron.agent.ovsdb.native import helpers


RowLookup = collections.namedtuple('RowLookup',
                                   ['table', 'column', 'uuid_column'])

# Tables with no index in OVSDB and special record lookup rules
_LOOKUP_TABLE = {
    'Controller': RowLookup('Bridge', 'name', 'controller'),
    'Flow_Table': RowLookup('Flow_Table', 'name', None),
    'IPFIX': RowLookup('Bridge', 'name', 'ipfix'),
    'Mirror': RowLookup('Mirror', 'name', None),
    'NetFlow': RowLookup('Bridge', 'name', 'netflow'),
    'Open_vSwitch': RowLookup('Open_vSwitch', None, None),
    'QoS': RowLookup('Port', 'name', 'qos'),
    'Queue': RowLookup(None, None, None),
    'sFlow': RowLookup('Bridge', 'name', 'sflow'),
    'SSL': RowLookup('Open_vSwitch', None, 'ssl'),
}

_NO_DEFAULT = object()


class RowNotFound(exceptions.NeutronException):
    message = _("Cannot find %(table)s with %(col)s=%(match)s")


def row_by_value(idl_, table, column, match, default=_NO_DEFAULT):
    """Lookup an IDL row in a table by column/value"""
    tab = idl_.tables[table]
    for r in tab.rows.values():
        if getattr(r, column) == match:
            return r
    if default is not _NO_DEFAULT:
        return default
    raise RowNotFound(table=table, col=column, match=match)


def row_by_record(idl_, table, record):
    t = idl_.tables[table]
    try:
        if isinstance(record, uuid.UUID):
            return t.rows[record]
        uuid_ = uuid.UUID(record)
        return t.rows[uuid_]
    except ValueError:
        # Not a UUID string, continue lookup by other means
        pass
    except KeyError:
        raise RowNotFound(table=table, col='uuid', match=record)

    rl = _LOOKUP_TABLE.get(table, RowLookup(table, get_index_column(t), None))
    # no table means uuid only, no column means lookup table only has one row
    if rl.table is None:
        raise ValueError(_("Table %s can only be queried by UUID") % table)
    if rl.column is None:
        return t.rows.values()[0]
    row = row_by_value(idl_, rl.table, rl.column, record)
    if rl.uuid_column:
        rows = getattr(row, rl.uuid_column)
        if len(rows) != 1:
            raise RowNotFound(table=table, col=_('record'), match=record)
        row = rows[0]
    return row


class ExceptionResult(object):
    def __init__(self, ex, tb):
        self.ex = ex
        self.tb = tb


def _get_schema_helper(connection, schema_name):
    err, strm = stream.Stream.open_block(
        stream.Stream.open(connection))
    if err:
        raise Exception(_("Could not connect to %s") % connection)
    rpc = jsonrpc.Connection(strm)
    req = jsonrpc.Message.create_request('get_schema', [schema_name])
    err, resp = rpc.transact_block(req)
    rpc.close()
    if err:
        raise Exception(_("Could not retrieve schema from %(conn)s: "
                          "%(err)s") % {'conn': connection,
                                        'err': os.strerror(err)})
    elif resp.error:
        raise Exception(resp.error)
    return idl.SchemaHelper(None, resp.result)


def get_schema_helper(connection, schema_name, retry=True):
    try:
        return _get_schema_helper(connection, schema_name)
    except Exception:
        with excutils.save_and_reraise_exception(reraise=False) as ctx:
            if not retry:
                ctx.reraise = True
            # We may have failed due to set-manager not being called
            helpers.enable_connection_uri(connection, set_timeout=True)

            # There is a small window for a race, so retry up to a second
            @tenacity.retry(wait=tenacity.wait_exponential(multiplier=0.01),
                            stop=tenacity.stop_after_delay(1),
                            reraise=True)
            def do_get_schema_helper():
                return _get_schema_helper(connection, schema_name)

            return do_get_schema_helper()


def wait_for_change(_idl, timeout, seqno=None):
    if seqno is None:
        seqno = _idl.change_seqno
    stop = time.time() + timeout
    while _idl.change_seqno == seqno and not _idl.run():
        ovs_poller = poller.Poller()
        _idl.wait(ovs_poller)
        ovs_poller.timer_wait(timeout * 1000)
        ovs_poller.block()
        if time.time() > stop:
            raise Exception(_("Timeout"))


def get_column_value(row, col):
    """Retrieve column value from the given row.

    If column's type is optional, the value will be returned as a single
    element instead of a list of length 1.
    """
    if col == '_uuid':
        val = row.uuid
    else:
        val = getattr(row, col)

    # Idl returns lists of Rows where ovs-vsctl returns lists of UUIDs
    if isinstance(val, list) and len(val):
        if isinstance(val[0], idl.Row):
            val = [v.uuid for v in val]
        col_type = row._table.columns[col].type
        # ovs-vsctl treats lists of 1 as single results
        if col_type.is_optional():
            val = val[0]
    return val


def condition_match(row, condition):
    """Return whether a condition matches a row

    :param row:       An OVSDB Row
    :param condition: A 3-tuple containing (column, operation, match)
    """
    col, op, match = condition
    val = get_column_value(row, col)

    # both match and val are primitive types, so type can be used for type
    # equality here.
    if type(match) is not type(val):
        # Types of 'val' and 'match' arguments MUST match in all cases with 2
        # exceptions:
        # - 'match' is an empty list and column's type is optional;
        # - 'value' is an empty and  column's type is optional
        if (not all([match, val]) and
                row._table.columns[col].type.is_optional()):
            # utilize the single elements comparison logic
            if match == []:
                match = None
            elif val == []:
                val = None
        else:
            # no need to process any further
            raise ValueError(
                _("Column type and condition operand do not match"))

    matched = True

    # TODO(twilson) Implement other operators and type comparisons
    # ovs_lib only uses dict '=' and '!=' searches for now
    if isinstance(match, dict):
        for key in match:
            if op == '=':
                if (key not in val or match[key] != val[key]):
                    matched = False
                    break
            elif op == '!=':
                if key not in val or match[key] == val[key]:
                    matched = False
                    break
            else:
                raise NotImplementedError()
    elif isinstance(match, list):
        # According to rfc7047, lists support '=' and '!='
        # (both strict and relaxed). Will follow twilson's dict comparison
        # and implement relaxed version (excludes/includes as per standard)
        if op == "=":
            if not all([val, match]):
                return val == match
            for elem in set(match):
                if elem not in val:
                    matched = False
                    break
        elif op == '!=':
            if not all([val, match]):
                return val != match
            for elem in set(match):
                if elem in val:
                    matched = False
                    break
        else:
            raise NotImplementedError()
    else:
        if op == '=':
            if val != match:
                matched = False
        elif op == '!=':
            if val == match:
                matched = False
        else:
            raise NotImplementedError()
    return matched


def row_match(row, conditions):
    """Return whether the row matches the list of conditions"""
    return all(condition_match(row, cond) for cond in conditions)


def get_index_column(table):
    if len(table.indexes) == 1:
        idx = table.indexes[0]
        if len(idx) == 1:
            return idx[0].name


def db_replace_record(obj):
    """Replace any api.Command objects with their results

    This method should leave obj untouched unless the object contains an
    api.Command object.
    """
    if isinstance(obj, collections.Mapping):
        for k, v in six.iteritems(obj):
            if isinstance(v, api.Command):
                obj[k] = v.result
    elif (isinstance(obj, collections.Sequence)
          and not isinstance(obj, six.string_types)):
        for i, v in enumerate(obj):
            if isinstance(v, api.Command):
                try:
                    obj[i] = v.result
                except TypeError:
                    # NOTE(twilson) If someone passes a tuple, then just return
                    # a tuple with the Commands replaced with their results
                    return type(obj)(getattr(v, "result", v) for v in obj)
    elif isinstance(obj, api.Command):
        obj = obj.result
    return obj
