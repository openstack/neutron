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

import os
import time

from ovs.db import idl
from ovs import jsonrpc
from ovs import poller
from ovs import stream


class ExceptionResult(object):
    def __init__(self, ex, tb):
        self.ex = ex
        self.tb = tb


def get_schema_helper(connection):
    err, strm = stream.Stream.open_block(
        stream.Stream.open(connection))
    if err:
        raise Exception("Could not connect to %s" % (
            connection,))
    rpc = jsonrpc.Connection(strm)
    req = jsonrpc.Message.create_request('get_schema', ['Open_vSwitch'])
    err, resp = rpc.transact_block(req)
    rpc.close()
    if err:
        raise Exception("Could not retrieve schema from %s: %s" % (
            connection, os.strerror(err)))
    elif resp.error:
        raise Exception(resp.error)
    return idl.SchemaHelper(None, resp.result)


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
            raise Exception("Timeout")


def get_column_value(row, col):
    if col == '_uuid':
        val = row.uuid
    else:
        val = getattr(row, col)

    # Idl returns lists of Rows where ovs-vsctl returns lists of UUIDs
    if isinstance(val, list) and len(val):
        if isinstance(val[0], idl.Row):
            val = [v.uuid for v in val]
        # ovs-vsctl treats lists of 1 as single results
        if len(val) == 1:
            val = val[0]
    return val


def condition_match(row, condition):
    """Return whether a condition matches a row

    :param row       An OVSDB Row
    :param condition A 3-tuple containing (column, operation, match)
    """

    col, op, match = condition
    val = get_column_value(row, col)
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
        raise NotImplementedError()
    else:
        if op == '==' and val != match:
            matched = False
        elif op == '!=' and val == match:
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
