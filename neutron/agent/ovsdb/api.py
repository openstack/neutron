# Copyright (c) 2014 OpenStack Foundation
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
import collections
import uuid

from oslo_config import cfg
from oslo_utils import importutils
import six

from neutron._i18n import _

interface_map = {
    'vsctl': 'neutron.agent.ovsdb.impl_vsctl.OvsdbVsctl',
    'native': 'neutron.agent.ovsdb.impl_idl.NeutronOvsdbIdl',
}

OPTS = [
    cfg.StrOpt('ovsdb_interface',
               choices=interface_map.keys(),
               default='native',
               help=_('The interface for interacting with the OVSDB')),
    cfg.StrOpt('ovsdb_connection',
               default='tcp:127.0.0.1:6640',
               help=_('The connection string for the OVSDB backend. '
                      'Will be used by ovsdb-client when monitoring and '
                      'used for the all ovsdb commands when native '
                      'ovsdb_interface is enabled'
                      ))
]
cfg.CONF.register_opts(OPTS, 'OVS')


@six.add_metaclass(abc.ABCMeta)
class Command(object):
    """An OVSDB command that can be executed in a transaction

    :attr result: The result of executing the command in a transaction
    """

    @abc.abstractmethod
    def execute(self, **transaction_options):
        """Immediately execute an OVSDB command

        This implicitly creates a transaction with the passed options and then
        executes it, returning the value of the executed transaction

        :param transaction_options: Options to pass to the transaction
        """


@six.add_metaclass(abc.ABCMeta)
class Transaction(object):
    @abc.abstractmethod
    def commit(self):
        """Commit the transaction to OVSDB"""

    @abc.abstractmethod
    def add(self, command):
        """Append an OVSDB operation to the transaction"""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        if exc_type is None:
            self.result = self.commit()


@six.add_metaclass(abc.ABCMeta)
class API(object):
    def __init__(self, context):
        self.context = context

    @staticmethod
    def get(context, iface_name=None):
        """Return the configured OVSDB API implementation"""
        iface = importutils.import_class(
            interface_map[iface_name or cfg.CONF.OVS.ovsdb_interface])
        return iface(context)

    @abc.abstractmethod
    def transaction(self, check_error=False, log_errors=True, **kwargs):
        """Create a transaction

        :param check_error: Allow the transaction to raise an exception?
        :type check_error:  bool
        :param log_errors:  Log an error if the transaction fails?
        :type log_errors:   bool
        :returns: A new transaction
        :rtype: :class:`Transaction`
        """

    @abc.abstractmethod
    def add_manager(self, connection_uri):
        """Create a command to add a Manager to the OVS switch

        This API will add a new manager without overriding the existing ones.

        :param connection_uri: target to which manager needs to be set
        :type connection_uri: string, see ovs-vsctl manpage for format
        :returns:           :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_manager(self):
        """Create a command to get Manager list from the OVS switch

        :returns: :class:`Command` with list of Manager names result
        """

    @abc.abstractmethod
    def remove_manager(self, connection_uri):
        """Create a command to remove a Manager from the OVS switch

        This API will remove the manager configured on the OVS switch.

        :param connection_uri: target identifying the manager uri that
                               needs to be removed.
        :type connection_uri: string, see ovs-vsctl manpage for format
        :returns:           :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_br(self, name, may_exist=True, datapath_type=None):
        """Create a command to add an OVS bridge

        :param name:            The name of the bridge
        :type name:             string
        :param may_exist:       Do not fail if bridge already exists
        :type may_exist:        bool
        :param datapath_type:   The datapath_type of the bridge
        :type datapath_type:    string
        :returns:               :class:`Command` with no result
        """

    @abc.abstractmethod
    def del_br(self, name, if_exists=True):
        """Create a command to delete an OVS bridge

        :param name:      The name of the bridge
        :type name:       string
        :param if_exists: Do not fail if the bridge does not exist
        :type if_exists:  bool
        :returns:        :class:`Command` with no result
        """

    @abc.abstractmethod
    def br_exists(self, name):
        """Create a command to check if an OVS bridge exists

        :param name: The name of the bridge
        :type name:  string
        :returns:    :class:`Command` with bool result
        """

    @abc.abstractmethod
    def port_to_br(self, name):
        """Create a command to return the name of the bridge with the port

        :param name: The name of the OVS port
        :type name:  string
        :returns:    :class:`Command` with bridge name result
        """

    @abc.abstractmethod
    def iface_to_br(self, name):
        """Create a command to return the name of the bridge with the interface

        :param name: The name of the OVS interface
        :type name:  string
        :returns:    :class:`Command` with bridge name result
        """

    @abc.abstractmethod
    def list_br(self):
        """Create a command to return the current list of OVS bridge names

        :returns: :class:`Command` with list of bridge names result
        """

    @abc.abstractmethod
    def br_get_external_id(self, name, field):
        """Create a command to return a field from the Bridge's external_ids

        :param name:  The name of the OVS Bridge
        :type name:   string
        :param field: The external_ids field to return
        :type field:  string
        :returns:     :class:`Command` with field value result
        """

    @abc.abstractmethod
    def db_create(self, table, **col_values):
        """Create a command to create new record

        :param table:      The OVS table containing the record to be created
        :type table:       string
        :param col_values: The columns and their associated values
                           to be set after create
        :type col_values:  Dictionary of columns id's and values
        :returns:          :class:`Command` with no result
        """

    @abc.abstractmethod
    def db_destroy(self, table, record):
        """Create a command to destroy a record

        :param table:      The OVS table containing the record to be destroyed
        :type table:       string
        :param record:     The record id (name/uuid) to be destroyed
        :type record:      uuid/string
        :returns:          :class:`Command` with no result
        """

    @abc.abstractmethod
    def db_set(self, table, record, *col_values):
        """Create a command to set fields in a record

        :param table:      The OVS table containing the record to be modified
        :type table:       string
        :param record:     The record id (name/uuid) to be modified
        :type table:       string
        :param col_values: The columns and their associated values
        :type col_values:  Tuples of (column, value). Values may be atomic
                           values or unnested sequences/mappings
        :returns:          :class:`Command` with no result
        """
        # TODO(twilson) Consider handling kwargs for arguments where order
        # doesn't matter. Though that would break the assert_called_once_with
        # unit tests

    @abc.abstractmethod
    def db_add(self, table, record, column, *values):
        """Create a command to add a value to a record

        Adds each value or key-value pair to column in record in table. If
        column is a map, then each value will be a dict, otherwise a base type.
        If key already exists in a map column, then the current value is not
        replaced (use the set command to replace an existing value).

        :param table:  The OVS table containing the record to be modified
        :type table:   string
        :param record: The record id (name/uuid) to modified
        :type record:  string
        :param column: The column name to be modified
        :type column:  string
        :param values: The values to be added to the column
        :type values:  The base type of the column. If column is a map, then
                       a dict containing the key name and the map's value type
        :returns:     :class:`Command` with no result
        """

    @abc.abstractmethod
    def db_clear(self, table, record, column):
        """Create a command to clear a field's value in a record

        :param table:  The OVS table containing the record to be modified
        :type table:   string
        :param record: The record id (name/uuid) to be modified
        :type record:  string
        :param column: The column whose value should be cleared
        :type column:  string
        :returns:      :class:`Command` with no result
        """

    @abc.abstractmethod
    def db_get(self, table, record, column):
        """Create a command to return a field's value in a record

        :param table:  The OVS table containing the record to be queried
        :type table:   string
        :param record: The record id (name/uuid) to be queried
        :type record:  string
        :param column: The column whose value should be returned
        :type column:  string
        :returns:      :class:`Command` with the field's value result
        """

    @abc.abstractmethod
    def db_list(self, table, records=None, columns=None, if_exists=False):
        """Create a command to return a list of OVSDB records

        :param table:     The OVS table to query
        :type table:      string
        :param records:   The records to return values from
        :type records:    list of record ids (names/uuids)
        :param columns:   Limit results to only columns, None means all columns
        :type columns:    list of column names or None
        :param if_exists: Do not fail if the record does not exist
        :type if_exists:  bool
        :returns:         :class:`Command` with [{'column', value}, ...] result
        """

    @abc.abstractmethod
    def db_find(self, table, *conditions, **kwargs):
        """Create a command to return find OVSDB records matching conditions

        :param table:     The OVS table to query
        :type table:      string
        :param conditions:The conditions to satisfy the query
        :type conditions: 3-tuples containing (column, operation, match)
                          Type of 'match' parameter MUST be identical to column
                          type
                          Examples:
                              atomic: ('tag', '=', 7)
                              map: ('external_ids' '=', {'iface-id': 'xxx'})
                              field exists?
                                  ('external_ids', '!=', {'iface-id', ''})
                              set contains?:
                                  ('protocols', '{>=}', 'OpenFlow13')
                          See the ovs-vsctl man page for more operations
        :param columns:   Limit results to only columns, None means all columns
        :type columns:    list of column names or None
        :returns:         :class:`Command` with [{'column', value}, ...] result
        """

    @abc.abstractmethod
    def set_controller(self, bridge, controllers):
        """Create a command to set an OVS bridge's OpenFlow controllers

        :param bridge:      The name of the bridge
        :type bridge:       string
        :param controllers: The controller strings
        :type controllers:  list of strings, see ovs-vsctl manpage for format
        :returns:           :class:`Command` with no result
        """

    @abc.abstractmethod
    def del_controller(self, bridge):
        """Create a command to clear an OVS bridge's OpenFlow controllers

        :param bridge: The name of the bridge
        :type bridge:  string
        :returns:      :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_controller(self, bridge):
        """Create a command to return an OVS bridge's OpenFlow controllers

        :param bridge: The name of the bridge
        :type bridge:  string
        :returns:      :class:`Command` with list of controller strings result
        """

    @abc.abstractmethod
    def set_fail_mode(self, bridge, mode):
        """Create a command to set an OVS bridge's failure mode

        :param bridge: The name of the bridge
        :type bridge:  string
        :param mode:   The failure mode
        :type mode:    "secure" or "standalone"
        :returns:      :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_port(self, bridge, port, may_exist=True):
        """Create a command to add a port to an OVS bridge

        :param bridge:    The name of the bridge
        :type bridge:     string
        :param port:      The name of the port
        :type port:       string
        :param may_exist: Do not fail if the port already exists
        :type may_exist:  bool
        :returns:         :class:`Command` with no result
        """

    @abc.abstractmethod
    def del_port(self, port, bridge=None, if_exists=True):
        """Create a command to delete a port an OVS port

        :param port:      The name of the port
        :type port:       string
        :param bridge:    Only delete port if it is attached to this bridge
        :type bridge:     string
        :param if_exists: Do not fail if the port does not exist
        :type if_exists:  bool
        :returns:         :class:`Command` with no result
        """

    @abc.abstractmethod
    def list_ports(self, bridge):
        """Create a command to list the names of ports on a bridge

        :param bridge: The name of the bridge
        :type bridge:  string
        :returns:      :class:`Command` with list of port names result
        """

    @abc.abstractmethod
    def list_ifaces(self, bridge):
        """Create a command to list the names of interfaces on a bridge

        :param bridge: The name of the bridge
        :type bridge:  string
        :returns:      :class:`Command` with list of interfaces names result
        """


class TimeoutException(Exception):
    pass


def val_to_py(val):
    """Convert a json ovsdb return value to native python object"""
    if isinstance(val, collections.Sequence) and len(val) == 2:
        if val[0] == "uuid":
            return uuid.UUID(val[1])
        elif val[0] == "set":
            return [val_to_py(x) for x in val[1]]
        elif val[0] == "map":
            return {val_to_py(x): val_to_py(y) for x, y in val[1]}
    return val


def py_to_val(pyval):
    """Convert python value to ovs-vsctl value argument"""
    if isinstance(pyval, bool):
        return 'true' if pyval is True else 'false'
    elif pyval == '':
        return '""'
    else:
        # NOTE(twilson) If a Command object, return its record_id as a value
        return getattr(pyval, "record_id", pyval)
