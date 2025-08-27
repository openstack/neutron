# Copyright 2025 Red Hat, Inc.
# All Rights Reserved.
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

from oslo_log import log
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event
from ovsdbapp.schema.ovn_northbound import impl_idl as nb_impl_idl
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor

LOG = log.getLogger(__name__)

OVN_NB_TABLES = (
    'Logical_Switch', 'Logical_Switch_Port',
    'Logical_Router', 'Logical_Router_Port',
    'HA_Chassis_Group', 'HA_Chassis',
    'Logical_Router_Static_Route', 'Logical_Router_Policy',
)
OVN_SB_TABLES = ('Chassis', 'Chassis_Private')


class OvnIdl(connection.OvsdbIdl):
    LEADER_ONLY = False

    def __init__(self, connection_string):
        if connection_string.startswith("ssl"):
            ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = idlutils.get_schema_helper(connection_string, self.SCHEMA)
        for table in self.tables:
            helper.register_table(table)
        self.notify_handler = event.RowEventHandler()
        super().__init__(
            connection_string, helper, leader_only=self.LEADER_ONLY)

    def notify(self, event, row, updates=None):
        self.notify_handler.notify(event, row, updates)

    def start(self, timeout):
        conn = connection.Connection(self, timeout=timeout)
        return self.api_cls(conn)


class BgpOvnNbIdl(nb_impl_idl.OvnNbApiIdlImpl):
    LOCK_NAME = 'bgp_topology_lock'

    def set_lock(self):
        LOG.debug("Setting lock for BGP topology")
        self.ovsdb_connection.idl.set_lock(self.LOCK_NAME)
        self.ovsdb_connection.txns.put(None)

    @property
    def has_lock(self):
        return not self.ovsdb_connection.idl.is_lock_contended

    def register_events(self, events):
        self.ovsdb_connection.idl.notify_handler.watch_events(events)


class BgpOvnSbIdl(sb_impl_idl.OvnSbApiIdlImpl):
    def register_events(self, events):
        self.ovsdb_connection.idl.notify_handler.watch_events(events)


class OvnNbIdl(OvnIdl):
    LEADER_ONLY = True
    SCHEMA = 'OVN_Northbound'
    tables = OVN_NB_TABLES
    api_cls = BgpOvnNbIdl


class OvnSbIdl(OvnIdl):
    SCHEMA = 'OVN_Southbound'
    tables = OVN_SB_TABLES
    api_cls = BgpOvnSbIdl
