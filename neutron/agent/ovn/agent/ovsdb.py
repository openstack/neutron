# Copyright 2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as impl_idl_ovs

from neutron.agent.ovsdb.native import connection as ovsdb_conn
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor


LOG = log.getLogger(__name__)


class MonitorAgentOvnSbIdl(ovsdb_monitor.OvnIdl):

    SCHEMA = 'OVN_Southbound'

    def __init__(self, tables, events, chassis=None):
        connection_string = config.get_ovn_sb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        for table in tables:
            helper.register_table(table)
        try:
            super().__init__(None, connection_string, helper,
                             leader_only=False)
        except TypeError:
            # TODO(twilson) We can remove this when we require ovs>=2.12.0
            super().__init__(None, connection_string, helper)
        if chassis:
            for table in set(tables).intersection({'Chassis',
                                                   'Chassis_Private'}):
                self.set_table_condition(table, [['name', '==', chassis]])
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry(max_=180)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbSbOvnIdl for OVN monitor with retry')
        conn = connection.Connection(
            self, timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbSbOvnIdl(conn)

    def post_connect(self):
        pass


class MonitorAgentOvnNbIdl(ovsdb_monitor.OvnIdl):

    SCHEMA = 'OVN_Northbound'

    def __init__(self, tables, events):
        connection_string = config.get_ovn_nb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        for table in tables:
            helper.register_table(table)
        try:
            super().__init__(None, connection_string, helper,
                             leader_only=False)
        except TypeError:
            # TODO(twilson) We can remove this when we require ovs>=2.12.0
            super().__init__(None, connection_string, helper)
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry(max_=180)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbNbOvnIdl for OVN monitor with retry')
        conn = connection.Connection(
            self, timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbNbOvnIdl(conn)

    def post_connect(self):
        pass


class MonitorAgentOvsIdl(ovsdb_conn.OvsIdl):

    def __init__(self, events):
        super().__init__()
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbIdl for OVN monitor with retry')
        conn = connection.Connection(self,
                                     timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovs.OvsdbIdl(conn)

    def post_connect(self):
        pass


def get_ovn_bridge(ovs_idl):
    """Return the external_ids:ovn-bridge value of the Open_vSwitch table.

    This is the OVS bridge used to plug the metadata ports to.
    If the key doesn't exist, this method will return 'br-int' as default.
    """
    ext_ids = ovs_idl.db_get('Open_vSwitch', '.', 'external_ids').execute()
    try:
        return ext_ids['ovn-bridge']
    except KeyError:
        LOG.warning("Can't read ovn-bridge external-id from OVSDB. Using "
                    "br-int instead.")
        return 'br-int'


def get_own_chassis_name(ovs_idl):
    """Return the external_ids:system-id value of the Open_vSwitch table.

    As long as ovn-controller is running on this node, the key is
    guaranteed to exist and will include the chassis name.
    """
    ext_ids = ovs_idl.db_get('Open_vSwitch', '.', 'external_ids').execute()
    return ext_ids['system-id']
