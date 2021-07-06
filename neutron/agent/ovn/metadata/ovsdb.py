# Copyright 2017 Red Hat, Inc.
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
from ovs.db import idl
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as idl_ovs
import tenacity

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor


LOG = log.getLogger(__name__)


class MetadataAgentOvnSbIdl(ovsdb_monitor.OvnIdl):

    SCHEMA = 'OVN_Southbound'

    def __init__(self, chassis=None, events=None, tables=None):
        connection_string = config.get_ovn_sb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        if tables is None:
            tables = ('Chassis', 'Encap', 'Port_Binding', 'Datapath_Binding',
                      'SB_Global')
        for table in tables:
            helper.register_table(table)
        super(MetadataAgentOvnSbIdl, self).__init__(
            None, connection_string, helper)
        if chassis:
            for table in set(tables).intersection({'Chassis',
                                                   'Chassis_Private'}):
                self.tables[table].condition = [['name', '==', chassis]]
        if events:
            self.notify_handler.watch_events(events)

    @tenacity.retry(
        wait=tenacity.wait_exponential(max=180),
        reraise=True)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    @tenacity.retry(
        wait=tenacity.wait_exponential(
            max=config.get_ovn_ovsdb_retry_max_interval()),
        reraise=True)
    def start(self):
        LOG.info('Getting OvsdbSbOvnIdl for MetadataAgent with retry')
        conn = connection.Connection(
            self, timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbSbOvnIdl(conn)


class MetadataAgentOvsIdl(object):

    def start(self):
        connection_string = config.cfg.CONF.ovs.ovsdb_connection
        helper = idlutils.get_schema_helper(connection_string,
                                            'Open_vSwitch')
        tables = ('Open_vSwitch', 'Bridge', 'Port', 'Interface')
        for table in tables:
            helper.register_table(table)
        ovs_idl = idl.Idl(
            connection_string, helper,
            probe_interval=config.get_ovn_ovsdb_probe_interval())
        conn = connection.Connection(
            ovs_idl, timeout=config.cfg.CONF.ovs.ovsdb_connection_timeout)
        return idl_ovs.OvsdbIdl(conn)
