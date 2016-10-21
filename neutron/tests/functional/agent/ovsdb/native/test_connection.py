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

from neutron.agent.ovsdb.native import connection
from neutron.tests.functional import base
from oslo_config import cfg


class OVSDBConnectionTestCase(base.BaseSudoTestCase):
    def setUp(self):
        super(OVSDBConnectionTestCase, self).setUp()
        self.connection = connection.Connection(
            cfg.CONF.OVS.ovsdb_connection,
            cfg.CONF.ovs_vsctl_timeout, 'Open_vSwitch')

    def test_limit_tables(self):
        tables = ['Open_vSwitch', 'Bridge', 'Port']
        self.connection.start(table_name_list=tables)
        self.assertItemsEqual(tables, self.connection.idl.tables.keys())
