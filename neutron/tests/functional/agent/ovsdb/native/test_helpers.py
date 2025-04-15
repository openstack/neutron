# Copyright (c) 2020 Red Hat, Inc.
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

from neutron_lib import constants as const

from neutron.agent.common import ovs_lib
from neutron.agent.ovsdb.native import helpers
from neutron.tests.common.exclusive_resources import port
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class EnableConnectionUriTestCase(base.BaseSudoTestCase):

    def test_add_manager_appends(self):
        ovs = ovs_lib.BaseOVS()
        ovsdb_cfg_connections = []
        manager_connections = []
        manager_removal = []

        for _ in range(5):
            _port = self.useFixture(port.ExclusivePort(
                const.PROTO_NAME_TCP,
                start=net_helpers.OVS_MANAGER_TEST_PORT_FIRST,
                end=net_helpers.OVS_MANAGER_TEST_PORT_LAST)).port
            ovsdb_cfg_connections.append('tcp:127.0.0.1:%s' % _port)
            manager_connections.append('ptcp:%s:127.0.0.1' % _port)

        for index, conn_uri in enumerate(ovsdb_cfg_connections):
            helpers.enable_connection_uri(conn_uri)
            manager_removal.append(ovs.ovsdb.remove_manager(
                manager_connections[index]))
            self.addCleanup(manager_removal[index].execute)
            self.assertIn(manager_connections[index],
                          ovs.ovsdb.get_manager().execute())

        for remove in manager_removal:
            remove.execute()

        for connection in manager_connections:
            self.assertNotIn(connection, ovs.ovsdb.get_manager().execute())

    def test_add_manager_overwrites_existing_manager(self):
        ovs = ovs_lib.BaseOVS()

        _port = self.useFixture(port.ExclusivePort(
            const.PROTO_NAME_TCP,
            start=net_helpers.OVS_MANAGER_TEST_PORT_FIRST,
            end=net_helpers.OVS_MANAGER_TEST_PORT_LAST)).port
        ovsdb_cfg_connection = 'tcp:127.0.0.1:%s' % _port
        manager_connection = 'ptcp:%s:127.0.0.1' % _port

        helpers.enable_connection_uri(ovsdb_cfg_connection,
                                      inactivity_probe=10)
        self.addCleanup(ovs.ovsdb.remove_manager(manager_connection).execute)
        # First call of enable_connection_uri cretes the manager
        # and the list returned by get_manager contains it:
        my_mans = ovs.ovsdb.get_manager().execute()
        self.assertIn(manager_connection, my_mans)

        # after 2nd call of enable_connection_uri with new value of
        # inactivity_probe will keep the original manager only the
        # inactivity_probe value is set:
        helpers.enable_connection_uri(ovsdb_cfg_connection,
                                      inactivity_probe=100)
        my_mans = ovs.ovsdb.get_manager().execute()
        self.assertIn(manager_connection, my_mans)
