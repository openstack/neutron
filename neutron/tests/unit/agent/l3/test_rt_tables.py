# Copyright (c) 2015 Hewlett-Packard Enterprise Development Company, L.P.
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

import fixtures
import mock

from neutron.agent.common import utils as common_utils
from neutron.agent.l3 import rt_tables
from neutron.tests import base


def mock_netnamespace_directory(function):
    """Decorator to test RoutingTablesManager with temp dir

    Allows direct testing of RoutingTablesManager by changing the directory
    where it finds the rt_tables to one in /tmp where root privileges are not
    required and it won't mess with any real routing tables.
    """
    orig_execute = common_utils.execute

    def execute_no_root(*args, **kwargs):
        kwargs['run_as_root'] = False
        orig_execute(*args, **kwargs)

    def inner(*args, **kwargs):
        with fixtures.TempDir() as tmpdir:
            cls = rt_tables.NamespaceEtcDir
            with mock.patch.object(common_utils, 'execute') as execute,\
                    mock.patch.object(cls, 'BASE_DIR', tmpdir.path):
                execute.side_effect = execute_no_root
                function(*args, **kwargs)
    return inner


class TestRoutingTablesManager(base.BaseTestCase):
    def setUp(self):
        super(TestRoutingTablesManager, self).setUp()
        self.ns_name = "fakens"

    @mock_netnamespace_directory
    def test_default_tables(self):
        rtm = rt_tables.RoutingTablesManager(self.ns_name)
        self.assertEqual(253, rtm.get("default").table_id)
        self.assertEqual(254, rtm.get("main").table_id)
        self.assertEqual(255, rtm.get("local").table_id)
        self.assertEqual(0, rtm.get("unspec").table_id)

    @mock_netnamespace_directory
    def test_get_all(self):
        rtm = rt_tables.RoutingTablesManager(self.ns_name)
        table_names = set(rt.name for rt in rtm.get_all())
        self.assertEqual({"main", "default", "local", "unspec"}, table_names)

        new_table = rtm.add("faketable")
        self.assertIn(new_table, rtm.get_all())

    @mock_netnamespace_directory
    def test_add(self):
        rtm = rt_tables.RoutingTablesManager(self.ns_name)
        added_table = rtm.add("faketable")
        self.assertGreaterEqual(added_table.table_id, 1024)

        table = rtm.get("faketable")
        self.assertEqual(added_table, table)

        # Be sure that adding it twice gets the same result
        added_again = rtm.add("faketable")
        self.assertEqual(added_table, added_again)

    @mock_netnamespace_directory
    def test_delete(self):
        rtm = rt_tables.RoutingTablesManager(self.ns_name)
        rtm.add("faketable")
        rtm.delete("faketable")

        table = rtm.get("faketable")
        self.assertIsNone(table)
