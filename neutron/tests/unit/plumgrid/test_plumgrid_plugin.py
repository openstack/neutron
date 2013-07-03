# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
#
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.

"""
Test cases for  Neutron PLUMgrid Plug-in
"""

from mock import patch

from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin as test_plugin


class PLUMgridPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = ('neutron.plugins.plumgrid.plumgrid_nos_plugin.'
                    'plumgrid_plugin.NeutronPluginPLUMgridV2')

    def setUp(self):
        self.restHTTPConnection = patch('httplib.HTTPConnection')
        self.restHTTPConnection.start()
        super(PLUMgridPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(PLUMgridPluginV2TestCase, self).tearDown()
        self.restHTTPConnection.stop()


class TestPlumgridPluginV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                       PLUMgridPluginV2TestCase):

    pass


class TestPlumgridPluginPortsV2(test_plugin.TestPortsV2,
                                PLUMgridPluginV2TestCase):

    pass


class TestPlumgridPluginNetworksV2(test_plugin.TestNetworksV2,
                                   PLUMgridPluginV2TestCase):

    pass


class TestPlumgridPluginSubnetsV2(test_plugin.TestSubnetsV2,
                                  PLUMgridPluginV2TestCase):

    pass


class TestPlumgridNetworkAdminState(PLUMgridPluginV2TestCase):

    def test_network_admin_state(self):
        name = 'network_test'
        admin_status_up = False
        tenant_id = 'tenant_test'
        network = {'network': {'name': name,
                               'admin_state_up': admin_status_up,
                               'tenant_id': tenant_id}}
        plugin = NeutronManager.get_plugin()
        self.assertEqual(plugin._network_admin_state(network), network)
