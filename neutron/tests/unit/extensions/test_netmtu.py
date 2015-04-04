# Copyright 2015 Openstack Foundation.
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

from neutron.common import constants
from neutron.db import db_base_plugin_v2
from neutron.db import netmtu_db
from neutron.extensions import netmtu
from neutron.tests.unit.db import test_db_base_plugin_v2


class NetmtuExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return netmtu.get_extended_resources(version)


class NetmtuExtensionTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                netmtu_db.Netmtu_db_mixin):
    """Test plugin to mixin the network MTU extensions.
    """

    supported_extension_aliases = ["net-mtu"]


class NetmtuExtensionTestCase(test_db_base_plugin_v2.TestNetworksV2):
    """Test API extension net-mtu attributes.
    """

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_netmtu.' +
                  'NetmtuExtensionTestPlugin')
        ext_mgr = NetmtuExtensionManager()
        super(NetmtuExtensionTestCase, self).setUp(plugin=plugin,
                                                   ext_mgr=ext_mgr)

    def test_list_networks_with_fields_mtu(self):
        with self.network(name='net1') as net1:
            req = self.new_list_request('networks',
                                        params='fields=name&fields=mtu')
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(1, len(res['networks']))
            self.assertEqual(res['networks'][0]['name'],
                             net1['network']['name'])
            self.assertEqual(res['networks'][0].get('mtu'),
                             constants.DEFAULT_NETWORK_MTU)

    def test_show_network_mtu(self):
        with self.network(name='net1') as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['network']['name'],
                             net['network']['name'])
            self.assertEqual(res['network']['mtu'],
                             constants.DEFAULT_NETWORK_MTU)
