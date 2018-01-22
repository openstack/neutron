# Copyright (c) 2015 Cisco Systems Inc.  All rights reserved.
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

from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from oslo_config import cfg
from webob import exc as web_exc

from neutron.db import db_base_plugin_v2
from neutron.db import vlantransparent_db as vlt_db
from neutron.extensions import vlantransparent as vlt
from neutron import quota
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit import testlib_api


class VlanTransparentExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return vlt.Vlantransparent.get_extended_resources(version)


class VlanTransparentExtensionTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                         vlt_db.Vlantransparent_db_mixin):
    """Test plugin to mixin the VLAN transparent extensions."""

    supported_extension_aliases = ["vlan-transparent"]

    def create_network(self, context, network):
        with context.session.begin(subtransactions=True):
            new_net = super(VlanTransparentExtensionTestPlugin,
                            self).create_network(context, network)
            # Update the vlan_transparent in the database
            n = network['network']
            vlan_transparent = vlan_apidef.get_vlan_transparent(n)
            network = self._get_network(context, new_net['id'])
            n['vlan_transparent'] = vlan_transparent
            network.update(n)
        return new_net


class VlanTransparentExtensionTestCase(test_db_base_plugin_v2.TestNetworksV2):
    fmt = 'json'

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_vlantransparent.'
                  'VlanTransparentExtensionTestPlugin')

        # Update the plugin and extensions path
        ext_mgr = VlanTransparentExtensionManager()
        super(VlanTransparentExtensionTestCase, self).setUp(plugin=plugin,
                                                            ext_mgr=ext_mgr)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def test_network_create_with_vlan_transparent_attr(self):
        vlantrans = {'vlan_transparent': True}
        with self.network(name='net1', **vlantrans) as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertTrue(res['network'][vlan_apidef.VLANTRANSPARENT])

    def test_network_create_with_bad_vlan_transparent_attr(self):
        vlantrans = {'vlan_transparent': "abc"}
        with testlib_api.ExpectedException(
                web_exc.HTTPClientError) as ctx_manager:
            with self.network(name='net1', **vlantrans):
                pass
        self.assertEqual(web_exc.HTTPClientError.code,
                         ctx_manager.exception.code)

    def test_network_update_with_vlan_transparent_exception(self):
        with self.network(name='net1') as net:
            self._update('networks', net['network']['id'],
                         {'network': {vlan_apidef.VLANTRANSPARENT: False}},
                         web_exc.HTTPBadRequest.code)
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertFalse(res['network'][vlan_apidef.VLANTRANSPARENT])
