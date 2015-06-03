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

from oslo_config import cfg
import six
from webob import exc as web_exc

from neutron.api.v2 import attributes
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
        return vlt.get_extended_resources(version)


class VlanTransparentExtensionTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                         vlt_db.Vlantransparent_db_mixin):
    """Test plugin to mixin the VLAN transparent extensions."""

    supported_extension_aliases = ["vlan-transparent"]


class VlanTransparentExtensionTestCase(test_db_base_plugin_v2.TestNetworksV2):
    fmt = 'json'

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_vlantransparent.'
                  'VlanTransparentExtensionTestPlugin')

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for res, attrs in six.iteritems(attributes.RESOURCE_ATTRIBUTE_MAP):
            self.saved_attr_map[res] = attrs.copy()

        # Update the plugin and extensions path
        self.setup_coreplugin(plugin)
        cfg.CONF.set_override('allow_pagination', True)
        cfg.CONF.set_override('allow_sorting', True)
        ext_mgr = VlanTransparentExtensionManager()
        self.addCleanup(self._restore_attribute_map)
        super(VlanTransparentExtensionTestCase, self).setUp(plugin=plugin,
                                                            ext_mgr=ext_mgr)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def _restore_attribute_map(self):
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_network_create_with_vlan_transparent_attr(self):
        vlantrans = {'vlan_transparent': True}
        with self.network(name='net1', **vlantrans) as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertEqual(True, res['network'][vlt.VLANTRANSPARENT])

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
                         {'network': {vlt.VLANTRANSPARENT: False}},
                         web_exc.HTTPBadRequest.code)
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertEqual(None, res['network'][vlt.VLANTRANSPARENT])
