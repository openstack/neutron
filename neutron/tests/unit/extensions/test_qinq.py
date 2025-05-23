# Copyright (c) 2024 Red Hat, Inc.
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

from neutron_lib.api.definitions import provider_net
from neutron_lib.api.definitions import qinq as qinq_apidef
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from oslo_config import cfg
from webob import exc as web_exc

from neutron.db import qinq_db
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.common import test_db_base_plugin_v2
from neutron.tests.unit import testlib_api


class QinqExtensionTestPlugin(ml2_plugin.Ml2Plugin,
                              qinq_db.Vlanqinq_db_mixin):
    """Test plugin to mixin the VLAN transparent extensions."""

    supported_extension_aliases = [provider_net.ALIAS,
                                   qinq_apidef.ALIAS,
                                   vlan_apidef.ALIAS]


class QinqExtensionTestCase(test_db_base_plugin_v2.TestNetworksV2):
    fmt = 'json'

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_qinq.'
                  'QinqExtensionTestPlugin')

        cfg.CONF.set_override('network_vlan_ranges', 'datacentre',
                              group='ml2_type_vlan')
        super().setUp(plugin=plugin)

    def test_create_network_with_qinq_attr(self):
        arg_list = (
            qinq_apidef.QINQ_FIELD,)
        net_kwargs = {
            qinq_apidef.QINQ_FIELD: True
        }
        with self.network(name='net1', as_admin=True,
                          arg_list=arg_list, **net_kwargs) as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertTrue(res['network'][qinq_apidef.QINQ_FIELD])

    def test_create_network_with_bad_qinq_attr(self):
        arg_list = (
            qinq_apidef.QINQ_FIELD,)
        net_kwargs = {
            qinq_apidef.QINQ_FIELD: 'this is not boolean value',
        }
        with testlib_api.ExpectedException(
                web_exc.HTTPClientError) as ctx_manager:
            with self.network(name='net1', as_admin=True,
                              arg_list=arg_list, **net_kwargs):
                pass
        self.assertEqual(web_exc.HTTPClientError.code,
                         ctx_manager.exception.code)

    def test_network_update_with_qinq_exception(self):
        arg_list = (
            qinq_apidef.QINQ_FIELD,)
        net_kwargs = {
            qinq_apidef.QINQ_FIELD: False,
        }
        with self.network(name='net1', as_admin=True,
                          arg_list=arg_list, **net_kwargs) as net:
            self._update('networks', net['network']['id'],
                         {'network': {qinq_apidef.QINQ_FIELD: True}},
                         web_exc.HTTPBadRequest.code)
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertFalse(res['network'][qinq_apidef.QINQ_FIELD])

    def _test_create_network_qinq_and_transparent_vlan(self, qinq_value, vlt):
        arg_list = (
            qinq_apidef.QINQ_FIELD,
            vlan_apidef.VLANTRANSPARENT)
        net_kwargs = {
            qinq_apidef.QINQ_FIELD: qinq_value,
            vlan_apidef.VLANTRANSPARENT: vlt,
        }
        # Both vlan_transparent and qinq can't be set for the same network
        if qinq_value and vlt:
            with testlib_api.ExpectedException(
                    web_exc.HTTPClientError) as ctx_manager:
                with self.network(name='net1', as_admin=True,
                                  arg_list=arg_list, **net_kwargs):
                    pass
            self.assertEqual(web_exc.HTTPBadRequest.code,
                             ctx_manager.exception.code)
            return

        # In any other case it should work fine
        with self.network(name='net1', as_admin=True,
                          arg_list=arg_list, **net_kwargs) as net:
            req = self.new_show_request('networks', net['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(net['network']['name'],
                             res['network']['name'])
            self.assertEqual(qinq_value,
                             res['network'][qinq_apidef.QINQ_FIELD])
            self.assertEqual(vlt, res['network'][vlan_apidef.VLANTRANSPARENT])

    def test_create_network_qinq_disabled_transparent_vlan_enabled(self):
        self._test_create_network_qinq_and_transparent_vlan(False, True)

    def test_create_network_qinq_disabled_transparent_vlan_disabled(self):
        self._test_create_network_qinq_and_transparent_vlan(False, False)

    def test_create_network_qinq_enabled_transparent_vlan_disabled(self):
        self._test_create_network_qinq_and_transparent_vlan(True, False)

    def test_create_network_qinq_enabled_transparent_vlan_enabled(self):
        self._test_create_network_qinq_and_transparent_vlan(True, True)
