#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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

import contextlib

import mock
from oslo.config import cfg
from webob import exc
import webtest

from quantum.api import extensions
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db_api
from quantum.db import db_base_plugin_v2
from quantum import manager
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import (nvp_networkgw
                                                                 as networkgw)
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_networkgw_db
from quantum.tests import base
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions


_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path


class TestExtensionManager(object):

    def get_resources(self):
        return networkgw.Nvp_networkgw.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NetworkGatewayExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super(NetworkGatewayExtensionTestCase, self).setUp()
        plugin = '%s.%s' % (networkgw.__name__,
                            networkgw.NetworkGatewayPluginBase.__name__)
        self._resource = networkgw.RESOURCE_NAME.replace('-', '_')
        # Ensure 'stale' patched copies of the plugin are never returned
        manager.QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Create the default configurations
        args = ['--config-file', test_api_v2.etcdir('quantum.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', plugin)
        self.addCleanup(cfg.CONF.reset)

        _plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = _plugin_patcher.start()
        self.addCleanup(_plugin_patcher.stop)

        # Instantiate mock plugin and enable extensions
        manager.QuantumManager.get_plugin().supported_extension_aliases = (
            [networkgw.EXT_ALIAS])
        ext_mgr = TestExtensionManager()
        PluginAwareExtensionManager._instance = ext_mgr
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

    def test_network_gateway_create(self):
        nw_gw_id = _uuid()
        data = {self._resource: {'name': 'nw-gw',
                                 'tenant_id': _uuid(),
                                 'devices': [{'id': _uuid(),
                                              'interface_name': 'xxx'}]}}
        return_value = data[self._resource].copy()
        return_value.update({'id': nw_gw_id})
        instance = self.plugin.return_value
        instance.create_network_gateway.return_value = return_value
        res = self.api.post_json(_get_path(networkgw.COLLECTION_NAME), data)
        instance.create_network_gateway.assert_called_with(
            mock.ANY, network_gateway=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue(self._resource in res.json)
        nw_gw = res.json[self._resource]
        self.assertEqual(nw_gw['id'], nw_gw_id)

    def test_network_gateway_update(self):
        nw_gw_name = 'updated'
        data = {self._resource: {'name': nw_gw_name}}
        nw_gw_id = _uuid()
        return_value = {'id': nw_gw_id,
                        'name': nw_gw_name}

        instance = self.plugin.return_value
        instance.update_network_gateway.return_value = return_value
        res = self.api.put_json(_get_path('%s/%s' % (networkgw.COLLECTION_NAME,
                                                     nw_gw_id)),
                                data)
        instance.update_network_gateway.assert_called_with(
            mock.ANY, nw_gw_id, network_gateway=data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertTrue(self._resource in res.json)
        nw_gw = res.json[self._resource]
        self.assertEqual(nw_gw['id'], nw_gw_id)
        self.assertEqual(nw_gw['name'], nw_gw_name)

    def test_network_gateway_delete(self):
        nw_gw_id = _uuid()
        instance = self.plugin.return_value
        res = self.api.delete(_get_path('%s/%s' % (networkgw.COLLECTION_NAME,
                                                   nw_gw_id)))

        instance.delete_network_gateway.assert_called_with(mock.ANY,
                                                           nw_gw_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_network_gateway_get(self):
        nw_gw_id = _uuid()
        return_value = {self._resource: {'name': 'test',
                                         'devices':
                                         [{'id': _uuid(),
                                           'interface_name': 'xxx'}],
                                         'id': nw_gw_id}}
        instance = self.plugin.return_value
        instance.get_network_gateway.return_value = return_value

        res = self.api.get(_get_path('%s/%s' % (networkgw.COLLECTION_NAME,
                                                nw_gw_id)))

        instance.get_network_gateway.assert_called_with(mock.ANY,
                                                        nw_gw_id,
                                                        fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_network_gateway_list(self):
        nw_gw_id = _uuid()
        return_value = [{self._resource: {'name': 'test',
                                          'devices':
                                          [{'id': _uuid(),
                                            'interface_name': 'xxx'}],
                                          'id': nw_gw_id}}]
        instance = self.plugin.return_value
        instance.get_network_gateways.return_value = return_value

        res = self.api.get(_get_path(networkgw.COLLECTION_NAME))

        instance.get_network_gateways.assert_called_with(mock.ANY,
                                                         fields=mock.ANY,
                                                         filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_network_gateway_connect(self):
        nw_gw_id = _uuid()
        nw_id = _uuid()
        gw_port_id = _uuid()
        mapping_data = {'network_id': nw_id,
                        'segmentation_type': 'vlan',
                        'segmentation_id': '999'}
        return_value = {'connection_info': {
                        'network_gateway_id': nw_gw_id,
                        'port_id': gw_port_id,
                        'network_id': nw_id}}
        instance = self.plugin.return_value
        instance.connect_network.return_value = return_value
        res = self.api.put_json(_get_path('%s/%s/connect_network' %
                                          (networkgw.COLLECTION_NAME,
                                           nw_gw_id)),
                                mapping_data)
        instance.connect_network.assert_called_with(mock.ANY,
                                                    nw_gw_id,
                                                    mapping_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        nw_conn_res = res.json['connection_info']
        self.assertEqual(nw_conn_res['port_id'], gw_port_id)
        self.assertEqual(nw_conn_res['network_id'], nw_id)

    def test_network_gateway_disconnect(self):
        nw_gw_id = _uuid()
        nw_id = _uuid()
        mapping_data = {'network_id': nw_id}
        instance = self.plugin.return_value
        res = self.api.put_json(_get_path('%s/%s/disconnect_network' %
                                          (networkgw.COLLECTION_NAME,
                                           nw_gw_id)),
                                mapping_data)
        instance.disconnect_network.assert_called_with(mock.ANY,
                                                       nw_gw_id,
                                                       mapping_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)


class NetworkGatewayDbTestCase(test_db_plugin.QuantumDbPluginV2TestCase):
    """ Unit tests for Network Gateway DB support """

    def setUp(self):
        test_config['plugin_name_v2'] = '%s.%s' % (
            __name__, TestNetworkGatewayPlugin.__name__)
        ext_mgr = TestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        self.resource = networkgw.RESOURCE_NAME.replace('-', '_')
        super(NetworkGatewayDbTestCase, self).setUp()

    def _create_network_gateway(self, fmt, tenant_id, name=None,
                                devices=None, arg_list=None, **kwargs):
        data = {self.resource: {'tenant_id': tenant_id,
                                'devices': devices}}
        if name:
            data[self.resource]['name'] = name
        for arg in arg_list or ():
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data[self.resource][arg] = kwargs[arg]
        nw_gw_req = self.new_create_request(networkgw.COLLECTION_NAME,
                                            data, fmt)
        if (kwargs.get('set_context') and tenant_id):
            # create a specific auth context for this request
            nw_gw_req.environ['quantum.context'] = context.Context(
                '', tenant_id)
        return nw_gw_req.get_response(self.ext_api)

    @contextlib.contextmanager
    def _network_gateway(self, name='gw1', devices=None,
                         fmt='json', tenant_id=_uuid()):
        if not devices:
            devices = [{'id': _uuid(), 'interface_name': 'xyz'}]
        res = self._create_network_gateway(fmt, tenant_id, name=name,
                                           devices=devices)
        network_gateway = self.deserialize(fmt, res)
        if res.status_int >= 400:
            raise exc.HTTPClientError(code=res.status_int)
        yield network_gateway
        self._delete(networkgw.COLLECTION_NAME,
                     network_gateway[self.resource]['id'])

    def _gateway_action(self, action, network_gateway_id, network_id,
                        segmentation_type, segmentation_id=None,
                        expected_status=exc.HTTPOk.code):
        connection_data = {'network_id': network_id,
                           'segmentation_type': segmentation_type}
        if segmentation_id:
            connection_data['segmentation_id'] = segmentation_id

        req = self.new_action_request(networkgw.COLLECTION_NAME,
                                      connection_data,
                                      network_gateway_id,
                                      "%s_network" % action)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_status)
        return self.deserialize('json', res)

    def _test_connect_and_disconnect_network(self, segmentation_type,
                                             segmentation_id=None):
        with self._network_gateway() as gw:
            with self.network() as net:
                body = self._gateway_action('connect',
                                            gw[self.resource]['id'],
                                            net['network']['id'],
                                            segmentation_type,
                                            segmentation_id)
                self.assertTrue('connection_info' in body)
                connection_info = body['connection_info']
                for attr in ('network_id', 'port_id',
                             'network_gateway_id'):
                    self.assertTrue(attr in connection_info)
                # fetch port and confirm device_id
                gw_port_id = connection_info['port_id']
                port_body = self._show('ports', gw_port_id)
                self.assertEqual(port_body['port']['device_id'],
                                 gw[self.resource]['id'])
                # Clean up - otherwise delete will fail
                body = self._gateway_action('disconnect',
                                            gw[self.resource]['id'],
                                            net['network']['id'],
                                            segmentation_type,
                                            segmentation_id)
                # Check associated port has been deleted too
                body = self._show('ports', gw_port_id,
                                  expected_code=exc.HTTPNotFound.code)

    def test_create_network_gateway(self):
        name = 'test-gw'
        devices = [{'id': _uuid(), 'interface_name': 'xxx'},
                   {'id': _uuid(), 'interface_name': 'yyy'}]
        keys = [('devices', devices), ('name', name)]
        with self._network_gateway(name=name, devices=devices) as gw:
            for k, v in keys:
                self.assertEqual(gw[self.resource][k], v)

    def _test_delete_network_gateway(self, exp_gw_count=0):
        name = 'test-gw'
        devices = [{'id': _uuid(), 'interface_name': 'xxx'},
                   {'id': _uuid(), 'interface_name': 'yyy'}]
        with self._network_gateway(name=name, devices=devices):
            # Nothing to do here - just let the gateway go
            pass
        # Verify nothing left on db
        session = db_api.get_session()
        gw_query = session.query(nicira_networkgw_db.NetworkGateway)
        dev_query = session.query(nicira_networkgw_db.NetworkGatewayDevice)
        self.assertEqual(exp_gw_count, len(gw_query.all()))
        self.assertEqual(0, len(dev_query.all()))

    def test_delete_network_gateway(self):
        self._test_delete_network_gateway()

    def test_update_network_gateway(self):
        with self._network_gateway() as gw:
            data = {self.resource: {'name': 'new_name'}}
            req = self.new_update_request(networkgw.COLLECTION_NAME,
                                          data,
                                          gw[self.resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))
            self.assertEqual(res[self.resource]['name'],
                             data[self.resource]['name'])

    def test_get_network_gateway(self):
        with self._network_gateway(name='test-gw') as gw:
            req = self.new_show_request(networkgw.COLLECTION_NAME,
                                        gw[self.resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))
            self.assertEqual(res[self.resource]['name'],
                             gw[self.resource]['name'])

    def test_list_network_gateways(self):
        with self._network_gateway(name='test-gw-1') as gw1:
            with self._network_gateway(name='test_gw_2') as gw2:
                req = self.new_list_request(networkgw.COLLECTION_NAME)
                res = self.deserialize('json', req.get_response(self.ext_api))
                key = self.resource + 's'
                self.assertEqual(len(res[key]), 2)
                self.assertEqual(res[key][0]['name'],
                                 gw1[self.resource]['name'])
                self.assertEqual(res[key][1]['name'],
                                 gw2[self.resource]['name'])

    def test_connect_and_disconnect_network(self):
        self._test_connect_and_disconnect_network('flat')

    def test_connect_and_disconnect_network_with_segmentation_id(self):
        self._test_connect_and_disconnect_network('vlan', 999)

    def test_connect_network_multiple_times(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_connect_network_multiple_gateways(self):
        with self._network_gateway() as gw_1:
            with self._network_gateway() as gw_2:
                with self.network() as net_1:
                    self._gateway_action('connect',
                                         gw_1[self.resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('connect',
                                         gw_2[self.resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('disconnect',
                                         gw_1[self.resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('disconnect',
                                         gw_2[self.resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)

    def test_connect_network_mapping_in_use_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                with self.network() as net_2:
                    self._gateway_action('connect',
                                         gw[self.resource]['id'],
                                         net_2['network']['id'],
                                         'vlan', 555,
                                         expected_status=exc.HTTPConflict.code)
                # Clean up - otherwise delete will fail
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)

    def test_connect_invalid_network_returns_400(self):
        with self._network_gateway() as gw:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     'hohoho',
                                     'vlan', 555,
                                     expected_status=exc.HTTPBadRequest.code)

    def test_connect_unspecified_network_returns_400(self):
        with self._network_gateway() as gw:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     None,
                                     'vlan', 555,
                                     expected_status=exc.HTTPBadRequest.code)

    def test_disconnect_network_ambiguous_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)
                # This should raise
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan',
                                     expected_status=exc.HTTPConflict.code)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_delete_active_gateway_port_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                body = self._gateway_action('connect',
                                            gw[self.resource]['id'],
                                            net_1['network']['id'],
                                            'vlan', 555)
                # fetch port id and try to delete it
                gw_port_id = body['connection_info']['port_id']
                self._delete('ports', gw_port_id,
                             expected_code=exc.HTTPConflict.code)
                body = self._gateway_action('disconnect',
                                            gw[self.resource]['id'],
                                            net_1['network']['id'],
                                            'vlan', 555)

    def test_delete_network_gateway_active_connections_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'flat')
                self._delete(networkgw.COLLECTION_NAME,
                             gw[self.resource]['id'],
                             expected_code=exc.HTTPConflict.code)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'flat')

    def test_disconnect_non_existing_connection_returns_404(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 999,
                                     expected_status=exc.HTTPNotFound.code)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)


class TestNetworkGatewayPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                               nicira_networkgw_db.NetworkGatewayMixin):
    """ Simple plugin class for testing db support for network gateway ext """

    supported_extension_aliases = ["network-gateway"]

    def delete_port(self, context, id, nw_gw_port_check=True):
        if nw_gw_port_check:
            port = self._get_port(context, id)
            self.prevent_network_gateway_port_deletion(context, port)
        super(TestNetworkGatewayPlugin, self).delete_port(context, id)
