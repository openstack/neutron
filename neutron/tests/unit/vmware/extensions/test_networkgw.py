# Copyright 2012 VMware, Inc.  All rights reserved.
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

from neutron.api import extensions
from neutron.api.extensions import PluginAwareExtensionManager
from neutron.api.v2 import attributes
from neutron.common import config
from neutron import context
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.dbexts import networkgw_db
from neutron.plugins.vmware.extensions import networkgw
from neutron.plugins.vmware import nsxlib
from neutron import quota
from neutron.tests import base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extensions
from neutron.tests.unit.vmware import NSXEXT_PATH
from neutron.tests.unit.vmware import PLUGIN_NAME
from neutron.tests.unit.vmware.test_nsx_plugin import NsxPluginV2TestCase

_uuid = test_api_v2._uuid
_get_path = test_api_v2._get_path


class TestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            networkgw.RESOURCE_ATTRIBUTE_MAP)
        return networkgw.Networkgw.get_resources()

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

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Create the default configurations
        args = ['--config-file', test_api_v2.etcdir('neutron.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        self.setup_coreplugin(plugin)
        self.addCleanup(cfg.CONF.reset)

        _plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = _plugin_patcher.start()
        self.addCleanup(_plugin_patcher.stop)

        # Instantiate mock plugin and enable extensions
        manager.NeutronManager.get_plugin().supported_extension_aliases = (
            [networkgw.EXT_ALIAS])
        ext_mgr = TestExtensionManager()
        PluginAwareExtensionManager._instance = ext_mgr
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

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
        self.assertIn(self._resource, res.json)
        nw_gw = res.json[self._resource]
        self.assertEqual(nw_gw['id'], nw_gw_id)

    def _test_network_gateway_create_with_error(
        self, data, error_code=exc.HTTPBadRequest.code):
        res = self.api.post_json(_get_path(networkgw.COLLECTION_NAME), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, error_code)

    def test_network_gateway_create_invalid_device_spec(self):
        data = {self._resource: {'name': 'nw-gw',
                                 'tenant_id': _uuid(),
                                 'devices': [{'id': _uuid(),
                                              'invalid': 'xxx'}]}}
        self._test_network_gateway_create_with_error(data)

    def test_network_gateway_create_extra_attr_in_device_spec(self):
        data = {self._resource: {'name': 'nw-gw',
                                 'tenant_id': _uuid(),
                                 'devices': [{'id': _uuid(),
                                              'interface_name': 'xxx',
                                              'extra_attr': 'onetoomany'}]}}
        self._test_network_gateway_create_with_error(data)

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
        self.assertIn(self._resource, res.json)
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


class NetworkGatewayDbTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    """Unit tests for Network Gateway DB support."""

    def setUp(self, plugin=None, ext_mgr=None):
        if not plugin:
            plugin = '%s.%s' % (__name__, TestNetworkGatewayPlugin.__name__)
        if not ext_mgr:
            ext_mgr = TestExtensionManager()
        self.resource = networkgw.RESOURCE_NAME.replace('-', '_')
        super(NetworkGatewayDbTestCase, self).setUp(plugin=plugin,
                                                    ext_mgr=ext_mgr)

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
            nw_gw_req.environ['neutron.context'] = context.Context(
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
                self.assertIn('connection_info', body)
                connection_info = body['connection_info']
                for attr in ('network_id', 'port_id',
                             'network_gateway_id'):
                    self.assertIn(attr, connection_info)
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

    def test_create_network_gateway_no_interface_name(self):
        name = 'test-gw'
        devices = [{'id': _uuid()}]
        exp_devices = devices
        exp_devices[0]['interface_name'] = 'breth0'
        keys = [('devices', exp_devices), ('name', name)]
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
        gw_query = session.query(networkgw_db.NetworkGateway)
        dev_query = session.query(networkgw_db.NetworkGatewayDevice)
        self.assertEqual(exp_gw_count, gw_query.count())
        self.assertEqual(0, dev_query.count())

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

    def _test_list_network_gateway_with_multiple_connections(
        self, expected_gateways=1):
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
                req = self.new_list_request(networkgw.COLLECTION_NAME)
                res = self.deserialize('json', req.get_response(self.ext_api))
                key = self.resource + 's'
                self.assertEqual(len(res[key]), expected_gateways)
                for item in res[key]:
                    self.assertIn('ports', item)
                    if item['id'] == gw[self.resource]['id']:
                        gw_ports = item['ports']
                self.assertEqual(len(gw_ports), 2)
                segmentation_ids = [555, 777]
                for gw_port in gw_ports:
                    self.assertEqual('vlan', gw_port['segmentation_type'])
                    self.assertIn(gw_port['segmentation_id'], segmentation_ids)
                    segmentation_ids.remove(gw_port['segmentation_id'])
                # Required cleanup
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_list_network_gateway_with_multiple_connections(self):
        self._test_list_network_gateway_with_multiple_connections()

    def test_connect_and_disconnect_network(self):
        self._test_connect_and_disconnect_network('flat')

    def test_connect_and_disconnect_network_no_seg_type(self):
        self._test_connect_and_disconnect_network(None)

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


class TestNetworkGateway(NsxPluginV2TestCase,
                         NetworkGatewayDbTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        cfg.CONF.set_override('api_extensions_path', NSXEXT_PATH)
        super(TestNetworkGateway,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def test_create_network_gateway_name_exceeds_40_chars(self):
        name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name=name) as nw_gw:
            # Assert Neutron name is not truncated
            self.assertEqual(nw_gw[self.resource]['name'], name)

    def test_update_network_gateway_with_name_calls_backend(self):
        with mock.patch.object(
            nsxlib.l2gateway, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='cavani') as nw_gw:
                nw_gw_id = nw_gw[self.resource]['id']
                self._update(networkgw.COLLECTION_NAME, nw_gw_id,
                             {self.resource: {'name': 'higuain'}})
                mock_update_gw.assert_called_once_with(
                    mock.ANY, nw_gw_id, 'higuain')

    def test_update_network_gateway_without_name_does_not_call_backend(self):
        with mock.patch.object(
            nsxlib.l2gateway, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='something') as nw_gw:
                nw_gw_id = nw_gw[self.resource]['id']
                self._update(networkgw.COLLECTION_NAME, nw_gw_id,
                             {self.resource: {}})
                self.assertEqual(mock_update_gw.call_count, 0)

    def test_update_network_gateway_name_exceeds_40_chars(self):
        new_name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name='something') as nw_gw:
            nw_gw_id = nw_gw[self.resource]['id']
            self._update(networkgw.COLLECTION_NAME, nw_gw_id,
                         {self.resource: {'name': new_name}})
            req = self.new_show_request(networkgw.COLLECTION_NAME,
                                        nw_gw_id)
            res = self.deserialize('json', req.get_response(self.ext_api))
            # Assert Neutron name is not truncated
            self.assertEqual(new_name, res[self.resource]['name'])
            # Assert NSX name is truncated
            self.assertEqual(
                new_name[:40],
                self.fc._fake_gatewayservice_dict[nw_gw_id]['display_name'])

    def test_create_network_gateway_nsx_error_returns_500(self):
        def raise_nsx_api_exc(*args, **kwargs):
            raise api_exc.NsxApiException

        with mock.patch.object(nsxlib.l2gateway,
                               'create_l2_gw_service',
                               new=raise_nsx_api_exc):
            res = self._create_network_gateway(
                self.fmt, 'xxx', name='yyy',
                devices=[{'id': uuidutils.generate_uuid()}])
            self.assertEqual(500, res.status_int)

    def test_create_network_gateway_nsx_error_returns_409(self):
        with mock.patch.object(nsxlib.l2gateway,
                               'create_l2_gw_service',
                               side_effect=api_exc.Conflict):
            res = self._create_network_gateway(
                self.fmt, 'xxx', name='yyy',
                devices=[{'id': uuidutils.generate_uuid()}])
            self.assertEqual(409, res.status_int)

    def test_list_network_gateways(self):
        with self._network_gateway(name='test-gw-1') as gw1:
            with self._network_gateway(name='test_gw_2') as gw2:
                req = self.new_list_request(networkgw.COLLECTION_NAME)
                res = self.deserialize('json', req.get_response(self.ext_api))
                # We expect the default gateway too
                key = self.resource + 's'
                self.assertEqual(len(res[key]), 3)
                self.assertEqual(res[key][0]['default'],
                                 True)
                self.assertEqual(res[key][1]['name'],
                                 gw1[self.resource]['name'])
                self.assertEqual(res[key][2]['name'],
                                 gw2[self.resource]['name'])

    def test_list_network_gateway_with_multiple_connections(self):
        self._test_list_network_gateway_with_multiple_connections(
            expected_gateways=2)

    def test_delete_network_gateway(self):
        # The default gateway must still be there
        self._test_delete_network_gateway(1)

    def test_show_network_gateway_nsx_error_returns_404(self):
        invalid_id = 'b5afd4a9-eb71-4af7-a082-8fc625a35b61'
        req = self.new_show_request(networkgw.COLLECTION_NAME, invalid_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(exc.HTTPNotFound.code, res.status_int)


class TestNetworkGatewayPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                               networkgw_db.NetworkGatewayMixin):
    """Simple plugin class for testing db support for network gateway ext."""

    supported_extension_aliases = ["network-gateway"]

    def __init__(self, **args):
        super(TestNetworkGatewayPlugin, self).__init__(**args)
        extensions.append_api_extensions_path([NSXEXT_PATH])

    def delete_port(self, context, id, nw_gw_port_check=True):
        if nw_gw_port_check:
            port = self._get_port(context, id)
            self.prevent_network_gateway_port_deletion(context, port)
        super(TestNetworkGatewayPlugin, self).delete_port(context, id)
