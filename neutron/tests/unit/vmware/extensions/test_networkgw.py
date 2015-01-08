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

from oslo_config import cfg
from webob import exc
import webtest

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron import context
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron import manager
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.dbexts import networkgw_db
from neutron.plugins.vmware.dbexts import nsx_models
from neutron.plugins.vmware.extensions import networkgw
from neutron.plugins.vmware import nsxlib
from neutron.plugins.vmware.nsxlib import l2gateway as l2gwlib
from neutron import quota
from neutron.tests import base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extensions
from neutron.tests.unit import testlib_plugin
from neutron.tests.unit import vmware
from neutron.tests.unit.vmware import test_nsx_plugin

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


class NetworkGatewayExtensionTestCase(base.BaseTestCase,
                                      testlib_plugin.PluginSetupHelper):

    def setUp(self):
        super(NetworkGatewayExtensionTestCase, self).setUp()
        plugin = '%s.%s' % (networkgw.__name__,
                            networkgw.NetworkGatewayPluginBase.__name__)
        self._gw_resource = networkgw.GATEWAY_RESOURCE_NAME
        self._dev_resource = networkgw.DEVICE_RESOURCE_NAME

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Create the default configurations
        self.config_parse()

        # Update the plugin and extensions path
        self.setup_coreplugin(plugin)

        _plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = _plugin_patcher.start()

        # Instantiate mock plugin and enable extensions
        manager.NeutronManager.get_plugin().supported_extension_aliases = (
            [networkgw.EXT_ALIAS])
        ext_mgr = TestExtensionManager()
        extensions.PluginAwareExtensionManager._instance = ext_mgr
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def test_network_gateway_create(self):
        nw_gw_id = _uuid()
        data = {self._gw_resource: {'name': 'nw-gw',
                                    'tenant_id': _uuid(),
                                    'devices': [{'id': _uuid(),
                                                 'interface_name': 'xxx'}]}}
        return_value = data[self._gw_resource].copy()
        return_value.update({'id': nw_gw_id})
        instance = self.plugin.return_value
        instance.create_network_gateway.return_value = return_value
        res = self.api.post_json(_get_path(networkgw.NETWORK_GATEWAYS), data)
        instance.create_network_gateway.assert_called_with(
            mock.ANY, network_gateway=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertIn(self._gw_resource, res.json)
        nw_gw = res.json[self._gw_resource]
        self.assertEqual(nw_gw['id'], nw_gw_id)

    def _test_network_gateway_create_with_error(
        self, data, error_code=exc.HTTPBadRequest.code):
        res = self.api.post_json(_get_path(networkgw.NETWORK_GATEWAYS), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, error_code)

    def test_network_gateway_create_invalid_device_spec(self):
        data = {self._gw_resource: {'name': 'nw-gw',
                                    'tenant_id': _uuid(),
                                    'devices': [{'id': _uuid(),
                                                 'invalid': 'xxx'}]}}
        self._test_network_gateway_create_with_error(data)

    def test_network_gateway_create_extra_attr_in_device_spec(self):
        data = {self._gw_resource: {'name': 'nw-gw',
                                    'tenant_id': _uuid(),
                                    'devices':
                                    [{'id': _uuid(),
                                      'interface_name': 'xxx',
                                      'extra_attr': 'onetoomany'}]}}
        self._test_network_gateway_create_with_error(data)

    def test_network_gateway_update(self):
        nw_gw_name = 'updated'
        data = {self._gw_resource: {'name': nw_gw_name}}
        nw_gw_id = _uuid()
        return_value = {'id': nw_gw_id,
                        'name': nw_gw_name}

        instance = self.plugin.return_value
        instance.update_network_gateway.return_value = return_value
        res = self.api.put_json(
            _get_path('%s/%s' % (networkgw.NETWORK_GATEWAYS, nw_gw_id)), data)
        instance.update_network_gateway.assert_called_with(
            mock.ANY, nw_gw_id, network_gateway=data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertIn(self._gw_resource, res.json)
        nw_gw = res.json[self._gw_resource]
        self.assertEqual(nw_gw['id'], nw_gw_id)
        self.assertEqual(nw_gw['name'], nw_gw_name)

    def test_network_gateway_delete(self):
        nw_gw_id = _uuid()
        instance = self.plugin.return_value
        res = self.api.delete(_get_path('%s/%s' % (networkgw.NETWORK_GATEWAYS,
                                                   nw_gw_id)))

        instance.delete_network_gateway.assert_called_with(mock.ANY,
                                                           nw_gw_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_network_gateway_get(self):
        nw_gw_id = _uuid()
        return_value = {self._gw_resource: {'name': 'test',
                                            'devices':
                                            [{'id': _uuid(),
                                              'interface_name': 'xxx'}],
                                            'id': nw_gw_id}}
        instance = self.plugin.return_value
        instance.get_network_gateway.return_value = return_value

        res = self.api.get(_get_path('%s/%s' % (networkgw.NETWORK_GATEWAYS,
                                                nw_gw_id)))

        instance.get_network_gateway.assert_called_with(mock.ANY,
                                                        nw_gw_id,
                                                        fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_network_gateway_list(self):
        nw_gw_id = _uuid()
        return_value = [{self._gw_resource: {'name': 'test',
                                             'devices':
                                             [{'id': _uuid(),
                                               'interface_name': 'xxx'}],
                                             'id': nw_gw_id}}]
        instance = self.plugin.return_value
        instance.get_network_gateways.return_value = return_value

        res = self.api.get(_get_path(networkgw.NETWORK_GATEWAYS))

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
                                          (networkgw.NETWORK_GATEWAYS,
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
                                          (networkgw.NETWORK_GATEWAYS,
                                           nw_gw_id)),
                                mapping_data)
        instance.disconnect_network.assert_called_with(mock.ANY,
                                                       nw_gw_id,
                                                       mapping_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_gateway_device_get(self):
        gw_dev_id = _uuid()
        return_value = {self._dev_resource: {'name': 'test',
                                             'connector_type': 'stt',
                                             'connector_ip': '1.1.1.1',
                                             'id': gw_dev_id}}
        instance = self.plugin.return_value
        instance.get_gateway_device.return_value = return_value

        res = self.api.get(_get_path('%s/%s' % (networkgw.GATEWAY_DEVICES,
                                                gw_dev_id)))

        instance.get_gateway_device.assert_called_with(mock.ANY,
                                                       gw_dev_id,
                                                       fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_gateway_device_list(self):
        gw_dev_id = _uuid()
        return_value = [{self._dev_resource: {'name': 'test',
                                              'connector_type': 'stt',
                                              'connector_ip': '1.1.1.1',
                                              'id': gw_dev_id}}]
        instance = self.plugin.return_value
        instance.get_gateway_devices.return_value = return_value

        res = self.api.get(_get_path(networkgw.GATEWAY_DEVICES))

        instance.get_gateway_devices.assert_called_with(mock.ANY,
                                                        fields=mock.ANY,
                                                        filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_gateway_device_create(self):
        gw_dev_id = _uuid()
        data = {self._dev_resource: {'name': 'test-dev',
                                     'tenant_id': _uuid(),
                                     'client_certificate': 'xyz',
                                     'connector_type': 'stt',
                                     'connector_ip': '1.1.1.1'}}
        return_value = data[self._dev_resource].copy()
        return_value.update({'id': gw_dev_id})
        instance = self.plugin.return_value
        instance.create_gateway_device.return_value = return_value
        res = self.api.post_json(_get_path(networkgw.GATEWAY_DEVICES), data)
        instance.create_gateway_device.assert_called_with(
            mock.ANY, gateway_device=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertIn(self._dev_resource, res.json)
        gw_dev = res.json[self._dev_resource]
        self.assertEqual(gw_dev['id'], gw_dev_id)

    def _test_gateway_device_create_with_error(
        self, data, error_code=exc.HTTPBadRequest.code):
        res = self.api.post_json(_get_path(networkgw.GATEWAY_DEVICES), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, error_code)

    def test_gateway_device_create_invalid_connector_type(self):
        data = {self._gw_resource: {'name': 'test-dev',
                                    'client_certificate': 'xyz',
                                    'tenant_id': _uuid(),
                                    'connector_type': 'invalid',
                                    'connector_ip': '1.1.1.1'}}
        self._test_gateway_device_create_with_error(data)

    def test_gateway_device_create_invalid_connector_ip(self):
        data = {self._gw_resource: {'name': 'test-dev',
                                    'client_certificate': 'xyz',
                                    'tenant_id': _uuid(),
                                    'connector_type': 'stt',
                                    'connector_ip': 'invalid'}}
        self._test_gateway_device_create_with_error(data)

    def test_gateway_device_create_extra_attr_in_device_spec(self):
        data = {self._gw_resource: {'name': 'test-dev',
                                    'client_certificate': 'xyz',
                                    'tenant_id': _uuid(),
                                    'alien_attribute': 'E.T.',
                                    'connector_type': 'stt',
                                    'connector_ip': '1.1.1.1'}}
        self._test_gateway_device_create_with_error(data)

    def test_gateway_device_update(self):
        gw_dev_name = 'updated'
        data = {self._dev_resource: {'name': gw_dev_name}}
        gw_dev_id = _uuid()
        return_value = {'id': gw_dev_id,
                        'name': gw_dev_name}

        instance = self.plugin.return_value
        instance.update_gateway_device.return_value = return_value
        res = self.api.put_json(
            _get_path('%s/%s' % (networkgw.GATEWAY_DEVICES, gw_dev_id)), data)
        instance.update_gateway_device.assert_called_with(
            mock.ANY, gw_dev_id, gateway_device=data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        self.assertIn(self._dev_resource, res.json)
        gw_dev = res.json[self._dev_resource]
        self.assertEqual(gw_dev['id'], gw_dev_id)
        self.assertEqual(gw_dev['name'], gw_dev_name)

    def test_gateway_device_delete(self):
        gw_dev_id = _uuid()
        instance = self.plugin.return_value
        res = self.api.delete(_get_path('%s/%s' % (networkgw.GATEWAY_DEVICES,
                                                   gw_dev_id)))
        instance.delete_gateway_device.assert_called_with(mock.ANY, gw_dev_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)


class NetworkGatewayDbTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    """Unit tests for Network Gateway DB support."""

    def setUp(self, plugin=None, ext_mgr=None):
        if not plugin:
            plugin = '%s.%s' % (__name__, TestNetworkGatewayPlugin.__name__)
        if not ext_mgr:
            ext_mgr = TestExtensionManager()
        self.gw_resource = networkgw.GATEWAY_RESOURCE_NAME
        self.dev_resource = networkgw.DEVICE_RESOURCE_NAME

        super(NetworkGatewayDbTestCase, self).setUp(plugin=plugin,
                                                    ext_mgr=ext_mgr)

    def _create_network_gateway(self, fmt, tenant_id, name=None,
                                devices=None, arg_list=None, **kwargs):
        data = {self.gw_resource: {'tenant_id': tenant_id,
                                   'devices': devices}}
        if name:
            data[self.gw_resource]['name'] = name
        for arg in arg_list or ():
            # Arg must be present and not empty
            if kwargs.get(arg):
                data[self.gw_resource][arg] = kwargs[arg]
        nw_gw_req = self.new_create_request(networkgw.NETWORK_GATEWAYS,
                                            data, fmt)
        if (kwargs.get('set_context') and tenant_id):
            # create a specific auth context for this request
            nw_gw_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return nw_gw_req.get_response(self.ext_api)

    @contextlib.contextmanager
    def _network_gateway(self, name='gw1', devices=None,
                         fmt='json', tenant_id=_uuid()):
        device = None
        if not devices:
            device_res = self._create_gateway_device(
                fmt, tenant_id, 'stt', '1.1.1.1', 'xxxxxx',
                name='whatever')
            if device_res.status_int >= 400:
                raise exc.HTTPClientError(code=device_res.status_int)
            device = self.deserialize(fmt, device_res)
            devices = [{'id': device[self.dev_resource]['id'],
                        'interface_name': 'xyz'}]

        res = self._create_network_gateway(fmt, tenant_id, name=name,
                                           devices=devices)
        if res.status_int >= 400:
            raise exc.HTTPClientError(code=res.status_int)
        network_gateway = self.deserialize(fmt, res)
        yield network_gateway

        self._delete(networkgw.NETWORK_GATEWAYS,
                     network_gateway[self.gw_resource]['id'])
        if device:
            self._delete(networkgw.GATEWAY_DEVICES,
                         device[self.dev_resource]['id'])

    def _create_gateway_device(self, fmt, tenant_id,
                               connector_type, connector_ip,
                               client_certificate, name=None,
                               set_context=False):
        data = {self.dev_resource: {'tenant_id': tenant_id,
                                    'connector_type': connector_type,
                                    'connector_ip': connector_ip,
                                    'client_certificate': client_certificate}}
        if name:
            data[self.dev_resource]['name'] = name
        gw_dev_req = self.new_create_request(networkgw.GATEWAY_DEVICES,
                                             data, fmt)
        if (set_context and tenant_id):
            # create a specific auth context for this request
            gw_dev_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return gw_dev_req.get_response(self.ext_api)

    def _update_gateway_device(self, fmt, gateway_device_id,
                               connector_type=None, connector_ip=None,
                               client_certificate=None, name=None,
                               set_context=False, tenant_id=None):
        data = {self.dev_resource: {}}
        if connector_type:
            data[self.dev_resource]['connector_type'] = connector_type
        if connector_ip:
            data[self.dev_resource]['connector_ip'] = connector_ip
        if client_certificate:
            data[self.dev_resource]['client_certificate'] = client_certificate
        if name:
            data[self.dev_resource]['name'] = name
        gw_dev_req = self.new_update_request(networkgw.GATEWAY_DEVICES,
                                             data, gateway_device_id, fmt)
        if (set_context and tenant_id):
            # create a specific auth context for this request
            gw_dev_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return gw_dev_req.get_response(self.ext_api)

    @contextlib.contextmanager
    def _gateway_device(self, name='gw_dev',
                        connector_type='stt',
                        connector_ip='1.1.1.1',
                        client_certificate='xxxxxxxxxxxxxxx',
                        fmt='json', tenant_id=_uuid()):
        res = self._create_gateway_device(
            fmt,
            tenant_id,
            connector_type=connector_type,
            connector_ip=connector_ip,
            client_certificate=client_certificate,
            name=name)
        if res.status_int >= 400:
            raise exc.HTTPClientError(code=res.status_int)
        gateway_device = self.deserialize(fmt, res)
        yield gateway_device

        self._delete(networkgw.GATEWAY_DEVICES,
                     gateway_device[self.dev_resource]['id'])

    def _gateway_action(self, action, network_gateway_id, network_id,
                        segmentation_type, segmentation_id=None,
                        expected_status=exc.HTTPOk.code):
        connection_data = {'network_id': network_id,
                           'segmentation_type': segmentation_type}
        if segmentation_id:
            connection_data['segmentation_id'] = segmentation_id

        req = self.new_action_request(networkgw.NETWORK_GATEWAYS,
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
                                            gw[self.gw_resource]['id'],
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
                                 gw[self.gw_resource]['id'])
                # Clean up - otherwise delete will fail
                body = self._gateway_action('disconnect',
                                            gw[self.gw_resource]['id'],
                                            net['network']['id'],
                                            segmentation_type,
                                            segmentation_id)
                # Check associated port has been deleted too
                body = self._show('ports', gw_port_id,
                                  expected_code=exc.HTTPNotFound.code)

    def test_create_network_gateway(self):
        tenant_id = _uuid()
        with contextlib.nested(
            self._gateway_device(name='dev_1',
                                 tenant_id=tenant_id),
            self._gateway_device(name='dev_2',
                                 tenant_id=tenant_id)) as (dev_1, dev_2):
            name = 'test-gw'
            dev_1_id = dev_1[self.dev_resource]['id']
            dev_2_id = dev_2[self.dev_resource]['id']
            devices = [{'id': dev_1_id, 'interface_name': 'xxx'},
                       {'id': dev_2_id, 'interface_name': 'yyy'}]
            keys = [('devices', devices), ('name', name)]
            with self._network_gateway(name=name,
                                       devices=devices,
                                       tenant_id=tenant_id) as gw:
                for k, v in keys:
                    self.assertEqual(gw[self.gw_resource][k], v)

    def test_create_network_gateway_no_interface_name(self):
        tenant_id = _uuid()
        with self._gateway_device(tenant_id=tenant_id) as dev:
            name = 'test-gw'
            devices = [{'id': dev[self.dev_resource]['id']}]
            exp_devices = devices
            exp_devices[0]['interface_name'] = 'breth0'
            keys = [('devices', exp_devices), ('name', name)]
            with self._network_gateway(name=name,
                                       devices=devices,
                                       tenant_id=tenant_id) as gw:
                for k, v in keys:
                    self.assertEqual(gw[self.gw_resource][k], v)

    def test_create_network_gateway_not_owned_device_raises_404(self):
        # Create a device with a different tenant identifier
        with self._gateway_device(name='dev', tenant_id=_uuid()) as dev:
            name = 'test-gw'
            dev_id = dev[self.dev_resource]['id']
            devices = [{'id': dev_id, 'interface_name': 'xxx'}]
            res = self._create_network_gateway(
                'json', _uuid(), name=name, devices=devices)
            self.assertEqual(404, res.status_int)

    def test_create_network_gateway_non_existent_device_raises_404(self):
        name = 'test-gw'
        devices = [{'id': _uuid(), 'interface_name': 'xxx'}]
        res = self._create_network_gateway(
            'json', _uuid(), name=name, devices=devices)
        self.assertEqual(404, res.status_int)

    def test_delete_network_gateway(self):
        tenant_id = _uuid()
        with self._gateway_device(tenant_id=tenant_id) as dev:
            name = 'test-gw'
            device_id = dev[self.dev_resource]['id']
            devices = [{'id': device_id,
                        'interface_name': 'xxx'}]
            with self._network_gateway(name=name,
                                       devices=devices,
                                       tenant_id=tenant_id) as gw:
                # Nothing to do here - just let the gateway go
                gw_id = gw[self.gw_resource]['id']
        # Verify nothing left on db
        session = db_api.get_session()
        dev_query = session.query(
            nsx_models.NetworkGatewayDevice).filter(
                nsx_models.NetworkGatewayDevice.id == device_id)
        self.assertIsNone(dev_query.first())
        gw_query = session.query(nsx_models.NetworkGateway).filter(
            nsx_models.NetworkGateway.id == gw_id)
        self.assertIsNone(gw_query.first())

    def test_update_network_gateway(self):
        with self._network_gateway() as gw:
            data = {self.gw_resource: {'name': 'new_name'}}
            req = self.new_update_request(networkgw.NETWORK_GATEWAYS,
                                          data,
                                          gw[self.gw_resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))
            self.assertEqual(res[self.gw_resource]['name'],
                             data[self.gw_resource]['name'])

    def test_get_network_gateway(self):
        with self._network_gateway(name='test-gw') as gw:
            req = self.new_show_request(networkgw.NETWORK_GATEWAYS,
                                        gw[self.gw_resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))
            self.assertEqual(res[self.gw_resource]['name'],
                             gw[self.gw_resource]['name'])

    def test_list_network_gateways(self):
        with self._network_gateway(name='test-gw-1') as gw1:
            with self._network_gateway(name='test_gw_2') as gw2:
                req = self.new_list_request(networkgw.NETWORK_GATEWAYS)
                res = self.deserialize('json', req.get_response(self.ext_api))
                key = self.gw_resource + 's'
                self.assertEqual(len(res[key]), 2)
                self.assertEqual(res[key][0]['name'],
                                 gw1[self.gw_resource]['name'])
                self.assertEqual(res[key][1]['name'],
                                 gw2[self.gw_resource]['name'])

    def _test_list_network_gateway_with_multiple_connections(
        self, expected_gateways=1):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)
                req = self.new_list_request(networkgw.NETWORK_GATEWAYS)
                res = self.deserialize('json', req.get_response(self.ext_api))
                key = self.gw_resource + 's'
                self.assertEqual(len(res[key]), expected_gateways)
                for item in res[key]:
                    self.assertIn('ports', item)
                    if item['id'] == gw[self.gw_resource]['id']:
                        gw_ports = item['ports']
                self.assertEqual(len(gw_ports), 2)
                segmentation_ids = [555, 777]
                for gw_port in gw_ports:
                    self.assertEqual('vlan', gw_port['segmentation_type'])
                    self.assertIn(gw_port['segmentation_id'], segmentation_ids)
                    segmentation_ids.remove(gw_port['segmentation_id'])
                # Required cleanup
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_list_network_gateway_with_multiple_connections(self):
        self._test_list_network_gateway_with_multiple_connections()

    def test_connect_and_disconnect_network(self):
        self._test_connect_and_disconnect_network('flat')

    def test_connect_and_disconnect_network_no_seg_type(self):
        self._test_connect_and_disconnect_network(None)

    def test_connect_and_disconnect_network_vlan_with_segmentation_id(self):
        self._test_connect_and_disconnect_network('vlan', 999)

    def test_connect_and_disconnect_network_vlan_without_segmentation_id(self):
        self._test_connect_and_disconnect_network('vlan')

    def test_connect_network_multiple_times(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_connect_network_multiple_gateways(self):
        with self._network_gateway() as gw_1:
            with self._network_gateway() as gw_2:
                with self.network() as net_1:
                    self._gateway_action('connect',
                                         gw_1[self.gw_resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('connect',
                                         gw_2[self.gw_resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('disconnect',
                                         gw_1[self.gw_resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)
                    self._gateway_action('disconnect',
                                         gw_2[self.gw_resource]['id'],
                                         net_1['network']['id'],
                                         'vlan', 555)

    def test_connect_network_mapping_in_use_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                with self.network() as net_2:
                    self._gateway_action('connect',
                                         gw[self.gw_resource]['id'],
                                         net_2['network']['id'],
                                         'vlan', 555,
                                         expected_status=exc.HTTPConflict.code)
                # Clean up - otherwise delete will fail
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)

    def test_connect_network_vlan_invalid_seg_id_returns_400(self):
        with self._network_gateway() as gw:
            with self.network() as net:
                # above upper bound
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net['network']['id'],
                                     'vlan', 4095,
                                     expected_status=exc.HTTPBadRequest.code)
                # below lower bound (0 is valid for NSX plugin)
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net['network']['id'],
                                     'vlan', -1,
                                     expected_status=exc.HTTPBadRequest.code)

    def test_connect_invalid_network_returns_400(self):
        with self._network_gateway() as gw:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     'hohoho',
                                     'vlan', 555,
                                     expected_status=exc.HTTPBadRequest.code)

    def test_connect_unspecified_network_returns_400(self):
        with self._network_gateway() as gw:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     None,
                                     'vlan', 555,
                                     expected_status=exc.HTTPBadRequest.code)

    def test_disconnect_network_ambiguous_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)
                # This should raise
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan',
                                     expected_status=exc.HTTPConflict.code)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 777)

    def test_delete_active_gateway_port_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                body = self._gateway_action('connect',
                                            gw[self.gw_resource]['id'],
                                            net_1['network']['id'],
                                            'vlan', 555)
                # fetch port id and try to delete it
                gw_port_id = body['connection_info']['port_id']
                self._delete('ports', gw_port_id,
                             expected_code=exc.HTTPConflict.code)
                body = self._gateway_action('disconnect',
                                            gw[self.gw_resource]['id'],
                                            net_1['network']['id'],
                                            'vlan', 555)

    def test_delete_network_gateway_active_connections_returns_409(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'flat')
                self._delete(networkgw.NETWORK_GATEWAYS,
                             gw[self.gw_resource]['id'],
                             expected_code=exc.HTTPConflict.code)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'flat')

    def test_disconnect_non_existing_connection_returns_404(self):
        with self._network_gateway() as gw:
            with self.network() as net_1:
                self._gateway_action('connect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 999,
                                     expected_status=exc.HTTPNotFound.code)
                self._gateway_action('disconnect',
                                     gw[self.gw_resource]['id'],
                                     net_1['network']['id'],
                                     'vlan', 555)

    def test_create_gateway_device(
        self, expected_status=networkgw_db.STATUS_UNKNOWN):
        with self._gateway_device(name='test-dev',
                                  connector_type='stt',
                                  connector_ip='1.1.1.1',
                                  client_certificate='xyz') as dev:
            self.assertEqual(dev[self.dev_resource]['name'], 'test-dev')
            self.assertEqual(dev[self.dev_resource]['connector_type'], 'stt')
            self.assertEqual(dev[self.dev_resource]['connector_ip'], '1.1.1.1')
            self.assertEqual(dev[self.dev_resource]['status'], expected_status)

    def test_list_gateway_devices(self):
        with contextlib.nested(
            self._gateway_device(name='test-dev-1',
                                 connector_type='stt',
                                 connector_ip='1.1.1.1',
                                 client_certificate='xyz'),
            self._gateway_device(name='test-dev-2',
                                 connector_type='stt',
                                 connector_ip='2.2.2.2',
                                 client_certificate='qwe')) as (dev_1, dev_2):
            req = self.new_list_request(networkgw.GATEWAY_DEVICES)
            res = self.deserialize('json', req.get_response(self.ext_api))
        devices = res[networkgw.GATEWAY_DEVICES.replace('-', '_')]
        self.assertEqual(len(devices), 2)
        dev_1 = devices[0]
        dev_2 = devices[1]
        self.assertEqual(dev_1['name'], 'test-dev-1')
        self.assertEqual(dev_2['name'], 'test-dev-2')

    def test_get_gateway_device(
        self, expected_status=networkgw_db.STATUS_UNKNOWN):
        with self._gateway_device(name='test-dev',
                                  connector_type='stt',
                                  connector_ip='1.1.1.1',
                                  client_certificate='xyz') as dev:
            req = self.new_show_request(networkgw.GATEWAY_DEVICES,
                                        dev[self.dev_resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(res[self.dev_resource]['name'], 'test-dev')
        self.assertEqual(res[self.dev_resource]['connector_type'], 'stt')
        self.assertEqual(res[self.dev_resource]['connector_ip'], '1.1.1.1')
        self.assertEqual(res[self.dev_resource]['status'], expected_status)

    def test_update_gateway_device(
        self, expected_status=networkgw_db.STATUS_UNKNOWN):
        with self._gateway_device(name='test-dev',
                                  connector_type='stt',
                                  connector_ip='1.1.1.1',
                                  client_certificate='xyz') as dev:
            self._update_gateway_device('json', dev[self.dev_resource]['id'],
                                        connector_type='stt',
                                        connector_ip='2.2.2.2',
                                        name='test-dev-upd')
            req = self.new_show_request(networkgw.GATEWAY_DEVICES,
                                        dev[self.dev_resource]['id'])
            res = self.deserialize('json', req.get_response(self.ext_api))

        self.assertEqual(res[self.dev_resource]['name'], 'test-dev-upd')
        self.assertEqual(res[self.dev_resource]['connector_type'], 'stt')
        self.assertEqual(res[self.dev_resource]['connector_ip'], '2.2.2.2')
        self.assertEqual(res[self.dev_resource]['status'], expected_status)

    def test_delete_gateway_device(self):
        with self._gateway_device(name='test-dev',
                                  connector_type='stt',
                                  connector_ip='1.1.1.1',
                                  client_certificate='xyz') as dev:
            # Nothing to do here - just note the device id
            dev_id = dev[self.dev_resource]['id']
        # Verify nothing left on db
        session = db_api.get_session()
        dev_query = session.query(nsx_models.NetworkGatewayDevice)
        dev_query.filter(nsx_models.NetworkGatewayDevice.id == dev_id)
        self.assertIsNone(dev_query.first())


class TestNetworkGateway(test_nsx_plugin.NsxPluginV2TestCase,
                         NetworkGatewayDbTestCase):

    def setUp(self, plugin=vmware.PLUGIN_NAME, ext_mgr=None):
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        # Mock l2gwlib calls for gateway devices since this resource is not
        # mocked through the fake NSX API client
        create_gw_dev_patcher = mock.patch.object(
            l2gwlib, 'create_gateway_device')
        update_gw_dev_patcher = mock.patch.object(
            l2gwlib, 'update_gateway_device')
        delete_gw_dev_patcher = mock.patch.object(
            l2gwlib, 'delete_gateway_device')
        get_gw_dev_status_patcher = mock.patch.object(
            l2gwlib, 'get_gateway_device_status')
        get_gw_dev_statuses_patcher = mock.patch.object(
            l2gwlib, 'get_gateway_devices_status')
        self.mock_create_gw_dev = create_gw_dev_patcher.start()
        self.mock_create_gw_dev.return_value = {'uuid': 'callejon'}
        self.mock_update_gw_dev = update_gw_dev_patcher.start()
        delete_gw_dev_patcher.start()
        self.mock_get_gw_dev_status = get_gw_dev_status_patcher.start()
        get_gw_dev_statuses = get_gw_dev_statuses_patcher.start()
        get_gw_dev_statuses.return_value = {}

        super(TestNetworkGateway,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def test_create_network_gateway_name_exceeds_40_chars(self):
        name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name=name) as nw_gw:
            # Assert Neutron name is not truncated
            self.assertEqual(nw_gw[self.gw_resource]['name'], name)

    def test_update_network_gateway_with_name_calls_backend(self):
        with mock.patch.object(
            nsxlib.l2gateway, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='cavani') as nw_gw:
                nw_gw_id = nw_gw[self.gw_resource]['id']
                self._update(networkgw.NETWORK_GATEWAYS, nw_gw_id,
                             {self.gw_resource: {'name': 'higuain'}})
                mock_update_gw.assert_called_once_with(
                    mock.ANY, nw_gw_id, 'higuain')

    def test_update_network_gateway_without_name_does_not_call_backend(self):
        with mock.patch.object(
            nsxlib.l2gateway, 'update_l2_gw_service') as mock_update_gw:
            with self._network_gateway(name='something') as nw_gw:
                nw_gw_id = nw_gw[self.gw_resource]['id']
                self._update(networkgw.NETWORK_GATEWAYS, nw_gw_id,
                             {self.gw_resource: {}})
                self.assertEqual(mock_update_gw.call_count, 0)

    def test_update_network_gateway_name_exceeds_40_chars(self):
        new_name = 'this_is_a_gateway_whose_name_is_longer_than_40_chars'
        with self._network_gateway(name='something') as nw_gw:
            nw_gw_id = nw_gw[self.gw_resource]['id']
            self._update(networkgw.NETWORK_GATEWAYS, nw_gw_id,
                         {self.gw_resource: {'name': new_name}})
            req = self.new_show_request(networkgw.NETWORK_GATEWAYS,
                                        nw_gw_id)
            res = self.deserialize('json', req.get_response(self.ext_api))
            # Assert Neutron name is not truncated
            self.assertEqual(new_name, res[self.gw_resource]['name'])
            # Assert NSX name is truncated
            self.assertEqual(
                new_name[:40],
                self.fc._fake_gatewayservice_dict[nw_gw_id]['display_name'])

    def test_create_network_gateway_nsx_error_returns_500(self):
        def raise_nsx_api_exc(*args, **kwargs):
            raise api_exc.NsxApiException()

        with mock.patch.object(nsxlib.l2gateway,
                               'create_l2_gw_service',
                               new=raise_nsx_api_exc):
            tenant_id = _uuid()
            with self._gateway_device(tenant_id=tenant_id) as dev:
                res = self._create_network_gateway(
                    self.fmt,
                    tenant_id,
                    name='yyy',
                    devices=[{'id': dev[self.dev_resource]['id']}])
            self.assertEqual(500, res.status_int)

    def test_create_network_gateway_nsx_error_returns_409(self):
        with mock.patch.object(nsxlib.l2gateway,
                               'create_l2_gw_service',
                               side_effect=api_exc.Conflict):
            tenant_id = _uuid()
            with self._gateway_device(tenant_id=tenant_id) as dev:
                res = self._create_network_gateway(
                    self.fmt,
                    tenant_id,
                    name='yyy',
                    devices=[{'id': dev[self.dev_resource]['id']}])
            self.assertEqual(409, res.status_int)

    def test_list_network_gateways(self):
        with self._network_gateway(name='test-gw-1') as gw1:
            with self._network_gateway(name='test_gw_2') as gw2:
                req = self.new_list_request(networkgw.NETWORK_GATEWAYS)
                res = self.deserialize('json', req.get_response(self.ext_api))
                # Ensure we always get the list in the same order
                gateways = sorted(
                    res[self.gw_resource + 's'], key=lambda k: k['name'])
                self.assertEqual(len(gateways), 3)
                # We expect the default gateway too
                self.assertEqual(gateways[0]['default'], True)
                self.assertEqual(gateways[1]['name'],
                                 gw1[self.gw_resource]['name'])
                self.assertEqual(gateways[2]['name'],
                                 gw2[self.gw_resource]['name'])

    def test_list_network_gateway_with_multiple_connections(self):
        self._test_list_network_gateway_with_multiple_connections(
            expected_gateways=2)

    def test_show_network_gateway_nsx_error_returns_404(self):
        invalid_id = 'b5afd4a9-eb71-4af7-a082-8fc625a35b61'
        req = self.new_show_request(networkgw.NETWORK_GATEWAYS, invalid_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(exc.HTTPNotFound.code, res.status_int)

    def test_create_gateway_device(self):
        self.mock_get_gw_dev_status.return_value = True
        super(TestNetworkGateway, self).test_create_gateway_device(
            expected_status=networkgw_db.STATUS_ACTIVE)

    def test_create_gateway_device_status_down(self):
        self.mock_get_gw_dev_status.return_value = False
        super(TestNetworkGateway, self).test_create_gateway_device(
            expected_status=networkgw_db.STATUS_DOWN)

    def test_create_gateway_device_invalid_cert_returns_400(self):
        self.mock_create_gw_dev.side_effect = (
            nsx_exc.InvalidSecurityCertificate)
        res = self._create_gateway_device(
            'json',
            _uuid(),
            connector_type='stt',
            connector_ip='1.1.1.1',
            client_certificate='invalid_certificate',
            name='whatever')
        self.assertEqual(res.status_int, 400)

    def test_get_gateway_device(self):
        self.mock_get_gw_dev_status.return_value = True
        super(TestNetworkGateway, self).test_get_gateway_device(
            expected_status=networkgw_db.STATUS_ACTIVE)

    def test_get_gateway_device_status_down(self):
        self.mock_get_gw_dev_status.return_value = False
        super(TestNetworkGateway, self).test_get_gateway_device(
            expected_status=networkgw_db.STATUS_DOWN)

    def test_update_gateway_device(self):
        self.mock_get_gw_dev_status.return_value = True
        super(TestNetworkGateway, self).test_update_gateway_device(
            expected_status=networkgw_db.STATUS_ACTIVE)

    def test_update_gateway_device_status_down(self):
        self.mock_get_gw_dev_status.return_value = False
        super(TestNetworkGateway, self).test_update_gateway_device(
            expected_status=networkgw_db.STATUS_DOWN)

    def test_update_gateway_device_invalid_cert_returns_400(self):
        with self._gateway_device(
            name='whaterver',
            connector_type='stt',
            connector_ip='1.1.1.1',
            client_certificate='iminvalidbutiitdoesnotmatter') as dev:
            self.mock_update_gw_dev.side_effect = (
                nsx_exc.InvalidSecurityCertificate)
            res = self._update_gateway_device(
                'json',
                dev[self.dev_resource]['id'],
                client_certificate='invalid_certificate')
            self.assertEqual(res.status_int, 400)


class TestNetworkGatewayPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                               networkgw_db.NetworkGatewayMixin):
    """Simple plugin class for testing db support for network gateway ext."""

    supported_extension_aliases = ["network-gateway"]

    def __init__(self, **args):
        super(TestNetworkGatewayPlugin, self).__init__(**args)
        extensions.append_api_extensions_path([vmware.NSXEXT_PATH])

    def delete_port(self, context, id, nw_gw_port_check=True):
        if nw_gw_port_check:
            port = self._get_port(context, id)
            self.prevent_network_gateway_port_deletion(context, port)
        super(TestNetworkGatewayPlugin, self).delete_port(context, id)
