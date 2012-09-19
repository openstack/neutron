# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the spec

import logging
import os
import unittest
import uuid

import mock
import webtest

from webob import exc

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.api.v2 import resource as wsgi_resource
from quantum.api.v2 import router
from quantum.common import config
from quantum.common import exceptions as q_exc
from quantum import context
from quantum.extensions.extensions import PluginAwareExtensionManager
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.openstack.common.notifier import api as notifer_api


LOG = logging.getLogger(__name__)


def _uuid():
    return str(uuid.uuid4())

ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')
EXTDIR = os.path.join(ROOTDIR, 'unit/extensions')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def _get_path(resource, id=None, action=None, fmt=None):
    path = '/%s' % resource

    if id is not None:
        path = path + '/%s' % id

    if action is not None:
        path = path + '/%s' % action

    if fmt is not None:
        path = path + '.%s' % fmt

    return path


class V2WsgiResourceTestCase(unittest.TestCase):
    def test_unmapped_quantum_error(self):
        controller = mock.MagicMock()
        controller.test.side_effect = q_exc.QuantumException()

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPInternalServerError.code)

    def test_mapped_quantum_error(self):
        controller = mock.MagicMock()
        controller.test.side_effect = q_exc.QuantumException()

        faults = {q_exc.QuantumException: exc.HTTPGatewayTimeout}
        resource = webtest.TestApp(wsgi_resource.Resource(controller,
                                                          faults=faults))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPGatewayTimeout.code)

    def test_http_error(self):
        controller = mock.MagicMock()
        controller.test.side_effect = exc.HTTPGatewayTimeout()

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPGatewayTimeout.code)

    def test_unhandled_error(self):
        controller = mock.MagicMock()
        controller.test.side_effect = Exception()

        resource = webtest.TestApp(wsgi_resource.Resource(controller))

        environ = {'wsgiorg.routing_args': (None, {'action': 'test'})}
        res = resource.get('', extra_environ=environ, expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPInternalServerError.code)


class ResourceIndexTestCase(unittest.TestCase):
    def test_index_json(self):
        index = webtest.TestApp(router.Index({'foo': 'bar'}))
        res = index.get('')

        self.assertTrue('resources' in res.json)
        self.assertTrue(len(res.json['resources']) == 1)

        resource = res.json['resources'][0]
        self.assertTrue('collection' in resource)
        self.assertTrue(resource['collection'] == 'bar')

        self.assertTrue('name' in resource)
        self.assertTrue(resource['name'] == 'foo')

        self.assertTrue('links' in resource)
        self.assertTrue(len(resource['links']) == 1)

        link = resource['links'][0]
        self.assertTrue('href' in link)
        self.assertTrue(link['href'] == 'http://localhost/bar')
        self.assertTrue('rel' in link)
        self.assertTrue(link['rel'] == 'self')


class APIv2TestBase(unittest.TestCase):
    def setUp(self):
        plugin = 'quantum.quantum_plugin_base_v2.QuantumPluginBaseV2'
        # Ensure 'stale' patched copies of the plugin are never returned
        QuantumManager._instance = None
        # Ensure existing ExtensionManager is not used
        PluginAwareExtensionManager._instance = None
        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        api = router.APIRouter()
        self.api = webtest.TestApp(api)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        cfg.CONF.reset()


class APIv2TestCase(APIv2TestBase):
    # NOTE(jkoelker) This potentially leaks the mock object if the setUp
    #                raises without being caught. Using unittest2
    #                or dropping 2.6 support so we can use addCleanup
    #                will get around this.
    def _do_field_list(self, resource, base_fields):
        attr_info = attributes.RESOURCE_ATTRIBUTE_MAP[resource]
        policy_attrs = [name for (name, info) in attr_info.items()
                        if info.get('required_by_policy')]
        fields = base_fields
        fields.extend(policy_attrs)
        return fields

    def test_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': 'foo'})
        fields = self._do_field_list('networks', ['foo'])
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=fields)

    def test_fields_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        fields = self._do_field_list('networks', ['foo', 'bar'])
        self.api.get(_get_path('networks'), {'fields': ['foo', 'bar']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=fields)

    def test_fields_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        fields = self._do_field_list('networks', ['foo'])
        self.api.get(_get_path('networks'), {'fields': ['foo', '']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=fields)

    def test_fields_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ''})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=[])

    def test_fields_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ['', '']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=[])

    def test_filters(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar'})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ''})
        filters = {}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['', '']})
        filters = {}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['bar', '']})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_multiple_values(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['bar', 'bar2']})
        filters = {'foo': ['bar', 'bar2']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar',
                                             'foo2': 'bar2'})
        filters = {'foo': ['bar'], 'foo2': ['bar2']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY)

    def test_filters_with_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar', 'fields': 'foo'})
        filters = {'foo': ['bar']}
        fields = self._do_field_list('networks', ['foo'])
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=fields)

    def test_filters_with_convert_to(self):
        instance = self.plugin.return_value
        instance.get_ports.return_value = []

        self.api.get(_get_path('ports'), {'admin_state_up': 'true'})
        filters = {'admin_state_up': [True]}
        instance.get_ports.assert_called_once_with(mock.ANY,
                                                   filters=filters,
                                                   fields=mock.ANY)

    def test_filters_with_convert_list_to(self):
        instance = self.plugin.return_value
        instance.get_ports.return_value = []

        self.api.get(_get_path('ports'),
                     {'fixed_ips': ['ip_address=foo', 'subnet_id=bar']})
        filters = {'fixed_ips': {'ip_address': ['foo'], 'subnet_id': ['bar']}}
        instance.get_ports.assert_called_once_with(mock.ANY,
                                                   filters=filters,
                                                   fields=mock.ANY)


# Note: since all resources use the same controller and validation
# logic, we actually get really good coverage from testing just networks.
class JSONV2TestCase(APIv2TestBase):

    def _test_list(self, req_tenant_id, real_tenant_id):
        env = {}
        if req_tenant_id:
            env = {'quantum.context': context.Context('', req_tenant_id)}
        input_dict = {'id': str(uuid.uuid4()),
                      'name': 'net1',
                      'admin_state_up': True,
                      'status': "ACTIVE",
                      'tenant_id': real_tenant_id,
                      'shared': False,
                      'subnets': []}
        return_value = [input_dict]
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value

        res = self.api.get(_get_path('networks'), extra_environ=env)
        self.assertTrue('networks' in res.json)
        if not req_tenant_id or req_tenant_id == real_tenant_id:
            # expect full list returned
            self.assertEqual(len(res.json['networks']), 1)
            output_dict = res.json['networks'][0]
            input_dict['shared'] = False
            self.assertEqual(len(input_dict), len(output_dict))
            for k, v in input_dict.iteritems():
                self.assertEqual(v, output_dict[k])
        else:
            # expect no results
            self.assertEqual(len(res.json['networks']), 0)

    def test_list_noauth(self):
        self._test_list(None, _uuid())

    def test_list_keystone(self):
        tenant_id = _uuid()
        self._test_list(tenant_id, tenant_id)

    def test_list_keystone_bad(self):
        tenant_id = _uuid()
        self._test_list(tenant_id + "bad", tenant_id)

    def test_create(self):
        net_id = _uuid()
        data = {'network': {'name': 'net1', 'admin_state_up': True,
                            'tenant_id': _uuid()}}
        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), data)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('network' in res.json)
        net = res.json['network']
        self.assertEqual(net['id'], net_id)
        self.assertEqual(net['status'], "ACTIVE")

    def test_create_use_defaults(self):
        net_id = _uuid()
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid()}}
        full_input = {'network': {'admin_state_up': True,
                                  'shared': False}}
        full_input['network'].update(initial_input['network'])

        return_value = {'id': net_id, 'status': "ACTIVE"}
        return_value.update(full_input['network'])

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), initial_input)

        instance.create_network.assert_called_with(mock.ANY,
                                                   network=full_input)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('network' in res.json)
        net = res.json['network']
        self.assertEqual(net['id'], net_id)
        self.assertEqual(net['admin_state_up'], True)
        self.assertEqual(net['status'], "ACTIVE")

    def test_create_no_keystone_env(self):
        data = {'name': 'net1'}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_with_keystone_env(self):
        tenant_id = _uuid()
        net_id = _uuid()
        env = {'quantum.context': context.Context('', tenant_id)}
        # tenant_id should be fetched from env
        initial_input = {'network': {'name': 'net1'}}
        full_input = {'network': {'admin_state_up': True,
                      'shared': False, 'tenant_id': tenant_id}}
        full_input['network'].update(initial_input['network'])

        return_value = {'id': net_id, 'status': "ACTIVE"}
        return_value.update(full_input['network'])

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), initial_input,
                                 extra_environ=env)

        instance.create_network.assert_called_with(mock.ANY,
                                                   network=full_input)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)

    def test_create_bad_keystone_tenant(self):
        tenant_id = _uuid()
        data = {'network': {'name': 'net1', 'tenant_id': tenant_id}}
        env = {'quantum.context': context.Context('', tenant_id + "bad")}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True,
                                 extra_environ=env)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_no_body(self):
        data = {'whoa': None}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_no_resource(self):
        res = self.api.post_json(_get_path('networks'), dict(),
                                 expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_missing_attr(self):
        data = {'port': {'what': 'who', 'tenant_id': _uuid()}}
        res = self.api.post_json(_get_path('ports'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 400)

    def test_create_readonly_attr(self):
        data = {'network': {'name': 'net1', 'tenant_id': _uuid(),
                            'status': "ACTIVE"}}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 400)

    def test_create_bulk(self):
        data = {'networks': [{'name': 'net1',
                              'admin_state_up': True,
                              'tenant_id': _uuid()},
                             {'name': 'net2',
                              'admin_state_up': True,
                              'tenant_id': _uuid()}]}

        def side_effect(context, network):
            net = network.copy()
            net['network'].update({'subnets': []})
            return net['network']

        instance = self.plugin.return_value
        instance.create_network.side_effect = side_effect

        res = self.api.post_json(_get_path('networks'), data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)

    def test_create_bulk_no_networks(self):
        data = {'networks': []}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_bulk_missing_attr(self):
        data = {'ports': [{'what': 'who', 'tenant_id': _uuid()}]}
        res = self.api.post_json(_get_path('ports'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 400)

    def test_create_bulk_partial_body(self):
        data = {'ports': [{'device_id': 'device_1',
                           'tenant_id': _uuid()},
                          {'tenant_id': _uuid()}]}
        res = self.api.post_json(_get_path('ports'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 400)

    def test_create_attr_not_specified(self):
        net_id = _uuid()
        tenant_id = _uuid()
        device_id = _uuid()
        initial_input = {'port': {'name': '', 'network_id': net_id,
                                  'tenant_id': tenant_id,
                                  'device_id': device_id,
                                  'admin_state_up': True}}
        full_input = {'port': {'admin_state_up': True,
                               'mac_address': attributes.ATTR_NOT_SPECIFIED,
                               'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                               'device_owner': ''}}
        full_input['port'].update(initial_input['port'])
        return_value = {'id': _uuid(), 'status': 'ACTIVE',
                        'admin_state_up': True,
                        'mac_address': 'ca:fe:de:ad:be:ef',
                        'device_id': device_id,
                        'device_owner': ''}
        return_value.update(initial_input['port'])

        instance = self.plugin.return_value
        instance.get_network.return_value = {'tenant_id': unicode(tenant_id)}
        instance.create_port.return_value = return_value
        res = self.api.post_json(_get_path('ports'), initial_input)

        instance.create_port.assert_called_with(mock.ANY, port=full_input)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('port' in res.json)
        port = res.json['port']
        self.assertEqual(port['network_id'], net_id)
        self.assertEqual(port['mac_address'], 'ca:fe:de:ad:be:ef')

    def test_create_return_extra_attr(self):
        net_id = _uuid()
        data = {'network': {'name': 'net1', 'admin_state_up': True,
                            'tenant_id': _uuid()}}
        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id, 'v2attrs:something': "123"}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), data)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('network' in res.json)
        net = res.json['network']
        self.assertEqual(net['id'], net_id)
        self.assertEqual(net['status'], "ACTIVE")
        self.assertFalse('v2attrs:something' in net)

    def test_fields(self):
        return_value = {'name': 'net1', 'admin_state_up': True,
                        'subnets': []}

        instance = self.plugin.return_value
        instance.get_network.return_value = return_value

        self.api.get(_get_path('networks', id=str(uuid.uuid4())))

    def _test_delete(self, req_tenant_id, real_tenant_id, expected_code,
                     expect_errors=False):
        env = {}
        if req_tenant_id:
            env = {'quantum.context': context.Context('', req_tenant_id)}
        instance = self.plugin.return_value
        instance.get_network.return_value = {'tenant_id': real_tenant_id,
                                             'shared': False}
        instance.delete_network.return_value = None

        res = self.api.delete(_get_path('networks', id=str(uuid.uuid4())),
                              extra_environ=env, expect_errors=expect_errors)
        self.assertEqual(res.status_int, expected_code)

    def test_delete_noauth(self):
        self._test_delete(None, _uuid(), exc.HTTPNoContent.code)

    def test_delete_keystone(self):
        tenant_id = _uuid()
        self._test_delete(tenant_id, tenant_id, exc.HTTPNoContent.code)

    def test_delete_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_delete(tenant_id + "bad", tenant_id,
                          exc.HTTPNotFound.code, expect_errors=True)

    def _test_get(self, req_tenant_id, real_tenant_id, expected_code,
                  expect_errors=False):
        env = {}
        shared = False
        if req_tenant_id:
            env = {'quantum.context': context.Context('', req_tenant_id)}
            if req_tenant_id.endswith('another'):
                shared = True
                env['quantum.context'].roles = ['tenant_admin']

        data = {'tenant_id': real_tenant_id, 'shared': shared}
        instance = self.plugin.return_value
        instance.get_network.return_value = data

        res = self.api.get(_get_path('networks',
                           id=str(uuid.uuid4())),
                           extra_environ=env,
                           expect_errors=expect_errors)
        self.assertEqual(res.status_int, expected_code)

    def test_get_noauth(self):
        self._test_get(None, _uuid(), 200)

    def test_get_keystone(self):
        tenant_id = _uuid()
        self._test_get(tenant_id, tenant_id, 200)

    def test_get_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_get(tenant_id + "bad", tenant_id,
                       exc.HTTPNotFound.code, expect_errors=True)

    def test_get_keystone_shared_network(self):
        tenant_id = _uuid()
        self._test_get(tenant_id + "another", tenant_id, 200)

    def _test_update(self, req_tenant_id, real_tenant_id, expected_code,
                     expect_errors=False):
        env = {}
        if req_tenant_id:
            env = {'quantum.context': context.Context('', req_tenant_id)}
        # leave out 'name' field intentionally
        data = {'network': {'admin_state_up': True}}
        return_value = {'subnets': []}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.get_network.return_value = {'tenant_id': real_tenant_id,
                                             'shared': False}
        instance.update_network.return_value = return_value

        res = self.api.put_json(_get_path('networks',
                                id=str(uuid.uuid4())),
                                data,
                                extra_environ=env,
                                expect_errors=expect_errors)
        self.assertEqual(res.status_int, expected_code)

    def test_update_noauth(self):
        self._test_update(None, _uuid(), 200)

    def test_update_keystone(self):
        tenant_id = _uuid()
        self._test_update(tenant_id, tenant_id, 200)

    def test_update_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_update(tenant_id + "bad", tenant_id,
                          exc.HTTPNotFound.code, expect_errors=True)

    def test_update_readonly_field(self):
        data = {'network': {'status': "NANANA"}}
        res = self.api.put_json(_get_path('networks', id=_uuid()), data,
                                expect_errors=True)
        self.assertEqual(res.status_int, 400)


class V2Views(unittest.TestCase):
    def _view(self, keys, collection, resource):
        data = dict((key, 'value') for key in keys)
        data['fake'] = 'value'
        attr_info = attributes.RESOURCE_ATTRIBUTE_MAP[collection]
        controller = base.Controller(None, collection, resource, attr_info)
        res = controller._view(data)
        self.assertTrue('fake' not in res)
        for key in keys:
            self.assertTrue(key in res)

    def test_network(self):
        keys = ('id', 'name', 'subnets', 'admin_state_up', 'status',
                'tenant_id')
        self._view(keys, 'networks', 'network')

    def test_port(self):
        keys = ('id', 'network_id', 'mac_address', 'fixed_ips',
                'device_id', 'admin_state_up', 'tenant_id', 'status')
        self._view(keys, 'ports', 'port')

    def test_subnet(self):
        keys = ('id', 'network_id', 'tenant_id', 'gateway_ip',
                'ip_version', 'cidr', 'enable_dhcp')
        self._view(keys, 'subnets', 'subnet')


class NotificationTest(APIv2TestBase):
    def _resource_op_notifier(self, opname, resource, expected_errors=False):
        initial_input = {resource: {'name': 'myname'}}
        instance = self.plugin.return_value
        instance.get_networks.return_value = initial_input
        expected_code = exc.HTTPCreated.code
        with mock.patch.object(notifer_api, 'notify') as mynotifier:
            if opname == 'create':
                initial_input[resource]['tenant_id'] = _uuid()
                res = self.api.post_json(
                    _get_path('networks'), initial_input, expected_errors)
            if opname == 'update':
                res = self.api.put_json(
                    _get_path('networks', id=_uuid()),
                    initial_input, expect_errors=expected_errors)
                expected_code = exc.HTTPOk.code
            if opname == 'delete':
                initial_input[resource]['tenant_id'] = _uuid()
                res = self.api.delete(
                    _get_path('networks', id=_uuid()),
                    expect_errors=expected_errors)
                expected_code = exc.HTTPNoContent.code
            expected = [mock.call(mock.ANY,
                                  'network.' + cfg.CONF.host,
                                  resource + "." + opname + ".start",
                                  'INFO',
                                  mock.ANY),
                        mock.call(mock.ANY,
                                  'network.' + cfg.CONF.host,
                                  resource + "." + opname + ".end",
                                  'INFO',
                                  mock.ANY)]
            self.assertEqual(expected, mynotifier.call_args_list)
        self.assertEqual(res.status_int, expected_code)

    def test_network_create_notifer(self):
        self._resource_op_notifier('create', 'network')

    def test_network_delete_notifer(self):
        self._resource_op_notifier('delete', 'network')

    def test_network_update_notifer(self):
        self._resource_op_notifier('update', 'network')


class QuotaTest(APIv2TestBase):
    def test_create_network_quota(self):
        cfg.CONF.set_override('quota_network', 1, group='QUOTAS')
        net_id = _uuid()
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid()}}
        full_input = {'network': {'admin_state_up': True, 'subnets': []}}
        full_input['network'].update(initial_input['network'])

        return_value = {'id': net_id, 'status': "ACTIVE"}
        return_value.update(full_input['network'])
        return_networks = {'networks': [return_value]}
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_networks
        res = self.api.post_json(
            _get_path('networks'), initial_input, expect_errors=True)
        instance.get_networks.assert_called_with(mock.ANY,
                                                 filters=mock.ANY)
        self.assertTrue("Quota exceeded for resources" in
                        res.json['QuantumError'])

    def test_create_network_quota_without_limit(self):
        cfg.CONF.set_override('quota_network', -1, group='QUOTAS')
        net_id = _uuid()
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid()}}
        full_input = {'network': {'admin_state_up': True, 'subnets': []}}
        full_input['network'].update(initial_input['network'])
        return_networks = []
        for i in xrange(0, 3):
            return_value = {'id': net_id + str(i), 'status': "ACTIVE"}
            return_value.update(full_input['network'])
            return_networks.append(return_value)
        self.assertEquals(3, len(return_networks))
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_networks
        res = self.api.post_json(
            _get_path('networks'), initial_input)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)


class ExtensionTestCase(unittest.TestCase):
    # NOTE(jkoelker) This potentially leaks the mock object if the setUp
    #                raises without being caught. Using unittest2
    #                or dropping 2.6 support so we can use addCleanup
    #                will get around this.
    def setUp(self):
        plugin = 'quantum.quantum_plugin_base_v2.QuantumPluginBaseV2'

        # Ensure 'stale' patched copies of the plugin are never returned
        QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        PluginAwareExtensionManager._instance = None

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        # Create the default configurations
        args = ['--config-file', etcdir('quantum.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', plugin)
        cfg.CONF.set_override('api_extensions_path', EXTDIR)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        # Instantiate mock plugin and enable the V2attributes extension
        QuantumManager.get_plugin().supported_extension_aliases = ["v2attrs"]

        api = router.APIRouter()
        self.api = webtest.TestApp(api)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        cfg.CONF.reset()
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_extended_create(self):
        net_id = _uuid()
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid(),
                                     'v2attrs:something_else': "abc"}}
        data = {'network': {'admin_state_up': True, 'shared': False}}
        data['network'].update(initial_input['network'])

        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id,
                        'v2attrs:something': "123"}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), initial_input)

        instance.create_network.assert_called_with(mock.ANY,
                                                   network=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        self.assertTrue('network' in res.json)
        net = res.json['network']
        self.assertEqual(net['id'], net_id)
        self.assertEqual(net['status'], "ACTIVE")
        self.assertEqual(net['v2attrs:something'], "123")
        self.assertFalse('v2attrs:something_else' in net)
