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
import unittest
import uuid

import mock
import webtest

from webob import exc

from quantum.common import exceptions as q_exc
from quantum.api.v2 import resource as wsgi_resource
from quantum.api.v2 import router
from quantum.api.v2 import views


LOG = logging.getLogger(__name__)


def _get_path(resource, id=None, fmt=None):
    path = '/%s' % resource

    if id is not None:
        path = path + '/%s' % id

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
        self.assertEqual(res.status_int,  exc.HTTPInternalServerError.code)

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


class APIv2TestCase(unittest.TestCase):
    # NOTE(jkoelker) This potentially leaks the mock object if the setUp
    #                raises without being caught. Using unittest2
    #                or dropping 2.6 support so we can use addCleanup
    #                will get around this.
    def setUp(self):
        plugin = 'quantum.quantum_plugin_base_v2.QuantumPluginBaseV2'
        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        api = router.APIRouter({'plugin_provider': plugin})
        self.api = webtest.TestApp(api)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None

    def test_verbose_attr(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': 'foo'})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=['foo'])

    def test_multiple_verbose_attr(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': ['foo', 'bar']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=['foo',
                                                               'bar'])

    def test_verbose_false_str(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': 'false'})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=False)

    def test_verbose_true_str(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': 'true'})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=True)

    def test_verbose_true_trump_attr(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': ['true', 'foo']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=True)

    def test_verbose_false_trump_attr(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': ['false', 'foo']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=False)

    def test_verbose_true_trump_false(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'verbose': ['true', 'false']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=mock.ANY,
                                                      verbose=True)

    def test_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': 'foo'})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=['foo'],
                                                      verbose=mock.ANY)

    def test_fields_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ['foo', 'bar']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=['foo', 'bar'],
                                                      verbose=mock.ANY)

    def test_fields_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ['foo', '']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=['foo'],
                                                      verbose=mock.ANY)

    def test_fields_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ''})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=[],
                                                      verbose=mock.ANY)

    def test_fields_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ['', '']})
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=mock.ANY,
                                                      fields=[],
                                                      verbose=mock.ANY)

    def test_filters(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar'})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ''})
        filters = {}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['', '']})
        filters = {}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['bar', '']})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_multiple_values(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': ['bar', 'bar2']})
        filters = {'foo': ['bar', 'bar2']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar',
                                             'foo2': 'bar2'})
        filters = {'foo': ['bar'], 'foo2': ['bar2']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=mock.ANY)

    def test_filters_with_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar', 'fields': 'foo'})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=['foo'],
                                                      verbose=mock.ANY)

    def test_filters_with_verbose(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar',
                                             'verbose': 'true'})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=mock.ANY,
                                                      verbose=True)

    def test_filters_with_fields_and_verbose(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'foo': 'bar',
                                             'fields': 'foo',
                                             'verbose': 'true'})
        filters = {'foo': ['bar']}
        instance.get_networks.assert_called_once_with(mock.ANY,
                                                      filters=filters,
                                                      fields=['foo'],
                                                      verbose=True)


class JSONV2TestCase(APIv2TestCase):
    def test_list(self):
        return_value = [{'network': {'name': 'net1',
                                     'admin_state_up': True,
                                     'subnets': []}}]
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value

        res = self.api.get(_get_path('networks'))
        self.assertTrue('networks' in res.json)

    def test_create(self):
        data = {'network': {'name': 'net1', 'admin_state_up': True}}
        return_value = {'subnets': []}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value

        res = self.api.post_json(_get_path('networks'), data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)

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
        data = {'network': {'what': 'who'}}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 422)

    def test_create_bulk(self):
        data = {'networks': [{'name': 'net1', 'admin_state_up': True},
                             {'name': 'net2', 'admin_state_up': True}]}

        def side_effect(context, network):
            nets = network.copy()
            for net in nets['networks']:
                net.update({'subnets': []})
            return nets

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
        data = {'networks': [{'what': 'who'}]}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 422)

    def test_create_bulk_partial_body(self):
        data = {'networks': [{'name': 'net1', 'admin_state_up': True},
                             {}]}
        res = self.api.post_json(_get_path('networks'), data,
                                 expect_errors=True)
        self.assertEqual(res.status_int, 422)

    def test_fields(self):
        return_value = {'name': 'net1', 'admin_state_up': True,
                        'subnets': []}

        instance = self.plugin.return_value
        instance.get_network.return_value = return_value

        self.api.get(_get_path('networks', id=str(uuid.uuid4())))

    def test_delete(self):
        instance = self.plugin.return_value
        instance.delete_network.return_value = None

        res = self.api.delete(_get_path('networks', id=str(uuid.uuid4())))
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_update(self):
        data = {'network': {'name': 'net1', 'admin_state_up': True}}
        return_value = {'subnets': []}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.update_network.return_value = return_value

        self.api.put_json(_get_path('networks',
                                    id=str(uuid.uuid4())), data)


class V2Views(unittest.TestCase):
    def _view(self, keys, func):
        data = dict((key, 'value') for key in keys)
        data['fake'] = 'value'
        res = func(data)
        self.assertTrue('fake' not in res)
        for key in keys:
            self.assertTrue(key in res)

    def test_resource(self):
        res = views.resource({'one': 1, 'two': 2}, ['one'])
        self.assertTrue('one' in res)
        self.assertTrue('two' not in res)

    def test_network(self):
        keys = ('id', 'name', 'subnets', 'admin_state_up', 'op_status',
                'tenant_id', 'mac_ranges')
        self._view(keys, views.network)

    def test_port(self):
        keys = ('id', 'network_id', 'mac_address', 'fixed_ips',
                'device_id', 'admin_state_up', 'tenant_id', 'op_status')
        self._view(keys, views.port)

    def test_subnet(self):
        keys = ('id', 'network_id', 'tenant_id', 'gateway_ip',
                'ip_version', 'prefix')
        self._view(keys, views.subnet)
