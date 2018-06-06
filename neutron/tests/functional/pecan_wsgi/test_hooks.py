# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
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

import mock
from neutron_lib.api import attributes
from neutron_lib.callbacks import events
from neutron_lib import context
from neutron_lib.db import constants as db_const
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils

from neutron.db.quota import driver as quota_driver
from neutron import manager
from neutron.pecan_wsgi.controllers import resource
from neutron import policy
from neutron.tests.functional.pecan_wsgi import test_functional


class TestOwnershipHook(test_functional.PecanFunctionalTest):

    def test_network_ownership_check(self):
        net_response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'})
        network_id = jsonutils.loads(net_response.body)['network']['id']
        port_response = self.app.post_json(
            '/v2.0/ports.json',
            params={'port': {'network_id': network_id,
                             'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(201, port_response.status_int)


class TestQueryParametersHook(test_functional.PecanFunctionalTest):

    def test_if_match_on_update(self):
        net_response = jsonutils.loads(self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'}).body)
        network_id = net_response['network']['id']
        response = self.app.put_json('/v2.0/networks/%s.json' % network_id,
                                     params={'network': {'name': 'cat'}},
                                     headers={'X-Project-Id': 'tenid',
                                              'If-Match': 'revision_number=0'},
                                     expect_errors=True)
        # revision plugin not supported by default, so badrequest
        self.assertEqual(400, response.status_int)


class TestQueryParametersHookWithRevision(test_functional.PecanFunctionalTest):

    def setUp(self):
        cfg.CONF.set_override('service_plugins', ['revisions'])
        super(TestQueryParametersHookWithRevision, self).setUp()

    def test_if_match_on_update(self):
        net_response = jsonutils.loads(self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'}).body)
        network_id = net_response['network']['id']
        rev = net_response['network']['revision_number']
        stale = rev - 1

        response = self.app.put_json(
            '/v2.0/networks/%s.json' % network_id,
            params={'network': {'name': 'cat'}},
            headers={'X-Project-Id': 'tenid',
                     'If-Match': 'revision_number=%s' % stale},
            expect_errors=True)
        self.assertEqual(412, response.status_int)
        self.app.put_json('/v2.0/networks/%s.json' % network_id,
                          params={'network': {'name': 'cat'}},
                          headers={'X-Project-Id': 'tenid',
                                   'If-Match': 'revision_number=%s' % rev})


class TestQuotaEnforcementHook(test_functional.PecanFunctionalTest):

    def test_quota_enforcement_single(self):
        ctx = context.get_admin_context()
        quota_driver.DbQuotaDriver.update_quota_limit(
            ctx, 'tenid', 'network', 1)
        # There is enough headroom for creating a network
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)
        # But a second request will fail
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh-2'}},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(response.status_int, 409)

    def test_quota_enforcement_bulk_request(self):
        ctx = context.get_admin_context()
        quota_driver.DbQuotaDriver.update_quota_limit(
            ctx, 'tenid', 'network', 3)
        # There is enough headroom for a bulk request creating 2 networks
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [
                {'name': 'meh1'},
                {'name': 'meh2'}]},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)
        # But it won't be possible to create 2 more networks...
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [
                {'name': 'meh3'},
                {'name': 'meh4'}]},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(response.status_int, 409)


class TestPolicyEnforcementHook(test_functional.PecanFunctionalTest):

    FAKE_RESOURCE = {
        'mehs': {
            'id': {'allow_post': False, 'allow_put': False,
                   'is_visible': True, 'primary_key': True},
            'attr': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': ''},
            'restricted_attr': {'allow_post': True, 'allow_put': True,
                                'is_visible': True, 'default': ''},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'validate': {'type:string':
                                       db_const.PROJECT_ID_FIELD_SIZE},
                          'is_visible': True}
        }
    }

    def setUp(self):
        # Create a controller for a fake resource. This will make the tests
        # independent from the evolution of the API (so if one changes the API
        # or the default policies there won't be any risk of breaking these
        # tests, or at least I hope so)
        super(TestPolicyEnforcementHook, self).setUp()
        self.mock_plugin = mock.Mock()
        attributes.RESOURCES.update(self.FAKE_RESOURCE)
        manager.NeutronManager.set_plugin_for_resource('mehs',
                                                       self.mock_plugin)
        fake_controller = resource.CollectionsController('mehs', 'meh')
        manager.NeutronManager.set_controller_for_resource(
            'mehs', fake_controller)
        # Inject policies for the fake resource
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'create_meh': '',
                 'update_meh': 'rule:admin_only',
                 'delete_meh': 'rule:admin_only',
                 'get_meh': 'rule:admin_only or field:mehs:id=xxx',
                 'get_meh:restricted_attr': 'rule:admin_only'}),
            overwrite=False)

    def test_before_on_create_authorized(self):
        # Mock a return value for an hypothetical create operation
        self.mock_plugin.create_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        response = self.app.post_json('/v2.0/mehs.json',
                                      params={'meh': {'attr': 'meh'}},
                                      headers={'X-Project-Id': 'tenid'})
        # We expect this operation to succeed
        self.assertEqual(201, response.status_int)
        self.assertEqual(0, self.mock_plugin.get_meh.call_count)
        self.assertEqual(1, self.mock_plugin.create_meh.call_count)

    def test_before_on_put_not_authorized(self):
        # The policy hook here should load the resource, and therefore we must
        # mock a get response
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'before', and the
        # plugin method should not be called at all
        response = self.app.put_json('/v2.0/mehs/xxx.json',
                                     params={'meh': {'attr': 'meh'}},
                                     headers={'X-Project-Id': 'tenid'},
                                     expect_errors=True)
        self.assertEqual(403, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)
        self.assertEqual(0, self.mock_plugin.update_meh.call_count)

    def test_before_on_put_not_found_when_not_authorized_to_get(self):
        # the user won't even have permission to view this resource
        # so the error on unauthorized updates should be translated into
        # a 404
        self.mock_plugin.get_meh.return_value = {
            'id': 'yyy',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        response = self.app.put_json('/v2.0/mehs/yyy.json',
                                     params={'meh': {'attr': 'meh'}},
                                     headers={'X-Project-Id': 'tenid'},
                                     expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)
        self.assertEqual(0, self.mock_plugin.update_meh.call_count)

    def test_before_on_delete_not_authorized(self):
        # The policy hook here should load the resource, and therefore we must
        # mock a get response
        self.mock_plugin.delete_meh.return_value = None
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'before', and the
        # plugin method should not be called
        response = self.app.delete_json('/v2.0/mehs/xxx.json',
                                        headers={'X-Project-Id': 'tenid'},
                                        expect_errors=True)
        self.assertEqual(403, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)
        self.assertEqual(0, self.mock_plugin.delete_meh.call_count)

    def test_after_on_get_not_found(self):
        # The GET test policy will deny access to anything whose id is not
        # 'xxx', so the following request should be forbidden and presented
        # to the user as an HTTPNotFound
        self.mock_plugin.get_meh.return_value = {
            'id': 'yyy',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'after', and the
        # plugin method should be called
        response = self.app.get('/v2.0/mehs/yyy.json',
                                headers={'X-Project-Id': 'tenid'},
                                expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)

    def test_after_on_get_excludes_admin_attribute(self):
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        response = self.app.get('/v2.0/mehs/xxx.json',
                                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)
        json_response = jsonutils.loads(response.body)
        self.assertNotIn('restricted_attr', json_response['meh'])

    def test_after_on_list_excludes_admin_attribute(self):
        self.mock_plugin.get_mehs.return_value = [{
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}]
        response = self.app.get('/v2.0/mehs',
                                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)
        json_response = jsonutils.loads(response.body)
        self.assertNotIn('restricted_attr', json_response['mehs'][0])

    def test_after_inits_policy(self):
        self.mock_plugin.get_mehs.return_value = [{
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}]
        policy.reset()
        response = self.app.get('/v2.0/mehs',
                                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)


class TestMetricsNotifierHook(test_functional.PecanFunctionalTest):

    def setUp(self):
        patcher = mock.patch('neutron.pecan_wsgi.hooks.notifier.NotifierHook.'
                             '_notifier')
        self.mock_notifier = patcher.start().info
        super(TestMetricsNotifierHook, self).setUp()

    def test_post_put_delete_triggers_notification(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        payload = {'network': {'name': 'meh'}}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params=payload, headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.create.start', payload),
             mock.call(mock.ANY, 'network.create.end', json_body)],
            self.mock_notifier.mock_calls)
        self.mock_notifier.reset_mock()
        network_id = json_body['network']['id']

        payload = {'network': {'name': 'meh-2'}}
        response = self.app.put_json(
            '/v2.0/networks/%s.json' % network_id,
            params=payload, headers=req_headers)
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        # id should be in payload sent to notifier
        payload['id'] = network_id
        self.assertEqual(
            [mock.call(mock.ANY, 'network.update.start', payload),
             mock.call(mock.ANY, 'network.update.end', json_body)],
            self.mock_notifier.mock_calls)
        self.mock_notifier.reset_mock()

        before_payload = {'network_id': network_id}
        after_payload = before_payload.copy()
        after_payload['network'] = directory.get_plugin().get_network(
            context.get_admin_context(), network_id)
        response = self.app.delete(
            '/v2.0/networks/%s.json' % network_id, headers=req_headers)
        self.assertEqual(204, response.status_int)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.delete.start', before_payload),
             mock.call(mock.ANY, 'network.delete.end', after_payload)],
            self.mock_notifier.mock_calls)

    def test_bulk_create_triggers_notification(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        payload = {'networks': [{'name': 'meh_1'}, {'name': 'meh_2'}]}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params=payload,
            headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.assertEqual(2, self.mock_notifier.call_count)
        self.mock_notifier.assert_has_calls(
            [mock.call(mock.ANY, 'network.create.start', payload),
             mock.call(mock.ANY, 'network.create.end', json_body)])

    def test_bad_create_doesnt_emit_end(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        payload = {'network': {'name': 'meh'}}
        plugin = directory.get_plugin()
        with mock.patch.object(plugin, 'create_network',
                               side_effect=ValueError):
            response = self.app.post_json(
                '/v2.0/networks.json',
                params=payload, headers=req_headers,
                expect_errors=True)
        self.assertEqual(500, response.status_int)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.create.start', mock.ANY)],
            self.mock_notifier.mock_calls)

    def test_bad_update_doesnt_emit_end(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        payload = {'network': {'name': 'meh'}}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params=payload, headers=req_headers,
            expect_errors=True)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.mock_notifier.reset_mock()
        plugin = directory.get_plugin()
        with mock.patch.object(plugin, 'update_network',
                               side_effect=ValueError):
            response = self.app.put_json(
                '/v2.0/networks/%s.json' % json_body['network']['id'],
                params=payload, headers=req_headers,
                expect_errors=True)
            self.assertEqual(500, response.status_int)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.update.start', mock.ANY)],
            self.mock_notifier.mock_calls)

    def test_bad_delete_doesnt_emit_end(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        payload = {'network': {'name': 'meh'}}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params=payload, headers=req_headers,
            expect_errors=True)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.mock_notifier.reset_mock()
        plugin = directory.get_plugin()
        with mock.patch.object(plugin, 'delete_network',
                               side_effect=ValueError):
            response = self.app.delete(
                '/v2.0/networks/%s.json' % json_body['network']['id'],
                headers=req_headers, expect_errors=True)
            self.assertEqual(500, response.status_int)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.delete.start', mock.ANY)],
            self.mock_notifier.mock_calls)


class TestCallbackRegistryNotifier(test_functional.PecanFunctionalTest):

    def setUp(self):
        super(TestCallbackRegistryNotifier, self).setUp()
        patcher = mock.patch('neutron.pecan_wsgi.hooks.notifier.registry')
        self.mock_notifier = patcher.start().publish

    def _create(self, bulk=False):
        if bulk:
            body = {'networks': [{'name': 'meh-1'}, {'name': 'meh-2'}]}
        else:
            body = {'network': {'name': 'meh-1'}}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params=body, headers={'X-Project-Id': 'tenid'})
        return response.json

    def test_create(self):
        self._create()
        self.mock_notifier.assert_called_once_with(
            'network', events.BEFORE_RESPONSE, mock.ANY, payload=mock.ANY)

        payload = self.mock_notifier.call_args[1]['payload']
        self.assertEqual('network.create.end', payload.method_name)
        self.assertEqual('create_network', payload.action)
        self.assertEqual('networks', payload.collection_name)

        actual = payload.latest_state
        self.assertEqual('meh-1', actual['network']['name'])

    def test_create_bulk(self):
        self._create(bulk=True)
        self.mock_notifier.assert_called_once_with(
            'network', events.BEFORE_RESPONSE, mock.ANY, payload=mock.ANY)

        payload = self.mock_notifier.call_args[1]['payload']
        self.assertEqual('network.create.end', payload.method_name)
        self.assertEqual('create_network', payload.action)
        self.assertEqual('networks', payload.collection_name)
        actual = payload.latest_state
        self.assertEqual(2, len(actual['networks']))
        self.assertEqual('meh-1', actual['networks'][0]['name'])
        self.assertEqual('meh-2', actual['networks'][1]['name'])

    def test_update(self):
        network_id = self._create()['network']['id']
        self.mock_notifier.reset_mock()
        self.app.put_json('/v2.0/networks/%s.json' % network_id,
                          params={'network': {'name': 'new-meh'}},
                          headers={'X-Project-Id': 'tenid'})
        self.mock_notifier.assert_called_once_with(
            'network', events.BEFORE_RESPONSE, mock.ANY, payload=mock.ANY)

        payload = self.mock_notifier.call_args[1]['payload']
        self.assertEqual('network.update.end', payload.method_name)
        self.assertEqual('update_network', payload.action)
        self.assertEqual('networks', payload.collection_name)

        actual_new = payload.latest_state
        self.assertEqual('new-meh', actual_new['network']['name'])
        actual_original = payload.states[0]
        self.assertEqual(network_id, actual_original['id'])

    def test_delete(self):
        network_id = self._create()['network']['id']
        self.mock_notifier.reset_mock()
        self.app.delete(
            '/v2.0/networks/%s.json' % network_id,
            headers={'X-Project-Id': 'tenid'})
        self.mock_notifier.assert_called_once_with(
            'network', events.BEFORE_RESPONSE, mock.ANY, payload=mock.ANY)

        payload = self.mock_notifier.call_args[1]['payload']
        self.assertEqual('network.delete.end', payload.method_name)
        self.assertEqual('delete_network', payload.action)
        self.assertEqual('networks', payload.collection_name)

        actual = payload.latest_state
        self.assertEqual(network_id, actual['network']['id'])
