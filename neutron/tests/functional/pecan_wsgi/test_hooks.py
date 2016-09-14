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
from oslo_config import cfg
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from neutron.api.v2 import attributes
from neutron import context
from neutron.db.quota import driver as quota_driver
from neutron import manager
from neutron.pecan_wsgi.controllers import resource
from neutron.pecan_wsgi.hooks import policy_enforcement as pe
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
                                       attributes.TENANT_ID_MAX_LEN},
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
        attributes.RESOURCE_ATTRIBUTE_MAP.update(self.FAKE_RESOURCE)
        attributes.PLURALS['mehs'] = 'meh'
        manager.NeutronManager.set_plugin_for_resource('meh', self.mock_plugin)
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

    def test_after_on_get_not_authorized(self):
        # The GET test policy will deny access to anything whose id is not
        # 'xxx', so the following request should be forbidden
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
        self.assertEqual(403, response.status_int)
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


class DHCPNotifierTestBase(test_functional.PecanFunctionalTest):

    def setUp(self):
        # the DHCP notifier needs to be mocked so that correct operations can
        # be easily validated. For the purpose of this test it is indeed not
        # necessary that the notification is actually received and processed by
        # the agent
        patcher = mock.patch('neutron.api.rpc.agentnotifiers.'
                             'dhcp_rpc_agent_api.DhcpAgentNotifyAPI.notify')
        self.mock_notifier = patcher.start()
        super(DHCPNotifierTestBase, self).setUp()


class TestDHCPNotifierHookNegative(DHCPNotifierTestBase):

    def setUp(self):
        cfg.CONF.set_override('dhcp_agent_notification', False)
        super(TestDHCPNotifierHookNegative, self).setUp()

    def test_dhcp_notifications_disabled(self):
        self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(0, self.mock_notifier.call_count)


class TestDHCPNotifierHook(DHCPNotifierTestBase):

    def test_get_does_not_trigger_notification(self):
        self.do_request('/v2.0/networks', tenant_id='tenid')
        self.assertEqual(0, self.mock_notifier.call_count)

    def test_post_put_delete_triggers_notification(self):
        ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()

        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}}, headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        net = {'network': plugin.get_network(ctx, json_body['network']['id'])}
        self.assertEqual(1, self.mock_notifier.call_count)
        self.assertEqual(mock.call(mock.ANY, net, 'network.create.end'),
                         self.mock_notifier.mock_calls[-1])
        network_id = json_body['network']['id']

        response = self.app.put_json(
            '/v2.0/networks/%s.json' % network_id,
            params={'network': {'name': 'meh-2'}},
            headers=req_headers)
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        net = {'network': plugin.get_network(ctx, json_body['network']['id'])}
        self.assertEqual(2, self.mock_notifier.call_count)
        self.assertEqual(mock.call(mock.ANY, net, 'network.update.end'),
                         self.mock_notifier.mock_calls[-1])

        response = self.app.delete(
            '/v2.0/networks/%s.json' % network_id, headers=req_headers)
        self.assertEqual(204, response.status_int)
        self.assertEqual(3, self.mock_notifier.call_count)
        # No need to validate data content sent to the notifier as it's just
        # going to load the object from the database
        self.assertEqual(mock.call(mock.ANY, mock.ANY, 'network.delete.end'),
                         self.mock_notifier.mock_calls[-1])

    def test_bulk_create_triggers_notifications(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [{'name': 'meh_1'},
                                 {'name': 'meh_2'}]},
            headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        item_1 = json_body['networks'][0]
        item_2 = json_body['networks'][1]
        self.assertEqual(2, self.mock_notifier.call_count)
        self.mock_notifier.assert_has_calls(
            [mock.call(mock.ANY, {'network': item_1}, 'network.create.end'),
             mock.call(mock.ANY, {'network': item_2}, 'network.create.end')])


class TestNovaNotifierHook(test_functional.PecanFunctionalTest):

    def setUp(self):
        patcher = mock.patch('neutron.pecan_wsgi.hooks.notifier.NotifierHook.'
                             '_nova_notify')
        self.mock_notifier = patcher.start()
        super(TestNovaNotifierHook, self).setUp()

    def test_nova_notification_skips_on_failure(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.put_json(
            '/v2.0/networks/%s.json' % uuidutils.generate_uuid(),
            params={'network': {'name': 'meh-2'}},
            headers=req_headers,
            expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertFalse(self.mock_notifier.called)

    def test_nova_notifications_disabled(self):
        cfg.CONF.set_override('notify_nova_on_port_data_changes', False)
        self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}},
            headers={'X-Project-Id': 'tenid'})
        self.assertFalse(self.mock_notifier.called)

    def test_post_put_delete_triggers_notification(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'meh'}}, headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.mock_notifier.assert_called_once_with('create', 'network', {},
                                                   json_body)
        self.mock_notifier.reset_mock()
        network_id = json_body['network']['id']

        # NOTE(kevinbenton): the original passed into the notifier does
        # not contain all of the fields of the object. Only those required
        # by the policy engine are included.
        controller = manager.NeutronManager.get_controller_for_resource(
            'networks')
        orig = pe.fetch_resource(context.get_admin_context(), controller,
                                 'network', network_id)
        response = self.app.put_json(
            '/v2.0/networks/%s.json' % network_id,
            params={'network': {'name': 'meh-2'}},
            headers=req_headers)
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.mock_notifier.assert_called_once_with('update', 'network',
                                                   orig, json_body)
        self.mock_notifier.reset_mock()

        orig = pe.fetch_resource(context.get_admin_context(), controller,
                                 'network', network_id)
        response = self.app.delete(
            '/v2.0/networks/%s.json' % network_id, headers=req_headers)
        self.assertEqual(204, response.status_int)
        # No need to validate data content sent to the notifier as it's just
        # going to load the object from the database
        self.mock_notifier.assert_called_once_with('delete', 'network', {},
                                                   {'network': orig})

    def test_bulk_create_triggers_notifications(self):
        req_headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [{'name': 'meh_1'},
                                 {'name': 'meh_2'}]},
            headers=req_headers)
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        item_1 = json_body['networks'][0]
        item_2 = json_body['networks'][1]
        self.assertEqual(
            [mock.call('create', 'network', {}, {'network': item_1}),
             mock.call('create', 'network', {}, {'network': item_2})],
            self.mock_notifier.mock_calls)


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

        response = self.app.delete(
            '/v2.0/networks/%s.json' % network_id, headers=req_headers)
        self.assertEqual(204, response.status_int)
        payload = {'network_id': network_id}
        self.assertEqual(
            [mock.call(mock.ANY, 'network.delete.start', payload),
             mock.call(mock.ANY, 'network.delete.end', payload)],
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
        plugin = manager.NeutronManager.get_plugin()
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
        plugin = manager.NeutronManager.get_plugin()
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
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(plugin, 'delete_network',
                               side_effect=ValueError):
            response = self.app.delete(
                '/v2.0/networks/%s.json' % json_body['network']['id'],
                headers=req_headers, expect_errors=True)
            self.assertEqual(500, response.status_int)
        self.assertEqual(
            [mock.call(mock.ANY, 'network.delete.start', mock.ANY)],
            self.mock_notifier.mock_calls)
