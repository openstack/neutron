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
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils

from neutron.api.v2 import attributes
from neutron import manager
from neutron.pecan_wsgi.controllers import resource
from neutron import policy
from neutron.tests.functional.pecan_wsgi import test_functional


class TestEnforcementHooks(test_functional.PecanFunctionalTest):

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

    def test_quota_enforcement(self):
        # TODO(kevinbenton): this test should do something
        pass


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
