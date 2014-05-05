#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy

import mock
from webob import exc

from neutron.extensions import group_policy as gpolicy
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class GroupPolicyExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(GroupPolicyExtensionTestCase, self).setUp()
        self._setUpExtension(
            'neutron.extensions.group_policy.GroupPolicyPluginBase',
            constants.GROUP_POLICY, gpolicy.RESOURCE_ATTRIBUTE_MAP,
            gpolicy.Group_policy, 'gp', plural_mappings={})

    def test_create_endpoint(self):
        endpoint_id = _uuid()
        data = {'endpoint': {'name': 'ep1',
                             'endpoint_group_id': _uuid(),
                             'tenant_id': _uuid(),
                             'description': ''}}
        return_value = copy.copy(data['endpoint'])
        return_value.update({'id': endpoint_id})

        instance = self.plugin.return_value
        instance.create_endpoint.return_value = return_value
        res = self.api.post(_get_path('gp/endpoints', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_endpoint.assert_called_with(mock.ANY,
                                                    endpoint=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(res['endpoint'], return_value)

    def test_list_endpoints(self):
        endpoint_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': endpoint_id}]

        instance = self.plugin.return_value
        instance.get_endpoints.return_value = return_value

        res = self.api.get(_get_path('gp/endpoints', fmt=self.fmt))

        instance.get_endpoints.assert_called_with(mock.ANY,
                                                  fields=mock.ANY,
                                                  filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_endpoint(self):
        endpoint_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': endpoint_id}

        instance = self.plugin.return_value
        instance.get_endpoint.return_value = return_value

        res = self.api.get(_get_path('gp/endpoints',
                                     id=endpoint_id, fmt=self.fmt))

        instance.get_endpoint.assert_called_with(mock.ANY,
                                                 endpoint_id,
                                                 fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(res['endpoint'], return_value)

    def test_update_endpoint(self):
        endpoint_id = _uuid()
        update_data = {'endpoint': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': endpoint_id}

        instance = self.plugin.return_value
        instance.update_endpoint.return_value = return_value

        res = self.api.put(_get_path('gp/endpoints',
                                     id=endpoint_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_endpoint.assert_called_with(
            mock.ANY, endpoint_id, endpoint=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(res['endpoint'], return_value)

    def test_delete_endpoint(self):
        self._test_entity_delete('endpoint')

    def test_create_endpoint_group(self):
        endpoint_group_id = _uuid()
        data = {'endpoint_group': {'name': 'epg1',
                                   'tenant_id': _uuid(),
                                   'description': '',
                                   'bridge_domain_id': _uuid(),
                                   'provided_contract_scopes': [],
                                   'consumed_contract_scopes': []}}
        return_value = copy.copy(data['endpoint_group'])
        return_value.update({'id': endpoint_group_id})
        return_value.update({'bridge_domain_id': None})

        instance = self.plugin.return_value
        instance.create_endpoint_group.return_value = return_value
        res = self.api.post(_get_path('gp/endpoint_groups', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_endpoint_group.assert_called_with(mock.ANY,
                                                          endpoint_group=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(res['endpoint_group'], return_value)

    def test_list_endpoint_groups(self):
        endpoint_group_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': endpoint_group_id}]

        instance = self.plugin.return_value
        instance.get_endpoint_groups.return_value = return_value

        res = self.api.get(_get_path('gp/endpoint_groups', fmt=self.fmt))

        instance.get_endpoint_groups.assert_called_with(mock.ANY,
                                                        fields=mock.ANY,
                                                        filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_endpoint_group(self):
        endpoint_group_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': endpoint_group_id}

        instance = self.plugin.return_value
        instance.get_endpoint_group.return_value = return_value

        res = self.api.get(_get_path('gp/endpoint_groups',
                                     id=endpoint_group_id, fmt=self.fmt))

        instance.get_endpoint_group.assert_called_with(mock.ANY,
                                                       endpoint_group_id,
                                                       fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(res['endpoint_group'], return_value)

    def test_update_endpoint_group(self):
        endpoint_group_id = _uuid()
        update_data = {'endpoint_group': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': endpoint_group_id}

        instance = self.plugin.return_value
        instance.update_endpoint_group.return_value = return_value

        res = self.api.put(_get_path('gp/endpoint_groups',
                                     id=endpoint_group_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_endpoint_group.assert_called_with(
            mock.ANY, endpoint_group_id, endpoint_group=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(res['endpoint_group'], return_value)

    def test_delete_endpoint_group(self):
        self._test_entity_delete('endpoint_group')

    def test_create_policy_action(self):
        policy_action_id = _uuid()
        data = {'policy_action': {'name': 'pa1',
                                  'tenant_id': _uuid(),
                                  'action_type': 'allow',
                                  'action_value': None,
                                  'description': ''}}
        return_value = copy.copy(data['policy_action'])
        return_value.update({'id': policy_action_id})

        instance = self.plugin.return_value
        instance.create_policy_action.return_value = return_value
        res = self.api.post(_get_path('gp/policy_actions', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_policy_action.assert_called_with(mock.ANY,
                                                         policy_action=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(res['policy_action'], return_value)

    def test_list_policy_actions(self):
        policy_action_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': policy_action_id}]

        instance = self.plugin.return_value
        instance.get_policy_actions.return_value = return_value

        res = self.api.get(_get_path('gp/policy_actions', fmt=self.fmt))

        instance.get_policy_actions.assert_called_with(mock.ANY,
                                                       fields=mock.ANY,
                                                       filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_policy_action(self):
        policy_action_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': policy_action_id}

        instance = self.plugin.return_value
        instance.get_policy_action.return_value = return_value

        res = self.api.get(_get_path('gp/policy_actions',
                                     id=policy_action_id, fmt=self.fmt))

        instance.get_policy_action.assert_called_with(mock.ANY,
                                                      policy_action_id,
                                                      fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(res['policy_action'], return_value)

    def test_update_policy_action(self):
        policy_action_id = _uuid()
        update_data = {'policy_action': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': policy_action_id}

        instance = self.plugin.return_value
        instance.update_policy_action.return_value = return_value

        res = self.api.put(_get_path('gp/policy_actions',
                                     id=policy_action_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_policy_action.assert_called_with(
            mock.ANY, policy_action_id, policy_action=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(res['policy_action'], return_value)

    def test_delete_policy_action(self):
        self._test_entity_delete('policy_action')

    def test_create_bridge_domain(self):
        bridge_domain_id = _uuid()
        data = {'bridge_domain': {'name': 'bd1',
                                  'tenant_id': _uuid(),
                                  'description': '',
                                  'routing_domain_id': _uuid()}}
        return_value = copy.copy(data['bridge_domain'])
        return_value.update({'id': bridge_domain_id})
        return_value.update({'routing_domain_id': None})

        instance = self.plugin.return_value
        instance.create_bridge_domain.return_value = return_value
        res = self.api.post(_get_path('gp/bridge_domains', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_bridge_domain.assert_called_with(mock.ANY,
                                                         bridge_domain=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('bridge_domain', res)
        self.assertEqual(res['bridge_domain'], return_value)

    def test_list_bridge_domains(self):
        bridge_domain_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': bridge_domain_id}]

        instance = self.plugin.return_value
        instance.get_bridge_domains.return_value = return_value

        res = self.api.get(_get_path('gp/bridge_domains', fmt=self.fmt))

        instance.get_bridge_domains.assert_called_with(mock.ANY,
                                                       fields=mock.ANY,
                                                       filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_bridge_domain(self):
        bridge_domain_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': bridge_domain_id}

        instance = self.plugin.return_value
        instance.get_bridge_domain.return_value = return_value

        res = self.api.get(_get_path('gp/bridge_domains',
                                     id=bridge_domain_id, fmt=self.fmt))

        instance.get_bridge_domain.assert_called_with(mock.ANY,
                                                      bridge_domain_id,
                                                      fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('bridge_domain', res)
        self.assertEqual(res['bridge_domain'], return_value)

    def test_update_bridge_domain(self):
        bridge_domain_id = _uuid()
        update_data = {'bridge_domain': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': bridge_domain_id}

        instance = self.plugin.return_value
        instance.update_bridge_domain.return_value = return_value

        res = self.api.put(_get_path('gp/bridge_domains',
                                     id=bridge_domain_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_bridge_domain.assert_called_with(
            mock.ANY, bridge_domain_id, bridge_domain=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('bridge_domain', res)
        self.assertEqual(res['bridge_domain'], return_value)

    def test_delete_bridge_domain(self):
        self._test_entity_delete('bridge_domain')

    def test_create_routing_domain(self):
        routing_domain_id = _uuid()
        data = {'routing_domain': {'name': 'rd1',
                                   'tenant_id': _uuid(),
                                   'description': '',
                                   'ip_version': 4,
                                   'ip_supernet': '10.0.0.0/8',
                                   'subnet_prefix_length': 16}}
        return_value = copy.copy(data['routing_domain'])
        return_value.update({'id': routing_domain_id})

        instance = self.plugin.return_value
        instance.create_routing_domain.return_value = return_value
        res = self.api.post(_get_path('gp/routing_domains', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_routing_domain.assert_called_with(mock.ANY,
                                                          routing_domain=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('routing_domain', res)
        self.assertEqual(res['routing_domain'], return_value)

    def test_list_routing_domains(self):
        routing_domain_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': routing_domain_id}]

        instance = self.plugin.return_value
        instance.get_routing_domains.return_value = return_value

        res = self.api.get(_get_path('gp/routing_domains', fmt=self.fmt))

        instance.get_routing_domains.assert_called_with(mock.ANY,
                                                        fields=mock.ANY,
                                                        filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_routing_domain(self):
        routing_domain_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': routing_domain_id}

        instance = self.plugin.return_value
        instance.get_routing_domain.return_value = return_value

        res = self.api.get(_get_path('gp/routing_domains',
                                     id=routing_domain_id, fmt=self.fmt))

        instance.get_routing_domain.assert_called_with(mock.ANY,
                                                       routing_domain_id,
                                                       fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('routing_domain', res)
        self.assertEqual(res['routing_domain'], return_value)

    def test_update_routing_domain(self):
        routing_domain_id = _uuid()
        update_data = {'routing_domain': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': routing_domain_id}

        instance = self.plugin.return_value
        instance.update_routing_domain.return_value = return_value

        res = self.api.put(_get_path('gp/routing_domains',
                                     id=routing_domain_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_routing_domain.assert_called_with(
            mock.ANY, routing_domain_id, routing_domain=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('routing_domain', res)
        self.assertEqual(res['routing_domain'], return_value)

    def test_delete_routing_domain(self):
        self._test_entity_delete('routing_domain')
