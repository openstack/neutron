# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

    def test_create_endpoint_group(self):
        endpoint_group_id = _uuid()
        data = {'endpoint_group': {'name': 'epg1',
                                   'tenant_id': _uuid(),
                                   'description': '',
                                   'parent_id': None,
                                   'endpoints': [],
                                   'provided_contract_scopes': [],
                                   'consumed_contract_scopes': []}}
        return_value = copy.copy(data['endpoint_group'])
        return_value.update({'id': endpoint_group_id})

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

    def test_create_endpoint(self):
        endpoint_id = _uuid()
        data = {'endpoint': {'name': 'ep1',
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
