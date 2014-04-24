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
from neutron.extensions import group_policy_mapping as gpm
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class GroupPolicyMappingExtTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        self._saved_gp_attr_map = {}
        for k, v in gpolicy.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self._saved_gp_attr_map[k] = v.copy()
        self.addCleanup(self._restore_gp_attr_map)

        super(GroupPolicyMappingExtTestCase, self).setUp()
        attr_map = gpolicy.RESOURCE_ATTRIBUTE_MAP
        attr_map['endpoints'].update(gpm.EXTENDED_ATTRIBUTES_2_0['endpoints'])
        attr_map['endpoint_groups'].update(
            gpm.EXTENDED_ATTRIBUTES_2_0['endpoint_groups'])
        self._setUpExtension(
            'neutron.extensions.group_policy.GroupPolicyPluginBase',
            constants.GROUP_POLICY, attr_map,
            gpolicy.Group_policy, 'gp', plural_mappings={})

    def _restore_gp_attr_map(self):
        gpolicy.RESOURCE_ATTRIBUTE_MAP = self._saved_gp_attr_map

    def test_create_endpoint(self):
        endpoint_id = _uuid()
        data = {'endpoint': {'name': 'ep1',
                             'tenant_id': _uuid(),
                             'description': '',
                             'endpointgroup_id': _uuid(),
                             'neutron_port_id': _uuid()}}
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

    def test_create_endpoint_group(self):
        endpoint_group_id = _uuid()
        data = {'endpoint_group': {'name': 'epg1',
                                   'tenant_id': _uuid(),
                                   'description': '',
                                   'neutron_subnets': [],
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
