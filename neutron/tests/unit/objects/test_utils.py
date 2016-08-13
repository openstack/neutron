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

from neutron.common import exceptions
from neutron.objects import utils
from neutron.tests import base as test_base


class TestConvertFilters(test_base.BaseTestCase):

    def test_convert_filters_no_tenant_id(self):
        kwargs = {
            'filter%d' % i: 'value%d' % i
            for i in range(0, 10)
        }
        self.assertEqual(kwargs, utils.convert_filters(**kwargs))

    def test_convert_filters_tenant_id(self):
        expected_project_id = 'fake-tenant-id'
        kwargs = {
            'filter%d' % i: 'value%d' % i
            for i in range(0, 10)
        }
        expected = kwargs.copy()
        expected['project_id'] = expected_project_id

        self.assertEqual(
            expected,
            utils.convert_filters(tenant_id=expected_project_id, **kwargs)
        )

    def test_convert_filters_tenant_id_and_project_id_raises(self):
        kwargs = {
            'filter%d' % i: 'value%d' % i
            for i in range(0, 10)
        }
        kwargs['tenant_id'] = 'fake-tenant-id'
        kwargs['project_id'] = 'fake-tenant-id'

        self.assertRaises(
            exceptions.TenantIdProjectIdFilterConflict,
            utils.convert_filters, **kwargs
        )
