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

from neutron.db import api as db_api
from neutron.objects.qos import rule
from neutron.tests.unit.objects import test_base


class QosBandwidthLimitPolicyObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = rule.QosBandwidthLimitRule

    def _filter_db_object(self, func):
        return {
            field: self.db_obj[field]
            for field in self._test_class.fields
            if func(field)
        }

    def _get_core_db_obj(self):
        return self._filter_db_object(
            lambda field: self._test_class._is_core_field(field))

    def _get_addn_db_obj(self):
        return self._filter_db_object(
            lambda field: self._test_class._is_addn_field(field))

    def test_create(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            test_class = self._test_class
            obj = test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.create()
            self._check_equal(obj, self.db_obj)

            core_db_obj = self._get_core_db_obj()
            create_mock.assert_any_call(
                self.context, self._test_class.base_db_model, core_db_obj)

            addn_db_obj = self._get_addn_db_obj()
            create_mock.assert_any_call(
                self.context, self._test_class.db_model,
                addn_db_obj)

    def test_update_changes(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj) as update_mock:
            obj = self._test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.update()
            self._check_equal(obj, self.db_obj)

            core_db_obj = self._get_core_db_obj()
            update_mock.assert_any_call(
                self.context, self._test_class.base_db_model, obj.id,
                core_db_obj)

            addn_db_obj = self._get_addn_db_obj()
            update_mock.assert_any_call(
                self.context, self._test_class.db_model, obj.id,
                addn_db_obj)
