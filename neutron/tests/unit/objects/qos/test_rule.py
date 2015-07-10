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

    @classmethod
    def get_random_fields(cls):
        # object middleware should not allow random types, so override it with
        # proper type
        fields = (super(QosBandwidthLimitPolicyObjectTestCase, cls)
                  .get_random_fields())
        fields['type'] = cls._test_class.rule_type
        return fields

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

    def test_get_by_id(self):
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            obj = self._test_class.get_by_id(self.context, id='fake_id')
            self.assertTrue(self._is_test_class(obj))
            self.assertEqual(self.db_obj, test_base.get_obj_db_fields(obj))
            get_object_mock.assert_has_calls([
                mock.call(self.context, model, 'fake_id')
                for model in (self._test_class.db_model,
                              self._test_class.base_db_model)
            ], any_order=True)

    def test_get_objects(self):
        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs):

            @classmethod
            def _get_by_id(cls, context, id):
                for db_obj in self.db_objs:
                    if db_obj['id'] == id:
                        return self._test_class(context, **db_obj)

            with mock.patch.object(rule.QosRule, 'get_by_id', new=_get_by_id):
                objs = self._test_class.get_objects(self.context)
                self.assertFalse(
                    filter(lambda obj: not self._is_test_class(obj), objs))
                self.assertEqual(
                    sorted(self.db_objs),
                    sorted(test_base.get_obj_db_fields(obj) for obj in objs))

    def test_create(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            test_class = self._test_class
            obj = test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.create()
            self._check_equal(obj, self.db_obj)

            core_db_obj = self._get_core_db_obj()
            addn_db_obj = self._get_addn_db_obj()
            create_mock.assert_has_calls(
                [mock.call(self.context, self._test_class.base_db_model,
                           core_db_obj),
                 mock.call(self.context, self._test_class.db_model,
                           addn_db_obj)]
            )

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
