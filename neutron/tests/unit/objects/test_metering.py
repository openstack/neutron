# Copyright (c) 2016 Intel Corporation.
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

from neutron.objects import metering
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class MeteringLabelRuleObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = metering.MeteringLabelRule


class MeteringLabelRuleDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                        testlib_api.SqlTestCase):

    _test_class = metering.MeteringLabelRule

    def _create_test_metering_label_id(self, **attrs):
        attrs = self.get_random_object_fields(metering.MeteringLabel)
        metering_label = metering.MeteringLabel(self.context, **attrs)
        metering_label.create()
        return metering_label.id

    def setUp(self):
        super().setUp()
        self.update_obj_fields(
            {'metering_label_id': self._create_test_metering_label_id})


class MeteringLabelObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = metering.MeteringLabel


class MeteringLabelDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):

    _test_class = metering.MeteringLabel
