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

# rule types are so different from other objects that we don't base the test
# class on the common base class for all objects

import mock

from neutron import manager
from neutron.objects.qos import rule_type
from neutron.services.qos import qos_consts
from neutron.tests import base as test_base


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class QosRuleTypeObjectTestCase(test_base.BaseTestCase):

    def setUp(self):
        self.config_parse()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        super(QosRuleTypeObjectTestCase, self).setUp()

    def test_get_objects(self):
        core_plugin = manager.NeutronManager.get_plugin()
        rule_types_mock = mock.PropertyMock(
            return_value=qos_consts.VALID_RULE_TYPES)
        with mock.patch.object(core_plugin, 'supported_qos_rule_types',
                               new_callable=rule_types_mock,
                               create=True):
            types = rule_type.QosRuleType.get_objects()
            self.assertEqual(sorted(qos_consts.VALID_RULE_TYPES),
                             sorted(type_['type'] for type_ in types))

    def test_wrong_type(self):
        self.assertRaises(ValueError, rule_type.QosRuleType, type='bad_type')
