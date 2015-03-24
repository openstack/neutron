# Copyright 2013 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base


class BaseSecGroupTest(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(BaseSecGroupTest, cls).resource_setup()

    def _create_security_group(self):
        # Create a security group
        name = data_utils.rand_name('secgroup-')
        group_create_body = self.client.create_security_group(name=name)
        self.addCleanup(self._delete_security_group,
                        group_create_body['security_group']['id'])
        self.assertEqual(group_create_body['security_group']['name'], name)
        return group_create_body, name

    def _delete_security_group(self, secgroup_id):
        self.client.delete_security_group(secgroup_id)
        # Asserting that the security group is not found in the list
        # after deletion
        list_body = self.client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertNotIn(secgroup_id, secgroup_list)

    def _delete_security_group_rule(self, rule_id):
        self.client.delete_security_group_rule(rule_id)
        # Asserting that the security group is not found in the list
        # after deletion
        list_body = self.client.list_security_group_rules()
        rules_list = list()
        for rule in list_body['security_group_rules']:
            rules_list.append(rule['id'])
        self.assertNotIn(rule_id, rules_list)
