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

from tempest.lib.common.utils import data_utils
from tempest import test

from neutron.tests.api import base_security_groups as base


class SecGroupTest(base.BaseSecGroupTest):

    @classmethod
    @test.requires_ext(extension="security-group", service="network")
    def resource_setup(cls):
        super(SecGroupTest, cls).resource_setup()

    @test.attr(type='smoke')
    @test.idempotent_id('bfd128e5-3c92-44b6-9d66-7fe29d22c802')
    def test_create_list_update_show_delete_security_group(self):
        group_create_body, name = self._create_security_group()

        # List security groups and verify if created group is there in response
        list_body = self.client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertIn(group_create_body['security_group']['id'], secgroup_list)
        # Update the security group
        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.client.update_security_group(
            group_create_body['security_group']['id'],
            name=new_name,
            description=new_description)
        # Verify if security group is updated
        self.assertEqual(update_body['security_group']['name'], new_name)
        self.assertEqual(update_body['security_group']['description'],
                         new_description)
        # Show details of the updated security group
        show_body = self.client.show_security_group(
            group_create_body['security_group']['id'])
        self.assertEqual(show_body['security_group']['name'], new_name)
        self.assertEqual(show_body['security_group']['description'],
                         new_description)
