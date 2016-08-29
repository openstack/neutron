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

from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.tempest.api import base_security_groups as base


class NegativeSecGroupTest(base.BaseSecGroupTest):

    @classmethod
    @test.requires_ext(extension="security-group", service="network")
    def resource_setup(cls):
        super(NegativeSecGroupTest, cls).resource_setup()

    @test.attr(type='negative')
    @test.idempotent_id('55100aa8-b24f-333c-0bef-64eefd85f15c')
    def test_update_default_security_group_name(self):
        sg_list = self.client.list_security_groups(name='default')
        sg = sg_list['security_groups'][0]
        self.assertRaises(lib_exc.Conflict, self.client.update_security_group,
                          sg['id'], name='test')


class NegativeSecGroupIPv6Test(NegativeSecGroupTest):
    _ip_version = 6
