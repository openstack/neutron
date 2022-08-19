# Copyright (c) 2021 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_policy import policy as base_policy
from oslo_utils import uuidutils

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class RouterAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(RouterAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(RouterAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_router(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router', self.alt_target)

    def test_create_router_distributed(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:distributed', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:distributed', self.alt_target)

    def test_create_router_ha(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:ha', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:ha', self.alt_target)

    def test_create_router_external_gateway_info(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info',
            self.alt_target)

    def test_create_router_external_gateway_info_network_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:network_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:network_id',
            self.alt_target)

    def test_create_router_external_gateway_info_enable_snat(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:enable_snat',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:enable_snat',
            self.alt_target)

    def test_create_router_external_gateway_info_external_fixed_ips(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context,
            'create_router:external_gateway_info:external_fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context,
            'create_router:external_gateway_info:external_fixed_ips',
            self.alt_target)

    def test_get_router(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router', self.alt_target)

    def test_get_router_distributed(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router:distributed', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router:distributed', self.alt_target)

    def test_get_router_ha(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router:ha', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_router:ha', self.alt_target)

    def test_update_router(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router', self.alt_target)

    def test_update_router_distributed(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:distributed', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:distributed', self.alt_target)

    def test_update_router_ha(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:ha', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:ha', self.alt_target)

    def test_update_router_external_gateway_info(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info',
            self.alt_target)

    def test_update_router_external_gateway_info_network_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:network_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:network_id',
            self.alt_target)

    def test_update_router_external_gateway_info_enable_snat(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:enable_snat',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:enable_snat',
            self.alt_target)

    def test_update_router_external_gateway_info_external_fixed_ips(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context,
            'update_router:external_gateway_info:external_fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context,
            'update_router:external_gateway_info:external_fixed_ips',
            self.alt_target)

    def test_delete_router(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_router', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_router', self.alt_target)

    def test_add_router_interface(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_router_interface', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_router_interface', self.alt_target)

    def test_remove_router_interface(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_router_interface', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_router_interface', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(RouterAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_router', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_router', self.alt_target))

    def test_create_router_distributed(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_router:distributed', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_router:distributed', self.alt_target))

    def test_create_router_ha(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_router:ha', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_router:ha', self.alt_target))

    def test_create_router_external_gateway_info(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info',
                           self.alt_target))

    def test_create_router_external_gateway_info_network_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info:network_id',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info:network_id',
                           self.alt_target))

    def test_create_router_external_gateway_info_enable_snat(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info:enable_snat',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info:enable_snat',
                           self.alt_target))

    def test_create_router_external_gateway_info_external_fixed_ips(self):
        self.assertTrue(
            policy.enforce(
                self.context,
                'create_router:external_gateway_info:external_fixed_ips',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'create_router:external_gateway_info:external_fixed_ips',
                self.alt_target))

    def test_get_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_router', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_router', self.alt_target))

    def test_get_router_distributed(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_router:distributed', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_router:distributed', self.alt_target))

    def test_get_router_ha(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_router:ha', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_router:ha', self.alt_target))

    def test_update_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_router', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_router', self.alt_target))

    def test_update_router_distributed(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_router:distributed', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_router:distributed', self.alt_target))

    def test_update_router_ha(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_router:ha', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_router:ha', self.alt_target))

    def test_update_router_external_gateway_info(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info',
                           self.alt_target))

    def test_update_router_external_gateway_info_network_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info:network_id',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info:network_id',
                           self.alt_target))

    def test_update_router_external_gateway_info_enable_snat(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info:enable_snat',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info:enable_snat',
                           self.alt_target))

    def test_update_router_external_gateway_info_external_fixed_ips(self):
        self.assertTrue(
            policy.enforce(
                self.context,
                'update_router:external_gateway_info:external_fixed_ips',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'update_router:external_gateway_info:external_fixed_ips',
                self.alt_target))

    def test_delete_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_router', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_router', self.alt_target))

    def test_add_router_interface(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'add_router_interface', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'add_router_interface', self.alt_target))

    def test_remove_router_interface(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'remove_router_interface', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'remove_router_interface', self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_router', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router', self.alt_target)

    def test_create_router_distributed(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:distributed', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:distributed', self.alt_target)

    def test_create_router_ha(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:ha', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:ha', self.alt_target)

    def test_create_router_external_gateway_info(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info',
            self.alt_target)

    def test_create_router_external_gateway_info_network_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_router:external_gateway_info:network_id',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:network_id',
            self.alt_target)

    def test_create_router_external_gateway_info_enable_snat(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:enable_snat',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:enable_snat',
            self.alt_target)

    def test_create_router_external_gateway_info_external_fixed_ips(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context,
            'create_router:external_gateway_info:external_fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context,
            'create_router:external_gateway_info:external_fixed_ips',
            self.alt_target)

    def test_get_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_router', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_router', self.alt_target)

    def test_get_router_distributed(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_router:distributed', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_router:distributed', self.alt_target)

    def test_get_router_ha(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_router:ha', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_router:ha', self.alt_target)

    def test_update_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_router', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router', self.alt_target)

    def test_update_router_distributed(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:distributed', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:distributed', self.alt_target)

    def test_update_router_ha(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:ha', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:ha', self.alt_target)

    def test_update_router_external_gateway_info(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info',
            self.alt_target)

    def test_update_router_external_gateway_info_network_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_router:external_gateway_info:network_id',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:network_id',
            self.alt_target)

    def test_update_router_external_gateway_info_enable_snat(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:enable_snat',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:enable_snat',
            self.alt_target)

    def test_update_router_external_gateway_info_external_fixed_ips(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context,
            'update_router:external_gateway_info:external_fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context,
            'update_router:external_gateway_info:external_fixed_ips',
            self.alt_target)

    def test_delete_router(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_router', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_router', self.alt_target)

    def test_add_router_interface(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'add_router_interface', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_router_interface', self.alt_target)

    def test_remove_router_interface(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'remove_router_interface', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_router_interface', self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_router(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router', self.alt_target)

    def test_create_router_external_gateway_info(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info',
            self.alt_target)

    def test_create_router_external_gateway_info_network_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:network_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_router:external_gateway_info:network_id',
            self.alt_target)

    def test_update_router(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router', self.alt_target)

    def test_update_router_external_gateway_info(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info',
            self.alt_target)

    def test_update_router_external_gateway_info_network_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:network_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_router:external_gateway_info:network_id',
            self.alt_target)

    def test_delete_router(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_router', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_router', self.alt_target)

    def test_add_router_interface(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_router_interface', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_router_interface', self.alt_target)

    def test_remove_router_interface(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_router_interface', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_router_interface', self.alt_target)


class ExtrarouteAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(ExtrarouteAPITestCase, self).setUp()
        self.router = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}

        self.target = {
            'project_id': self.project_id,
            'router_id': self.router['id'],
            'ext_parent_router_id': self.router['id']}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'router_id': self.router['id'],
            'ext_parent_router_id': self.router['id']}


class SystemAdminExtrarouteTests(ExtrarouteAPITestCase):

    def setUp(self):
        super(SystemAdminExtrarouteTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_add_extraroute(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_extraroutes', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_extraroutes', self.alt_target)

    def test_remove_extraroute(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_extraroutes', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_extraroutes', self.alt_target)


class SystemMemberExtrarouteTests(SystemAdminExtrarouteTests):

    def setUp(self):
        super(SystemMemberExtrarouteTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderExtrarouteTests(SystemMemberExtrarouteTests):

    def setUp(self):
        super(SystemReaderExtrarouteTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminExtrarouteTests(ExtrarouteAPITestCase):

    def setUp(self):
        super(AdminExtrarouteTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_add_extraroute(self):
        self.assertTrue(
            policy.enforce(self.context, 'add_extraroutes', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'add_extraroutes', self.alt_target))

    def test_remove_extraroute(self):
        self.assertTrue(
            policy.enforce(self.context, 'remove_extraroutes', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'remove_extraroutes', self.alt_target))


class ProjectMemberExtrarouteTests(AdminExtrarouteTests):

    def setUp(self):
        super(ProjectMemberExtrarouteTests, self).setUp()
        self.context = self.project_member_ctx

    def test_add_extraroute(self):
        self.assertTrue(
            policy.enforce(self.context, 'add_extraroutes', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_extraroutes', self.alt_target)

    def test_remove_extraroute(self):
        self.assertTrue(
            policy.enforce(self.context, 'remove_extraroutes', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_extraroutes', self.alt_target)


class ProjectReaderExtrarouteTests(ProjectMemberExtrarouteTests):

    def setUp(self):
        super(ProjectReaderExtrarouteTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_add_extraroute(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_extraroutes', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_extraroutes', self.alt_target)

    def test_remove_extraroute(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_extraroutes', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_extraroutes', self.alt_target)
