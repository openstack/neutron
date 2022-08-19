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

from unittest import mock

from oslo_policy import policy as base_policy
from oslo_utils import uuidutils

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class PortAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(PortAPITestCase, self).setUp()

        self.network = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}
        self.target = {
            'project_id': self.project_id,
            'tenant_id': self.alt_project_id,
            'network_id': self.network['id'],
            'ext_parent_network_id': self.network['id']}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'tenant_id': self.alt_project_id,
            'network_id': self.network['id'],
            'ext_parent_network_id': self.network['id']}

        self.plugin_mock = mock.Mock()
        self.plugin_mock.get_network.return_value = self.network
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()


class SystemAdminTests(PortAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_port(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port', self.alt_target)

    def test_create_port_with_device_owner(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:device_owner',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:device_owner',
            self.alt_target)

    def test_create_port_with_mac_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:mac_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:mac_address',
            self.alt_target)

    def test_create_port_with_fixed_ips(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips',
            self.alt_target)

    def test_create_port_with_fixed_ips_and_ip_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips:ip_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips:ip_address',
            self.alt_target)

    def test_create_port_with_fixed_ips_and_subnet_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips:subnet_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:fixed_ips:subnet_id',
            self.alt_target)

    def test_create_port_with_port_security_enabled(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:port_security_enabled',
            self.alt_target)

    def test_create_port_with_binding_host_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:host_id',
            self.alt_target)

    def test_create_port_with_binding_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:profile',
            self.alt_target)

    def test_create_port_with_binding_vnic_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:vnic_type',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_port:binding:vnic_type',
            self.alt_target)

    def test_create_port_with_allowed_address_pairs(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs',
            self.alt_target)

    def test_create_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:mac_address',
            self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:mac_address',
            self.target)

    def test_create_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:ip_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:ip_address',
            self.alt_target)

    def test_get_port(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port', self.alt_target)

    def test_get_port_binding_vif_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:vif_type',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:vif_type',
            self.alt_target)

    def test_get_port_binding_vif_details(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:vif_details',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:vif_details',
            self.alt_target)

    def test_get_port_binding_host_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:host_id',
            self.alt_target)

    def test_get_port_binding_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:binding:profile',
            self.alt_target)

    def test_get_port_resource_request(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:resource_request',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_port:resource_request',
            self.alt_target)

    def test_update_port(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port', self.alt_target)

    def test_update_port_with_device_owner(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:device_owner',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:device_owner',
            self.alt_target)

    def test_update_port_with_mac_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:mac_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:mac_address',
            self.alt_target)

    def test_update_port_with_fixed_ips(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips',
            self.alt_target)

    def test_update_port_with_fixed_ips_and_ip_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips:ip_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips:ip_address',
            self.alt_target)

    def test_update_port_with_fixed_ips_and_subnet_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips:subnet_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:fixed_ips:subnet_id',
            self.alt_target)

    def test_update_port_with_port_security_enabled(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:port_security_enabled',
            self.alt_target)

    def test_update_port_with_binding_host_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:host_id',
            self.alt_target)

    def test_update_port_with_binding_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:profile',
            self.alt_target)

    def test_update_port_with_binding_vnic_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:vnic_type',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_port:binding:vnic_type',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:mac_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:mac_address',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:ip_address',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:ip_address',
            self.alt_target)

    def test_update_port_data_plane_status(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:data_plane_status', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_port:data_plane_status', self.alt_target)

    def test_delete_port(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_port', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_port', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(PortAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_port', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_port', self.alt_target))

    def test_create_port_with_device_owner(self):
        target = self.target.copy()
        target['device_owner'] = 'network:test'
        alt_target = self.alt_target.copy()
        alt_target['device_owner'] = 'network:test'
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:device_owner', target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:device_owner', alt_target))

    def test_create_port_with_mac_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:mac_address', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:mac_address', self.alt_target))

    def test_create_port_with_fixed_ips(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:fixed_ips', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:fixed_ips', self.alt_target))

    def test_create_port_with_fixed_ips_and_ip_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:fixed_ips:ip_address', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'create_port:fixed_ips:ip_address', self.alt_target))

    def test_create_port_with_fixed_ips_and_subnet_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:fixed_ips:subent_id', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:fixed_ips:subent_id', self.alt_target))

    def test_create_port_with_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:port_security_enabled', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'create_port:port_security_enabled', self.alt_target))

    def test_create_port_with_binding_host_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:host_id', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:host_id', self.alt_target))

    def test_create_port_with_binding_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:profile', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:profile', self.alt_target))

    def test_create_port_with_binding_vnic_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:vnic_type', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:vnic_type', self.alt_target))

    def test_create_port_with_allowed_address_pairs(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:allowed_address_pairs', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'create_port:allowed_address_pairs', self.alt_target))

    def test_create_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:allowed_address_pairs:mac_address',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:allowed_address_pairs:mac_address',
                           self.alt_target))

    def test_create_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:allowed_address_pairs:ip_address',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:allowed_address_pairs:ip_address',
                           self.alt_target))

    def test_get_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_port', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_port', self.alt_target))

    def test_get_port_binding_vif_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:vif_type', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:vif_type', self.alt_target))

    def test_get_port_binding_vif_details(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:vif_details', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:vif_details', self.alt_target))

    def test_get_port_binding_host_id(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:host_id', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:host_id', self.alt_target))

    def test_get_port_binding_profile(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:profile', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:binding:profile', self.alt_target))

    def test_get_port_resource_request(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:resource_request', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:resource_request', self.alt_target))

    def test_update_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_port', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_port', self.alt_target))

    def test_update_port_with_device_owner(self):
        target = self.target.copy()
        target['device_owner'] = 'network:test'
        alt_target = self.alt_target.copy()
        alt_target['device_owner'] = 'network:test'
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:device_owner', target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:device_owner', alt_target))

    def test_update_port_with_mac_address(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:mac_address', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:mac_address', self.alt_target))

    def test_update_port_with_fixed_ips(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:fixed_ips', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:fixed_ips', self.alt_target))

    def test_update_port_with_fixed_ips_and_ip_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:fixed_ips:ip_address', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'update_port:fixed_ips:ip_address', self.alt_target))

    def test_update_port_with_fixed_ips_and_subnet_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:fixed_ips:subent_id', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:fixed_ips:subent_id', self.alt_target))

    def test_update_port_with_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:port_security_enabled', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'update_port:port_security_enabled', self.alt_target))

    def test_update_port_with_binding_host_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:host_id', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:host_id', self.alt_target))

    def test_update_port_with_binding_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:profile', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:profile', self.alt_target))

    def test_update_port_with_binding_vnic_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:vnic_type', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:vnic_type', self.alt_target))

    def test_update_port_with_allowed_address_pairs(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:allowed_address_pairs', self.target))
        self.assertTrue(
            policy.enforce(
                self.context,
                'update_port:allowed_address_pairs', self.alt_target))

    def test_update_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:allowed_address_pairs:mac_address',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:allowed_address_pairs:mac_address',
                           self.alt_target))

    def test_update_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:allowed_address_pairs:ip_address',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:allowed_address_pairs:ip_address',
                           self.alt_target))

    def test_update_port_data_plane_status(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:data_plane_status',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:data_plane_status',
                           self.alt_target))

    def test_delete_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_port', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_port', self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_port', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port', self.alt_target)

    def test_create_port_with_device_owner(self):
        target = self.target.copy()
        target['device_owner'] = 'network:test'
        alt_target = self.alt_target.copy()
        alt_target['device_owner'] = 'network:test'
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:device_owner',
            target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:device_owner',
            alt_target)

    def test_create_port_with_mac_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:mac_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:mac_address',
            self.alt_target)

    def test_create_port_with_fixed_ips(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips',
            self.alt_target)

    def test_create_port_with_fixed_ips_and_ip_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips:ip_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips:ip_address',
            self.alt_target)

    def test_create_port_with_fixed_ips_and_subnet_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips:subnet_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:fixed_ips:subnet_id',
            self.alt_target)

    def test_create_port_with_port_security_enabled(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:port_security_enabled',
            self.alt_target)

    def test_create_port_with_binding_host_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:host_id',
            self.alt_target)

    def test_create_port_with_binding_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:profile',
            self.alt_target)

    def test_create_port_with_binding_vnic_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_port:binding:vnic_type', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:vnic_type',
            self.alt_target)

    def test_create_port_with_allowed_address_pairs(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs',
            self.alt_target)

    def test_create_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:mac_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:mac_address',
            self.alt_target)

    def test_create_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:ip_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:allowed_address_pairs:ip_address',
            self.alt_target)

    def test_get_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_port', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port', self.alt_target)

    def test_get_port_binding_vif_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:vif_type',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:vif_type',
            self.alt_target)

    def test_get_port_binding_vif_details(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:vif_details',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:vif_details',
            self.alt_target)

    def test_get_port_binding_host_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:host_id',
            self.alt_target)

    def test_get_port_binding_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:binding:profile',
            self.alt_target)

    def test_get_port_resource_request(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:resource_request',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_port:resource_request',
            self.alt_target)

    def test_update_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_port', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port', self.alt_target)

    def test_update_port_with_device_owner(self):
        target = self.target.copy()
        target['device_owner'] = 'network:test'
        alt_target = self.alt_target.copy()
        alt_target['device_owner'] = 'network:test'
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:device_owner',
            target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:device_owner',
            alt_target)

    def test_update_port_with_mac_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:mac_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:mac_address',
            self.alt_target)

    def test_update_port_with_fixed_ips(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips',
            self.alt_target)

    def test_update_port_with_fixed_ips_and_ip_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips:ip_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips:ip_address',
            self.alt_target)

    def test_update_port_with_fixed_ips_and_subnet_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips:subnet_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:fixed_ips:subnet_id',
            self.alt_target)

    def test_update_port_with_port_security_enabled(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:port_security_enabled',
            self.alt_target)

    def test_update_port_with_binding_host_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:host_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:host_id',
            self.alt_target)

    def test_update_port_with_binding_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:profile',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:profile',
            self.alt_target)

    def test_update_port_with_binding_vnic_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_port:binding:vnic_type', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:vnic_type',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs_and_mac_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:mac_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:mac_address',
            self.alt_target)

    def test_update_port_with_allowed_address_pairs_and_ip_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:ip_address',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:allowed_address_pairs:ip_address',
            self.alt_target)

    def test_update_port_data_plane_status(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:data_plane_status', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:data_plane_status', self.alt_target)

    def test_delete_port(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_port', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_port', self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_port(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port', self.alt_target)

    def test_create_port_with_binding_vnic_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:vnic_type',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_port:binding:vnic_type',
            self.alt_target)

    def test_update_port(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port', self.alt_target)

    def test_update_port_with_binding_vnic_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:vnic_type',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_port:binding:vnic_type',
            self.alt_target)

    def test_delete_port(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_port', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_port', self.alt_target)
