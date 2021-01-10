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

from neutron_lib.api.definitions import security_groups_normalized_cidr
import webob.exc

from neutron.tests.unit.extensions import test_securitygroup


DB_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_security_groups_normalized_cidr.'
    'TestPlugin')


class SecurityGroupNormalizedCidrTestExtManager(
        test_securitygroup.SecurityGroupTestExtensionManager):

    def get_resources(self):
        self.update_attributes_map(
            security_groups_normalized_cidr.RESOURCE_ATTRIBUTE_MAP)
        return super(
            SecurityGroupNormalizedCidrTestExtManager, self).get_resources()


class TestPlugin(test_securitygroup.SecurityGroupTestPlugin):

    supported_extension_aliases = ['security-group',
                                   security_groups_normalized_cidr.ALIAS]


class TestSecurityGroupsNormalizedCidr(
        test_securitygroup.SecurityGroupDBTestCase):

    def setUp(self):
        super(TestSecurityGroupsNormalizedCidr, self).setUp(
              plugin=DB_PLUGIN_KLASS,
              ext_mgr=SecurityGroupNormalizedCidrTestExtManager())

    def test_create_security_group_rule_with_not_normalized_cidr(self):
        name = 'webservers'
        description = 'my webservers'
        remote_prefixes = ['10.0.0.120/24', '10.0.0.200/24']
        with self.security_group(name, description) as sg:
            sg_id = sg['security_group']['id']
            for remote_ip_prefix in remote_prefixes:
                rule = self._build_security_group_rule(
                    sg_id,
                    'ingress', 'tcp',
                    remote_ip_prefix=remote_ip_prefix)
                res = self._create_security_group_rule(self.fmt, rule)
                self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
                res_sg = self.deserialize(self.fmt, res)
                self.assertEqual(
                    '10.0.0.0/24',
                    res_sg['security_group_rule']['normalized_cidr']
                )
                self.assertEqual(
                    remote_ip_prefix,
                    res_sg['security_group_rule']['remote_ip_prefix']
                )
