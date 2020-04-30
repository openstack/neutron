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

from unittest import mock

from neutron_lib import context
from neutron_lib import fixture
from oslo_utils import uuidutils

from neutron.db.quota import api as quota_db_api
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup
from neutron.tests.unit.plugins.ml2 import base as ml2_base
from neutron.tests.unit.plugins.ml2 import test_plugin


class SgTestCaseWrapper(test_securitygroup.SecurityGroupDBTestCase):
    # This wrapper class enables Ml2PluginV2TestCase to correctly call the
    # setup method in SecurityGroupDBTestCase which does not accept the
    # service_plugins keyword parameter.

    def setUp(self, plugin, **kwargs):
        super(SgTestCaseWrapper, self).setUp(plugin)


class BaseTestTrackedResources(test_plugin.Ml2PluginV2TestCase,
                               SgTestCaseWrapper):

    def setUp(self):
        self.ctx = context.get_admin_context()
        super(BaseTestTrackedResources, self).setUp()
        self._tenant_id = uuidutils.generate_uuid()

    def _test_init(self, resource_name):
        quota_db_api.set_quota_usage(
            self.ctx, resource_name, self._tenant_id)


class BaseTestEventHandler(object):

    def setUp(self):
        # Prevent noise from default security group operations
        def_sec_group_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_ensure_default_security_group')
        def_sec_group_patch.start()
        get_sec_group_port_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_get_security_groups_on_port')

        get_sec_group_port_patch.start()
        process_port_create_security_group_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_process_port_create_security_group')
        process_port_create_security_group_patch.start()
        handler_patch = mock.patch(
            'neutron.quota.resource.TrackedResource._db_event_handler')
        self.handler_mock = handler_patch.start()
        super(BaseTestEventHandler, self).setUp()

    def _verify_event_handler_calls(self, data, expected_call_count=1):
        if not hasattr(data, '__iter__') or isinstance(data, dict):
            data = [data]
        self.assertEqual(expected_call_count, self.handler_mock.call_count)
        call_idx = -1
        for item in data:
            if item:
                model = self.handler_mock.call_args_list[call_idx][0][-1]
                self.assertEqual(model['id'], item['id'])
                self.assertEqual(model['tenant_id'], item['tenant_id'])
            call_idx = call_idx - 1


class TestTrackedResourcesEventHandler(BaseTestEventHandler,
                                       BaseTestTrackedResources):

    def test_create_delete_network_triggers_event(self):
        self._test_init('network')
        net = self._make_network('json', 'meh', True)['network']
        self._verify_event_handler_calls(net)
        self._delete('networks', net['id'])
        self._verify_event_handler_calls(net, expected_call_count=2)

    def test_create_delete_port_triggers_event(self):
        self._test_init('port')
        net = self._make_network('json', 'meh', True)['network']
        port = self._make_port('json', net['id'])['port']
        # Expecting 2 calls - 1 for the network, 1 for the port
        self._verify_event_handler_calls(port, expected_call_count=2)
        self._delete('ports', port['id'])
        self._verify_event_handler_calls(port, expected_call_count=3)

    def test_create_delete_subnet_triggers_event(self):
        self._test_init('subnet')
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        # Expecting 2 calls - 1 for the network, 1 for the subnet
        self._verify_event_handler_calls([subnet, net['network']],
                                         expected_call_count=2)
        self._delete('subnets', subnet['id'])
        self._verify_event_handler_calls(subnet, expected_call_count=3)

    def test_create_delete_network_with_subnet_triggers_event(self):
        self._test_init('network')
        self._test_init('subnet')
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        # Expecting 2 calls - 1 for the network, 1 for the subnet
        self._verify_event_handler_calls([subnet, net['network']],
                                         expected_call_count=2)
        self._delete('networks', net['network']['id'])
        # Expecting 2 more calls - 1 for the network, 1 for the subnet
        self._verify_event_handler_calls([net['network'], subnet],
                                         expected_call_count=4)

    def test_create_delete_subnetpool_triggers_event(self):
        self._test_init('subnetpool')
        pool = self._make_subnetpool('json', ['10.0.0.0/8'],
                                     name='meh',
                                     tenant_id=self._tenant_id)['subnetpool']
        self._verify_event_handler_calls(pool)
        self._delete('subnetpools', pool['id'])
        self._verify_event_handler_calls(pool, expected_call_count=2)

    def test_create_delete_securitygroup_triggers_event(self):
        self._test_init('security_group')
        sec_group = self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        # When a security group is created it also creates 2 rules, therefore
        # there will be three calls and we need to verify the first
        self._verify_event_handler_calls([None, None, sec_group],
                                         expected_call_count=3)
        self._delete('security-groups', sec_group['id'])
        # When a security group is deleted it also removes the 2 rules
        # generated upon creation
        self._verify_event_handler_calls(sec_group, expected_call_count=6)

    def test_create_delete_securitygrouprule_triggers_event(self):
        self._test_init('security_group_rule')
        sec_group = self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        rule_req = self._build_security_group_rule(
            sec_group['id'], 'ingress', 'TCP', tenant_id=self._tenant_id)
        sec_group_rule = self._make_security_group_rule(
            'json', rule_req)['security_group_rule']
        # When a security group is created it also creates 2 rules, therefore
        # there will be four calls in total to the event handler
        self._verify_event_handler_calls(sec_group_rule, expected_call_count=4)
        self._delete('security-group-rules', sec_group_rule['id'])
        self._verify_event_handler_calls(sec_group_rule, expected_call_count=5)


class TestL3ResourcesEventHandler(BaseTestEventHandler,
                                  ml2_base.ML2TestFramework,
                                  test_l3.L3NatTestCaseMixin):

    def setUp(self):
        super(TestL3ResourcesEventHandler, self).setUp()
        self.useFixture(fixture.APIDefinitionFixture())
        ext_mgr = test_l3.L3TestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_create_delete_floating_ip_triggers_event(self):
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '14.0.0.1',
                                   '14.0.0.0/24')['subnet']
        self._set_net_external(subnet['network_id'])
        floatingip = self._make_floatingip('json', subnet['network_id'])
        internal_port = self._show(
            'ports', floatingip['floatingip']['port_id'])['ports'][0]
        # When a floatingip is created it also creates port, therefore
        # there will be four calls in total to the event handler
        self._verify_event_handler_calls(floatingip['floatingip'],
                                         expected_call_count=4)
        self._delete('floatingips', floatingip['floatingip']['id'])
        # Expecting 2 more calls - 1 for the port, 1 for the floatingip
        self._verify_event_handler_calls(
            [internal_port, floatingip['floatingip']], expected_call_count=6)


class TestTrackedResources(BaseTestTrackedResources):

    def _verify_dirty_bit(self, resource_name, expected_value=True):
        usage = quota_db_api.get_quota_usage_by_resource_and_tenant(
            self.ctx, resource_name, self._tenant_id)
        self.assertEqual(expected_value, usage.dirty)

    def test_create_delete_network_marks_dirty(self):
        self._test_init('network')
        net = self._make_network('json', 'meh', True)['network']
        self._verify_dirty_bit('network')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'network', self._tenant_id, dirty=False)
        self._delete('networks', net['id'])
        self._verify_dirty_bit('network')

    def test_list_networks_clears_dirty(self):
        self._test_init('network')
        net = self._make_network('json', 'meh', True)['network']
        self.ctx.tenant_id = net['tenant_id']
        self._list('networks', neutron_context=self.ctx)
        self._verify_dirty_bit('network', expected_value=False)

    def test_create_delete_port_marks_dirty(self):
        self._test_init('port')
        net = self._make_network('json', 'meh', True)['network']
        port = self._make_port('json', net['id'])['port']
        self._verify_dirty_bit('port')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'port', self._tenant_id, dirty=False)
        self._delete('ports', port['id'])
        self._verify_dirty_bit('port')

    def test_list_ports_clears_dirty(self):
        self._test_init('port')
        net = self._make_network('json', 'meh', True)['network']
        port = self._make_port('json', net['id'])['port']
        self.ctx.tenant_id = port['tenant_id']
        self._list('ports', neutron_context=self.ctx)
        self._verify_dirty_bit('port', expected_value=False)

    def test_create_delete_subnet_marks_dirty(self):
        self._test_init('subnet')
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        self._verify_dirty_bit('subnet')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'subnet', self._tenant_id, dirty=False)
        self._delete('subnets', subnet['id'])
        self._verify_dirty_bit('subnet')

    def test_create_delete_network_with_subnet_marks_dirty(self):
        self._test_init('network')
        self._test_init('subnet')
        net = self._make_network('json', 'meh', True)
        self._make_subnet('json', net, '10.0.0.1',
                          '10.0.0.0/24')['subnet']
        self._verify_dirty_bit('subnet')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'subnet', self._tenant_id, dirty=False)
        self._delete('networks', net['network']['id'])
        self._verify_dirty_bit('network')
        self._verify_dirty_bit('subnet')

    def test_list_subnets_clears_dirty(self):
        self._test_init('subnet')
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        self.ctx.tenant_id = subnet['tenant_id']
        self._list('subnets', neutron_context=self.ctx)
        self._verify_dirty_bit('subnet', expected_value=False)

    def test_create_delete_subnetpool_marks_dirty(self):
        self._test_init('subnetpool')
        pool = self._make_subnetpool('json', ['10.0.0.0/8'],
                                     name='meh',
                                     tenant_id=self._tenant_id)['subnetpool']
        self._verify_dirty_bit('subnetpool')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'subnetpool', self._tenant_id, dirty=False)
        self._delete('subnetpools', pool['id'])
        self._verify_dirty_bit('subnetpool')

    def test_list_subnetpools_clears_dirty(self):
        self._test_init('subnetpool')
        pool = self._make_subnetpool('json', ['10.0.0.0/8'],
                                     name='meh',
                                     tenant_id=self._tenant_id)['subnetpool']
        self.ctx.tenant_id = pool['tenant_id']
        self._list('subnetpools', neutron_context=self.ctx)
        self._verify_dirty_bit('subnetpool', expected_value=False)

    def test_create_delete_securitygroup_marks_dirty(self):
        self._test_init('security_group')
        sec_group = self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        self._verify_dirty_bit('security_group')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'security_group', self._tenant_id, dirty=False)
        self._delete('security-groups', sec_group['id'])
        self._verify_dirty_bit('security_group')

    def test_list_securitygroups_clears_dirty(self):
        self._test_init('security_group')
        self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        self.ctx.tenant_id = self._tenant_id
        self._list('security-groups', neutron_context=self.ctx)
        self._verify_dirty_bit('security_group', expected_value=False)

    def test_create_delete_securitygrouprule_marks_dirty(self):
        self._test_init('security_group_rule')
        sec_group = self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        rule_req = self._build_security_group_rule(
            sec_group['id'], 'ingress', 'TCP', tenant_id=self._tenant_id)
        sec_group_rule = self._make_security_group_rule(
            'json', rule_req)['security_group_rule']
        self._verify_dirty_bit('security_group_rule')
        # Clear the dirty bit
        quota_db_api.set_quota_usage_dirty(
            self.ctx, 'security_group_rule', self._tenant_id, dirty=False)
        self._delete('security-group-rules', sec_group_rule['id'])
        self._verify_dirty_bit('security_group_rule')

    def test_list_securitygrouprules_clears_dirty(self):
        self._test_init('security_group_rule')
        self._make_security_group(
            'json', 'meh', 'meh', tenant_id=self._tenant_id)['security_group']
        # As the security group create operation also creates 2 security group
        # rules there is no need to explicitly create any rule
        self.ctx.tenant_id = self._tenant_id
        self._list('security-group-rules', neutron_context=self.ctx)
        self._verify_dirty_bit('security_group_rule', expected_value=False)
