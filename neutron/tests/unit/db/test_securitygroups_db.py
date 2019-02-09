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

import copy

import mock
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
import sqlalchemy
import testtools

from neutron.db import common_db_mixin
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup
from neutron.services.revisions import revision_plugin
from neutron.tests.unit import testlib_api


FAKE_SECGROUP = {
    'security_group': {
        "tenant_id": 'fake',
        'description': 'fake',
        'name': 'fake'
    }
}

FAKE_SECGROUP_RULE = {
    'security_group_rule': {
        "tenant_id": 'fake',
        'description': 'fake',
        'name': 'fake',
        'port_range_min': '21',
        'protocol': 'tcp',
        'port_range_max': '23',
        'remote_ip_prefix': '10.0.0.1',
        'ethertype': 'IPv4',
        'remote_group_id': None,
        'security_group_id': 'None',
        'direction': 'ingress'
    }
}

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


def fake_callback(resource, event, *args, **kwargs):
    raise KeyError('bar')


class SecurityGroupDbMixinImpl(securitygroups_db.SecurityGroupDbMixin,
                               common_db_mixin.CommonDbMixin):
    pass


class SecurityGroupDbMixinTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(SecurityGroupDbMixinTestCase, self).setUp()
        self.setup_coreplugin(core_plugin=DB_PLUGIN_KLASS)
        self.ctx = context.get_admin_context()
        self.mixin = SecurityGroupDbMixinImpl()

    def test_create_security_group_conflict(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            secgroup = {'security_group': mock.ANY}
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.create_security_group(self.ctx, secgroup)

    def test_delete_security_group_in_use(self):
        with mock.patch.object(self.mixin,
                               '_get_port_security_group_bindings'),\
                mock.patch.object(self.mixin, '_get_security_group'),\
                mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupInUse):
                self.mixin.delete_security_group(self.ctx, mock.ANY)

    def test_update_security_group_conflict(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            secgroup = {'security_group': mock.ANY}
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.update_security_group(self.ctx, 'foo_id', secgroup)

    def test_create_security_group_rule_conflict(self):
        with mock.patch.object(self.mixin, '_validate_security_group_rule'),\
                mock.patch.object(self.mixin,
                                  '_check_for_duplicate_rules'),\
                mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.create_security_group_rule(
                    self.ctx, mock.MagicMock())

    def test__check_for_duplicate_rules_does_not_drop_protocol(self):
        with mock.patch.object(self.mixin, 'get_security_group',
                               return_value=None):
            context = mock.Mock()
            rule_dict = {
                'security_group_rule': {'protocol': None,
                                        'tenant_id': 'fake',
                                        'security_group_id': 'fake',
                                        'direction': 'fake'}
            }
            self.mixin._check_for_duplicate_rules(context, 'fake', [rule_dict])
        self.assertIn('protocol', rule_dict['security_group_rule'])

    def test__check_for_duplicate_rules_ignores_rule_id(self):
        rules = [{'security_group_rule': {'protocol': 'tcp', 'id': 'fake1'}},
                 {'security_group_rule': {'protocol': 'tcp', 'id': 'fake2'}}]

        # NOTE(arosen): the name of this exception is a little misleading
        # in this case as this test, tests that the id fields are dropped
        # while being compared. This is in the case if a plugin specifies
        # the rule ids themselves.
        with mock.patch.object(self.mixin, 'get_security_group',
                               return_value=None):
            self.assertRaises(securitygroup.DuplicateSecurityGroupRuleInPost,
                              self.mixin._check_for_duplicate_rules,
                              context, 'fake', rules)

    def test_check_for_duplicate_diff_rules_remote_ip_prefix_ipv4(self):
        fake_secgroup = copy.deepcopy(FAKE_SECGROUP)
        fake_secgroup['security_group_rules'] = \
            [{'id': 'fake', 'tenant_id': 'fake', 'ethertype': 'IPv4',
              'direction': 'ingress', 'security_group_id': 'fake',
              'remote_ip_prefix': None}]
        with mock.patch.object(self.mixin, 'get_security_group',
                               return_value=fake_secgroup):
            context = mock.Mock()
            rule_dict = {
                'security_group_rule': {'id': 'fake2',
                                        'tenant_id': 'fake',
                                        'security_group_id': 'fake',
                                        'ethertype': 'IPv4',
                                        'direction': 'ingress',
                                        'remote_ip_prefix': '0.0.0.0/0'}
            }
            self.assertRaises(securitygroup.SecurityGroupRuleExists,
                self.mixin._check_for_duplicate_rules,
                context, 'fake', [rule_dict])

    def test_check_for_duplicate_diff_rules_remote_ip_prefix_ipv6(self):
        fake_secgroup = copy.deepcopy(FAKE_SECGROUP)
        fake_secgroup['security_group_rules'] = \
            [{'id': 'fake', 'tenant_id': 'fake', 'ethertype': 'IPv6',
              'direction': 'ingress', 'security_group_id': 'fake',
              'remote_ip_prefix': None}]
        with mock.patch.object(self.mixin, 'get_security_group',
                               return_value=fake_secgroup):
            context = mock.Mock()
            rule_dict = {
                'security_group_rule': {'id': 'fake2',
                                        'tenant_id': 'fake',
                                        'security_group_id': 'fake',
                                        'ethertype': 'IPv6',
                                        'direction': 'ingress',
                                        'remote_ip_prefix': '::/0'}
            }
            self.assertRaises(securitygroup.SecurityGroupRuleExists,
                self.mixin._check_for_duplicate_rules,
                context, 'fake', [rule_dict])

    def test_delete_security_group_rule_in_use(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupRuleInUse):
                self.mixin.delete_security_group_rule(self.ctx, mock.ANY)

    def test_delete_security_group_rule_raise_error_on_not_found(self):
        with testtools.ExpectedException(
            securitygroup.SecurityGroupRuleNotFound):
            self.mixin.delete_security_group_rule(self.ctx, 'foo_rule')

    def test_validate_ethertype_and_protocol(self):
        fake_ipv4_rules = [{'protocol': constants.PROTO_NAME_IPV6_ICMP,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_ICMP_LEGACY,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_ENCAP,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_ROUTE,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_FRAG,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_NONXT,
                            'ethertype': constants.IPv4},
                           {'protocol': constants.PROTO_NAME_IPV6_OPTS,
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_ICMP),
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_ENCAP),
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_ROUTE),
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_FRAG),
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_NONXT),
                            'ethertype': constants.IPv4},
                           {'protocol': str(constants.PROTO_NUM_IPV6_OPTS),
                            'ethertype': constants.IPv4}]
        # test wrong protocols
        for rule in fake_ipv4_rules:
            with testtools.ExpectedException(
                securitygroup.SecurityGroupEthertypeConflictWithProtocol):
                self.mixin._validate_ethertype_and_protocol(rule)

    def test_security_group_precommit_create_event_fail(self):
        registry.subscribe(fake_callback, resources.SECURITY_GROUP,
                           events.PRECOMMIT_CREATE)
        with mock.patch.object(sqlalchemy.orm.session.SessionTransaction,
                              'rollback') as mock_rollback:
            self.assertRaises(securitygroup.SecurityGroupConflict,
                              self.mixin.create_security_group,
                              self.ctx, FAKE_SECGROUP)
            self.assertTrue(mock_rollback.called)

    def test_security_group_precommit_update_event_fail(self):
        registry.subscribe(fake_callback, resources.SECURITY_GROUP,
                           events.PRECOMMIT_UPDATE)
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        with mock.patch.object(sqlalchemy.orm.session.SessionTransaction,
                              'rollback') as mock_rollback:
            self.assertRaises(securitygroup.SecurityGroupConflict,
                              self.mixin.update_security_group,
                              self.ctx, sg_dict['id'], FAKE_SECGROUP)
            self.assertTrue(mock_rollback.called)

    def test_security_group_precommit_delete_event_fail(self):
        registry.subscribe(fake_callback, resources.SECURITY_GROUP,
                           events.PRECOMMIT_DELETE)
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        with mock.patch.object(sqlalchemy.orm.session.SessionTransaction,
                              'rollback') as mock_rollback:
            self.assertRaises(securitygroup.SecurityGroupInUse,
                              self.mixin.delete_security_group,
                              self.ctx, sg_dict['id'])
            self.assertTrue(mock_rollback.called)

    def _test_security_group_precommit_create_event(self,
                                                    with_revisions=False):
        DEFAULT_SECGROUP = {
            'tenant_id': FAKE_SECGROUP['security_group']['tenant_id'],
            'name': 'default',
            'description': 'Default security group',
        }
        DEFAULT_SECGROUP_DICT = {
            'id': mock.ANY,
            'tenant_id': FAKE_SECGROUP['security_group']['tenant_id'],
            'project_id': FAKE_SECGROUP['security_group']['tenant_id'],
            'name': 'default',
            'description': 'Default security group',
            'security_group_rules': [
                # Four rules for egress/ingress and ipv4/ipv6
                mock.ANY, mock.ANY, mock.ANY, mock.ANY,
            ],
        }
        if with_revisions:
            DEFAULT_SECGROUP_DICT.update({
                'revision_number': mock.ANY,
            })
        with mock.patch.object(registry, "notify") as mock_notify:
            sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
            mock_notify.assert_has_calls([
                mock.call('security_group', 'before_create', mock.ANY,
                          context=mock.ANY, is_default=False,
                          security_group=FAKE_SECGROUP['security_group']),

                mock.call('security_group', 'before_create', mock.ANY,
                          context=mock.ANY, is_default=True,
                          security_group=DEFAULT_SECGROUP),
                mock.call('security_group', 'precommit_create', mock.ANY,
                          context=mock.ANY, is_default=True,
                          security_group=DEFAULT_SECGROUP_DICT),
                mock.call('security_group', 'after_create', mock.ANY,
                          context=mock.ANY, is_default=True,
                          security_group=DEFAULT_SECGROUP_DICT),

                mock.call('security_group', 'precommit_create', mock.ANY,
                          context=mock.ANY, is_default=False,
                          security_group=sg_dict),
                mock.call('security_group', 'after_create', mock.ANY,
                          context=mock.ANY, is_default=False,
                          security_group=sg_dict)])
            # Ensure that the result of create is same as get.
            # Especially we want to check the revision number here.
            sg_dict_got = self.mixin.get_security_group(
                self.ctx, sg_dict['id'])
            self.assertEqual(sg_dict, sg_dict_got)

    def test_security_group_precommit_create_event_with_revisions(self):
        revision = revision_plugin.RevisionPlugin()
        self._test_security_group_precommit_create_event(True)
        del revision  # appease pep8

    def test_security_group_precommit_create_event(self):
        self._test_security_group_precommit_create_event()

    def test_security_group_precommit_update_event(self):
        original_sg_dict = self.mixin.create_security_group(self.ctx,
                                                            FAKE_SECGROUP)
        sg_id = original_sg_dict['id']
        with mock.patch.object(registry, "publish") as mock_notify:
            fake_secgroup = copy.deepcopy(FAKE_SECGROUP)
            fake_secgroup['security_group']['name'] = 'updated_fake'
            sg_dict = self.mixin.update_security_group(
                    self.ctx, sg_id, fake_secgroup)

            mock_notify.assert_has_calls(
                [mock.call('security_group', 'precommit_update', mock.ANY,
                           payload=mock.ANY)])
            payload = mock_notify.call_args[1]['payload']
            self.assertEqual(original_sg_dict, payload.states[0])
            self.assertEqual(sg_id, payload.resource_id)
            self.assertEqual(sg_dict, payload.desired_state)

    def test_security_group_precommit_and_after_delete_event(self):
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        with mock.patch.object(registry, "notify") as mock_notify:
            self.mixin.delete_security_group(self.ctx, sg_dict['id'])
            sg_dict['security_group_rules'] = mock.ANY
            mock_notify.assert_has_calls(
                [mock.call('security_group', 'precommit_delete',
                           mock.ANY, context=mock.ANY, security_group=sg_dict,
                           security_group_id=sg_dict['id'],
                           security_group_rule_ids=[mock.ANY, mock.ANY]),
                 mock.call('security_group', 'after_delete',
                           mock.ANY, context=mock.ANY,
                           security_group_id=sg_dict['id'],
                           security_group_rule_ids=[mock.ANY, mock.ANY])])

    def test_security_group_rule_precommit_create_event_fail(self):
        registry.subscribe(fake_callback, resources.SECURITY_GROUP_RULE,
                           events.PRECOMMIT_CREATE)
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        fake_rule = FAKE_SECGROUP_RULE
        fake_rule['security_group_rule']['security_group_id'] = sg_dict['id']
        with mock.patch.object(sqlalchemy.orm.session.SessionTransaction,
                              'rollback') as mock_rollback,\
            mock.patch.object(self.mixin, '_get_security_group'):
            self.assertRaises(securitygroup.SecurityGroupConflict,
                              self.mixin.create_security_group_rule,
                              self.ctx, fake_rule)
            self.assertTrue(mock_rollback.called)

    def test_security_group_rule_precommit_delete_event_fail(self):
        registry.subscribe(fake_callback, resources.SECURITY_GROUP_RULE,
                           events.PRECOMMIT_DELETE)
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        fake_rule = FAKE_SECGROUP_RULE
        fake_rule['security_group_rule']['security_group_id'] = sg_dict['id']
        with mock.patch.object(sqlalchemy.orm.session.SessionTransaction,
                              'rollback') as mock_rollback,\
            mock.patch.object(self.mixin, '_get_security_group'):
            sg_rule_dict = self.mixin.create_security_group_rule(self.ctx,
                   fake_rule)
            self.assertRaises(securitygroup.SecurityGroupRuleInUse,
                              self.mixin.delete_security_group_rule, self.ctx,
                              sg_rule_dict['id'])
            self.assertTrue(mock_rollback.called)

    def test_security_group_rule_precommit_create_event(self):
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        fake_rule = FAKE_SECGROUP_RULE
        fake_rule['security_group_rule']['security_group_id'] = sg_dict['id']
        with mock.patch.object(registry, "notify") as mock_notify, \
            mock.patch.object(self.mixin, '_get_security_group'):
            mock_notify.assert_has_calls([mock.call('security_group_rule',
                'precommit_create', mock.ANY, context=mock.ANY,
                security_group_rule=self.mixin.create_security_group_rule(
                    self.ctx, fake_rule))])

    def test_sg_rule_before_precommit_and_after_delete_event(self):
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        fake_rule = FAKE_SECGROUP_RULE
        fake_rule['security_group_rule']['security_group_id'] = sg_dict['id']
        with mock.patch.object(registry, "notify") as mock_notify, \
            mock.patch.object(self.mixin, '_get_security_group'):
            sg_rule_dict = self.mixin.create_security_group_rule(self.ctx,
                   fake_rule)
            self.mixin.delete_security_group_rule(self.ctx,
                    sg_rule_dict['id'])
            mock_notify.assert_has_calls([mock.call('security_group_rule',
                'before_delete', mock.ANY, context=mock.ANY,
                security_group_rule_id=sg_rule_dict['id'])])
            mock_notify.assert_has_calls([mock.call('security_group_rule',
                'precommit_delete', mock.ANY, context=mock.ANY,
                security_group_id=sg_dict['id'],
                security_group_rule_id=sg_rule_dict['id'])])
            mock_notify.assert_has_calls([mock.call('security_group_rule',
                'after_delete', mock.ANY, context=mock.ANY,
                security_group_rule_id=sg_rule_dict['id'],
                security_group_id=sg_dict['id'])])

    def test_get_ip_proto_name_and_num(self):
        protocols = [constants.PROTO_NAME_UDP, str(constants.PROTO_NUM_TCP),
                     'blah', '111']
        protocol_names_nums = (
            [[constants.PROTO_NAME_UDP, str(constants.PROTO_NUM_UDP)],
             [constants.PROTO_NAME_TCP, str(constants.PROTO_NUM_TCP)],
             ['blah', 'blah'], ['111', '111']])

        for i, protocol in enumerate(protocols):
            self.assertEqual(protocol_names_nums[i],
                             self.mixin._get_ip_proto_name_and_num(protocol))

    def test__validate_port_range_for_icmp_exception(self):
        states = [(1, 256, securitygroup.SecurityGroupInvalidIcmpValue),
                  (None, 6, securitygroup.SecurityGroupMissingIcmpType),
                  (300, 1, securitygroup.SecurityGroupInvalidIcmpValue)]
        for protocol in (constants.PROTO_NAME_ICMP,
                         constants.PROTO_NAME_IPV6_ICMP,
                         constants.PROTO_NAME_IPV6_ICMP_LEGACY):
            for pmin, pmax, exception in states:
                self.assertRaises(exception,
                    self.mixin._validate_port_range,
                    {'port_range_min': pmin,
                     'port_range_max': pmax,
                     'protocol': protocol})

    def test__validate_port_range_exception(self):
        self.assertRaises(securitygroup.SecurityGroupInvalidPortValue,
                          self.mixin._validate_port_range,
                          {'port_range_min': 0,
                           'port_range_max': None,
                           'protocol': constants.PROTO_NAME_TCP})
        self.assertRaises(securitygroup.SecurityGroupInvalidPortRange,
                          self.mixin._validate_port_range,
                          {'port_range_min': 1,
                           'port_range_max': None,
                           'protocol': constants.PROTO_NAME_SCTP})
        self.assertRaises(securitygroup.SecurityGroupInvalidPortRange,
                          self.mixin._validate_port_range,
                          {'port_range_min': 1000,
                           'port_range_max': 1,
                           'protocol': constants.PROTO_NAME_UDPLITE})
        self.assertRaises(
            securitygroup.SecurityGroupInvalidProtocolForPortRange,
            self.mixin._validate_port_range,
            {'port_range_min': 100,
             'port_range_max': 200,
             'protocol': '111'})
