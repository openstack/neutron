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

import mock
import sqlalchemy
import testtools

from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants
from neutron import context
from neutron.db import common_db_mixin
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup
from neutron.tests.unit import testlib_api


FAKE_SECGROUP = {'security_group': {"tenant_id": 'fake', 'description':
                 'fake', 'name': 'fake'}}

FAKE_SECGROUP_RULE = {'security_group_rule': {"tenant_id": 'fake',
    'description': 'fake', 'name': 'fake', 'port_range_min':
    '21', 'protocol': 'tcp', 'port_range_max': '23',
    'remote_ip_prefix': '10.0.0.1', 'ethertype': 'IPv4',
    'remote_group_id': None, 'security_group_id': 'None',
    'direction': 'ingress'}}


def fake_callback(resource, event, *args, **kwargs):
    raise KeyError('bar')


class SecurityGroupDbMixinImpl(securitygroups_db.SecurityGroupDbMixin,
                               common_db_mixin.CommonDbMixin):
    pass


class SecurityGroupDbMixinTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(SecurityGroupDbMixinTestCase, self).setUp()
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
                                  '_check_for_duplicate_rules_in_db'),\
                mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.create_security_group_rule(
                    self.ctx, mock.MagicMock())

    def test__check_for_duplicate_rules_in_db_does_not_drop_protocol(self):
        with mock.patch.object(self.mixin, 'get_security_group_rules',
                               return_value=[mock.Mock()]):
            context = mock.Mock()
            rule_dict = {
                'security_group_rule': {'protocol': None,
                                        'tenant_id': 'fake',
                                        'security_group_id': 'fake',
                                        'direction': 'fake'}
            }
            self.mixin._check_for_duplicate_rules_in_db(context, rule_dict)
        self.assertIn('protocol', rule_dict['security_group_rule'])

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

    def test_security_group_precommit_create_event(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
            mock_notify.assert_has_calls([mock.call('security_group',
                'precommit_create', mock.ANY, context=mock.ANY,
                is_default=mock.ANY, security_group=mock.ANY)])

    def test_security_group_precommit_update_event(self):
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        with mock.patch.object(registry, "notify") as mock_notify:
            self.mixin.update_security_group(self.ctx, sg_dict['id'],
                                             FAKE_SECGROUP)
            mock_notify.assert_has_calls([mock.call('security_group',
                'precommit_update', mock.ANY, context=mock.ANY,
                security_group=mock.ANY, security_group_id=sg_dict['id'])])

    def test_security_group_precommit_delete_event(self):
        sg_dict = self.mixin.create_security_group(self.ctx, FAKE_SECGROUP)
        with mock.patch.object(registry, "notify") as mock_notify:
            self.mixin.delete_security_group(self.ctx, sg_dict['id'])
            mock_notify.assert_has_calls([mock.call('security_group',
                'precommit_delete', mock.ANY, context=mock.ANY,
                security_group=mock.ANY, security_group_id=sg_dict['id'])])

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
            self.mixin.create_security_group_rule(self.ctx,
                   fake_rule)
            mock_notify.assert_has_calls([mock.call('security_group_rule',
                'precommit_create', mock.ANY, context=mock.ANY,
                security_group_rule=mock.ANY)])

    def test_security_group_rule_precommit_delete_event(self):
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
                'precommit_delete', mock.ANY, context=mock.ANY,
                security_group_rule_id=mock.ANY)])

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
