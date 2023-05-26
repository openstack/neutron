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

from unittest import mock

import netaddr
from neutron_lib.callbacks import events
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent import resource_cache
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron import objects
from neutron.objects import address_group
from neutron.objects.port.extensions import port_security as psec
from neutron.objects import ports
from neutron.objects import securitygroup
from neutron.tests import base


class SecurityGroupServerRpcApiTestCase(base.BaseTestCase):

    def test_security_group_rules_for_devices(self):
        rpcapi = securitygroups_rpc.SecurityGroupServerRpcApi('fake_topic')

        with mock.patch.object(rpcapi.client, 'call') as rpc_mock,\
                mock.patch.object(rpcapi.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = rpcapi.client
            rpcapi.security_group_rules_for_devices('context', ['fake_device'])

            rpc_mock.assert_called_once_with(
                    'context',
                    'security_group_rules_for_devices',
                    devices=['fake_device'])


class SGAgentRpcCallBackMixinTestCase(base.BaseTestCase):

    def setUp(self):
        super(SGAgentRpcCallBackMixinTestCase, self).setUp()
        self.rpc = securitygroups_rpc.SecurityGroupAgentRpcCallbackMixin()
        self.rpc.sg_agent = mock.Mock()

    def test_security_groups_rule_updated(self):
        self.rpc.security_groups_rule_updated(None,
                                              security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [mock.call.security_groups_rule_updated(['fake_sgid'])])

    def test_security_groups_member_updated(self):
        self.rpc.security_groups_member_updated(None,
                                                security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [mock.call.security_groups_member_updated(['fake_sgid'])])


class SecurityGroupServerAPIShimTestCase(base.BaseTestCase):

    def setUp(self):
        super(SecurityGroupServerAPIShimTestCase, self).setUp()
        objects.register_objects()
        resource_types = [resources.PORT, resources.SECURITYGROUP,
                          resources.SECURITYGROUPRULE, resources.ADDRESSGROUP]
        self.rcache = resource_cache.RemoteResourceCache(resource_types)
        # prevent any server lookup attempts
        mock.patch.object(self.rcache, '_flood_cache_for_query').start()
        self.shim = securitygroups_rpc.SecurityGroupServerAPIShim(self.rcache)
        self.sg_agent = mock.Mock()
        self.shim.register_legacy_sg_notification_callbacks(self.sg_agent)
        self.ctx = context.get_admin_context()

    def _make_port_ovo(self, ip, **kwargs):
        attrs = {'id': uuidutils.generate_uuid(),
                 'network_id': uuidutils.generate_uuid(),
                 'security_group_ids': set(),
                 'device_owner': 'compute:None',
                 'allowed_address_pairs': []}
        attrs['fixed_ips'] = [ports.IPAllocation(
            port_id=attrs['id'], subnet_id=uuidutils.generate_uuid(),
            network_id=attrs['network_id'], ip_address=ip)]
        attrs.update(**kwargs)
        p = ports.Port(self.ctx, **attrs)
        self.rcache.record_resource_update(self.ctx, 'Port', p)
        return p

    @mock.patch.object(address_group.AddressGroup, 'is_shared_with_project',
                       return_value=False)
    def _make_address_group_ovo(self, *args, **kwargs):
        id = uuidutils.generate_uuid()
        address_associations = [
            address_group.AddressAssociation(
                self.ctx,
                address=netaddr.IPNetwork('10.0.0.1/32'),
                address_group_id=id),
            address_group.AddressAssociation(
                self.ctx,
                address=netaddr.IPNetwork('2001:db8::/32'),
                address_group_id=id)
        ]
        ag = address_group.AddressGroup(self.ctx, id=id,
                                        name='an-address-group',
                                        description='An address group',
                                        addresses=address_associations)
        self.rcache.record_resource_update(self.ctx, resources.ADDRESSGROUP,
                                           ag)
        return ag

    @mock.patch.object(securitygroup.SecurityGroup, 'is_shared_with_project',
                       return_value=False)
    def _make_security_group_ovo(self, *args, **kwargs):
        attrs = {'id': uuidutils.generate_uuid(), 'revision_number': 1}
        r_group = kwargs.get('remote_group_id') or attrs['id']
        sg_rule = securitygroup.SecurityGroupRule(
            id=uuidutils.generate_uuid(),
            security_group_id=attrs['id'],
            direction='ingress',
            ethertype='IPv4', protocol='tcp',
            port_range_min=400,
            remote_group_id=r_group,
            revision_number=1,
            remote_address_group_id=kwargs.get('remote_address_group_id',
                                               None),
        )
        attrs['rules'] = [sg_rule]
        attrs.update(**kwargs)
        sg = securitygroup.SecurityGroup(self.ctx, **attrs)
        self.rcache.record_resource_update(self.ctx, 'SecurityGroup', sg)
        return sg

    def test_sg_parent_ops_affect_rules(self):
        s1 = self._make_security_group_ovo()
        filters = {'security_group_id': (s1.id, )}
        self.assertEqual(
            s1.rules,
            self.rcache.get_resources('SecurityGroupRule', filters))
        self.sg_agent.security_groups_rule_updated.assert_called_once_with(
            [s1.id])
        self.sg_agent.security_groups_rule_updated.reset_mock()
        self.rcache.record_resource_delete(self.ctx, 'SecurityGroup', s1.id)
        self.assertEqual(
            [],
            self.rcache.get_resources('SecurityGroupRule', filters))
        self.sg_agent.security_groups_rule_updated.assert_called_once_with(
            [s1.id])

    def test_security_group_info_for_devices(self):
        s1 = self._make_security_group_ovo()
        mac_1 = 'fa:16:3e:aa:bb:c1'
        p1 = self._make_port_ovo(ip='1.1.1.1',
                                 mac_address=netaddr.EUI(mac_1),
                                 security_group_ids={s1.id})
        mac_2 = 'fa:16:3e:aa:bb:c2'
        p2 = self._make_port_ovo(
            ip='2.2.2.2',
            mac_address=netaddr.EUI(mac_2),
            security_group_ids={s1.id},
            security=psec.PortSecurity(port_security_enabled=False))
        mac_3 = 'fa:16:3e:aa:bb:c3'
        p3 = self._make_port_ovo(ip='3.3.3.3',
                                 mac_address=netaddr.EUI(mac_3),
                                 security_group_ids={s1.id},
                                 device_owner='network:dhcp')

        ids = [p1.id, p2.id, p3.id]
        info = self.shim.security_group_info_for_devices(self.ctx, ids)
        self.assertIn(('1.1.1.1', str(netaddr.EUI(mac_1))),
                      info['sg_member_ips'][s1.id]['IPv4'])
        self.assertIn(('2.2.2.2', str(netaddr.EUI(mac_2))),
                      info['sg_member_ips'][s1.id]['IPv4'])
        self.assertIn(('3.3.3.3', str(netaddr.EUI(mac_3))),
                      info['sg_member_ips'][s1.id]['IPv4'])
        self.assertIn(p1.id, info['devices'].keys())
        self.assertIn(p2.id, info['devices'].keys())
        # P3 is a trusted port so it doesn't have rules
        self.assertNotIn(p3.id, info['devices'].keys())
        self.assertEqual([s1.id], list(info['security_groups'].keys()))
        self.assertTrue(info['devices'][p1.id]['port_security_enabled'])
        self.assertFalse(info['devices'][p2.id]['port_security_enabled'])

    def test_sg_member_update_events(self):
        s1 = self._make_security_group_ovo()
        p1 = self._make_port_ovo(ip='1.1.1.1', security_group_ids={s1.id})
        self._make_port_ovo(ip='2.2.2.2', security_group_ids={s1.id})
        self.sg_agent.security_groups_member_updated.assert_called_with(
            {s1.id})
        self.sg_agent.security_groups_member_updated.reset_mock()
        self.rcache.record_resource_delete(self.ctx, 'Port', p1.id)
        self.sg_agent.security_groups_member_updated.assert_called_with(
            {s1.id})

    def test_sg_delete_events_with_remote(self):
        s1 = self._make_security_group_ovo(remote_group_id='')
        s2 = self._make_security_group_ovo(remote_group_id=s1.id)
        rules = self.rcache.get_resources(
            'SecurityGroupRule',
            filters={'security_group_id': (s1.id, s2.id)})
        self.assertEqual(2, len(rules))
        self.assertEqual(s1.id, rules[0].remote_group_id)

        self.shim._clear_child_sg_rules(
            'SecurityGroup', 'after_delete', '',
            events.DBEventPayload(
                context=self.ctx,
                states=[s1]
            )
        )
        rules = self.rcache.get_resources(
            'SecurityGroupRule',
            filters={'security_group_id': (s1.id, s2.id)})
        self.assertEqual(0, len(rules))

    def test_sg_delete_events_without_remote(self):
        s1 = self._make_security_group_ovo()
        s2 = self._make_security_group_ovo()
        rules = self.rcache.get_resources(
            'SecurityGroupRule',
            filters={'security_group_id': (s1.id, s2.id)})
        self.assertEqual(2, len(rules))
        self.assertEqual(s1.id, rules[0].remote_group_id)

        self.shim._clear_child_sg_rules(
            'SecurityGroup', 'after_delete', '',
            events.DBEventPayload(
                context=self.ctx,
                states=[s1]
            )
        )
        s1_rules = self.rcache.get_resources(
            'SecurityGroupRule',
            filters={'security_group_id': (s1.id, )})
        self.assertEqual(0, len(s1_rules))
        s2_rules = self.rcache.get_resources(
            'SecurityGroupRule',
            filters={'security_group_id': (s2.id, )})
        self.assertEqual(1, len(s2_rules))

    def test_get_secgroup_ids_for_address_group(self):
        ag = self._make_address_group_ovo()
        sg1 = self._make_security_group_ovo(remote_address_group_id=ag.id)
        sg2 = self._make_security_group_ovo(remote_address_group_id=ag.id)
        sg3 = self._make_security_group_ovo()
        sec_group_ids = self.shim.get_secgroup_ids_for_address_group(ag.id)
        self.assertEqual(set([sg1.id, sg2.id]), set(sec_group_ids))
        self.assertEqual(2, len(sec_group_ids))
        self.assertNotIn(sg3.id, sec_group_ids)

    def test_address_group_update_events(self):
        ag = self._make_address_group_ovo()
        self.sg_agent.address_group_updated.assert_called_with(ag.id)
        self.sg_agent.address_group_updated.reset_mock()
        self.rcache.record_resource_delete(self.ctx, resources.ADDRESSGROUP,
            ag.id)
        self.sg_agent.address_group_deleted.assert_called_with(ag.id)
