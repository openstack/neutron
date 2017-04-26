# Copyright (c) 2016 OpenStack Foundation.
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


import mock
from neutron_lib.callbacks import events
from neutron_lib import constants
from neutron_lib import context

from neutron.db.db_base_plugin_v2 import NeutronDbPluginV2 as db_plugin_v2
from neutron.extensions import rbac as ext_rbac
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin


class NetworkRbacTestcase(test_plugin.NeutronDbPluginV2TestCase):
    def setUp(self):
        self.context = context.get_admin_context()
        super(NetworkRbacTestcase, self).setUp()

    def _make_networkrbac(self, network, target):
        policy = {'rbac_policy': {'tenant_id': network['network']['tenant_id'],
                                  'object_id': network['network']['id'],
                                  'object_type': 'network',
                                  'action': 'access_as_shared',
                                  'target_tenant': target}}
        return policy

    def _setup_networkrbac_and_port(self, network, target_tenant):
        policy = self._make_networkrbac(network, target_tenant)
        netrbac = self.plugin.create_rbac_policy(self.context, policy)

        test_port = {'port': {'name': 'test-port',
                              'network_id': network['network']['id'],
                              'mac_address': constants.ATTR_NOT_SPECIFIED,
                              'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                              'admin_state_up': True,
                              'device_id': 'device_id',
                              'device_owner': 'device_owner',
                              'tenant_id': target_tenant}}

        port = self.plugin.create_port(self.context, test_port)
        return netrbac, port

    def test_update_networkrbac_valid(self):
        orig_target = 'test-tenant-2'
        new_target = 'test-tenant-3'

        with self.network() as net:
            policy = self._make_networkrbac(net, orig_target)
            netrbac = self.plugin.create_rbac_policy(self.context, policy)
            update_policy = {'rbac_policy': {'target_tenant': new_target}}

            netrbac2 = self.plugin.update_rbac_policy(self.context,
                                                      netrbac['id'],
                                                      update_policy)

            policy['rbac_policy']['target_tenant'] = new_target
            for k, v in policy['rbac_policy'].items():
                self.assertEqual(netrbac2[k], v)

    def test_delete_networkrbac_in_use_fail(self):
        with self.network() as net:
            netrbac, _ = self._setup_networkrbac_and_port(
                network=net, target_tenant='test-tenant-2')

            self.assertRaises(ext_rbac.RbacPolicyInUse,
                              self.plugin.delete_rbac_policy,
                              self.context, netrbac['id'])

    def test_delete_networkrbac(self):
        with self.network() as net:
            netrbac, port = self._setup_networkrbac_and_port(
                network=net, target_tenant='test-tenant-4')
            self.assertRaises(ext_rbac.RbacPolicyInUse,
                              self.plugin.delete_rbac_policy,
                              self.context, netrbac['id'])

            self.plugin.delete_port(self.context, port['id'])
            self.plugin.delete_rbac_policy(self.context, netrbac['id'])

            self.assertRaises(ext_rbac.RbacPolicyNotFound,
                              self.plugin.get_rbac_policy,
                              self.context, netrbac['id'])

    def test_delete_networkrbac_self_share(self):
        net_id = 'my-network'
        net_owner = 'my-tenant-id'
        net = {'network': {'id': net_id, 'tenant_id': net_owner}}
        policy = self._make_networkrbac(net, net_owner)['rbac_policy']
        kwargs = {}

        with mock.patch.object(db_plugin_v2, '_get_network') as get_net,\
            mock.patch.object(db_plugin_v2,
                              'ensure_no_tenant_ports_on_network') as ensure:
            get_net.return_value = net['network']
            self.plugin.validate_network_rbac_policy_change(
                None, events.BEFORE_DELETE, None,
                self.context, 'network', policy, **kwargs)
            self.assertEqual(0, ensure.call_count)

    def test_update_self_share_networkrbac(self):
        net_id = 'my-network'
        net_owner = 'my-tenant-id'
        net = {'network': {'id': net_id, 'tenant_id': net_owner}}
        policy = self._make_networkrbac(net, net_owner)['rbac_policy']
        kwargs = {'policy_update': {'target_tenant': 'new-target-tenant'}}

        with mock.patch.object(db_plugin_v2, '_get_network') as get_net,\
            mock.patch.object(db_plugin_v2,
                              'ensure_no_tenant_ports_on_network') as ensure:
            get_net.return_value = net['network']
            self.plugin.validate_network_rbac_policy_change(
                None, events.BEFORE_UPDATE, None,
                self.context, 'network', policy, **kwargs)
            self.assertEqual(0, ensure.call_count)
